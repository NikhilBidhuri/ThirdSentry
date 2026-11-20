import { appendFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { z } from 'zod';
import { ProxyEventSchema, type Issue, type ProxyEvent, type ScanEvidence } from '../types/evidence.js';
import { getLogger } from '../utils/logger.js';
import { isValidRunId, type ProxyClientTag, type ProxyConnectionEvent, type ProxyEventSink } from './egress-proxy.js';

/**
 * Trusted record of the egress proxy's connection events in the container
 * pipeline.
 *
 * The scanner container runs hostile page code, so connection evidence it
 * reports cannot be trusted. Instead the scanner tags its proxy connections
 * with `<runId>.<site>` (see EgressProxy), the egress proxy appends one NDJSON
 * line per event to `<dir>/<runId>.ndjson` on a volume the scanner cannot
 * mount, and `analyze --proxy-events` replaces each site's proxyEvents with
 * these lines.
 *
 * Bounds: events per site are capped by the proxy (`maxRecordedEvents`), each
 * run file by `maxBytesPerRun` (a single `truncated` marker is written when
 * it is reached), and the directory by `maxRunFiles` (new runs are refused,
 * loudly, beyond it). Dropped counts are written as summary lines.
 *
 * Limitation: the tag is chosen by the (untrusted) scanner. A compromised
 * scanner can hide its connections by mis-tagging them; it cannot forge or
 * alter events recorded under the correct tag.
 */

export const PROXY_EVENT_LOG_VERSION = 1;
export const DEFAULT_MAX_BYTES_PER_RUN = 32 * 1024 * 1024;
export const DEFAULT_MAX_RUN_FILES = 64;
/** Events kept per site and kind (blocked / allowed), as in local mode. */
export const PROXY_EVENTS_PER_SITE = 5_000;

const RunIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const SiteSchema = z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/i);

const LineSchema = z.union([
  z.object({ v: z.literal(PROXY_EVENT_LOG_VERSION), run: RunIdSchema, site: SiteSchema, event: ProxyEventSchema }).strict(),
  z.object({ v: z.literal(PROXY_EVENT_LOG_VERSION), run: RunIdSchema, site: SiteSchema, dropped: z.number().int().min(0) }).strict(),
  z.object({ v: z.literal(PROXY_EVENT_LOG_VERSION), run: RunIdSchema, truncated: z.literal(true), maxBytes: z.number().int().min(0) }).strict(),
]);

export interface ProxyEventLogOptions {
  readonly dir: string;
  readonly maxBytesPerRun?: number;
  readonly maxRunFiles?: number;
  /** Delay used to coalesce dropped-count summary lines. */
  readonly flushDelayMs?: number;
}

interface RunFile {
  readonly path: string;
  bytes: number;
  truncated: boolean;
  failed: boolean;
}

/** Event sink used by the standalone egress proxy. Synchronous appends: events are durable before the next one is handled. */
export class ProxyEventLogWriter implements ProxyEventSink {
  private readonly dir: string;
  private readonly maxBytes: number;
  private readonly maxFiles: number;
  private readonly flushDelayMs: number;
  private readonly runs = new Map<string, RunFile>();
  private readonly refused = new Set<string>();
  private readonly pendingDropped = new Map<string, { tag: ProxyClientTag; total: number }>();
  private flushTimer: NodeJS.Timeout | undefined;
  private readonly log = getLogger('proxy-event-log');

  constructor(options: ProxyEventLogOptions) {
    this.dir = options.dir;
    this.maxBytes = options.maxBytesPerRun ?? DEFAULT_MAX_BYTES_PER_RUN;
    this.maxFiles = options.maxRunFiles ?? DEFAULT_MAX_RUN_FILES;
    this.flushDelayMs = options.flushDelayMs ?? 200;
  }

  /** Fail fast (at proxy start) when the directory is missing or not writable. */
  init(): void {
    const probe = join(this.dir, `.write-probe-${process.pid}`);
    writeFileSync(probe, '');
    unlinkSync(probe);
  }

  append(tag: ProxyClientTag, event: ProxyConnectionEvent): void {
    this.writeLine(tag.runId, { v: PROXY_EVENT_LOG_VERSION, run: tag.runId, site: tag.site, event });
  }

  dropped(tag: ProxyClientTag, total: number): void {
    this.pendingDropped.set(`${tag.runId}.${tag.site}`, { tag, total });
    this.flushTimer ??= setTimeout(() => this.flush(), this.flushDelayMs);
  }

  /** Write pending dropped-count summaries now. */
  flush(): void {
    if (this.flushTimer) clearTimeout(this.flushTimer);
    this.flushTimer = undefined;
    const pending = [...this.pendingDropped.values()];
    this.pendingDropped.clear();
    for (const { tag, total } of pending) {
      this.writeLine(tag.runId, { v: PROXY_EVENT_LOG_VERSION, run: tag.runId, site: tag.site, dropped: total });
    }
  }

  close(): void {
    this.flush();
  }

  private runFile(runId: string): RunFile | undefined {
    const known = this.runs.get(runId);
    if (known) return known;
    if (this.refused.has(runId) || !isValidRunId(runId)) return undefined;
    const path = join(this.dir, `${runId}.ndjson`);
    let bytes = 0;
    try {
      bytes = statSync(path).size; // proxy restarted during a run: keep appending
    } catch {
      const existing = readdirSync(this.dir).filter((f) => f.endsWith('.ndjson')).length;
      if (existing >= this.maxFiles) {
        if (this.refused.size < 1_024) this.refused.add(runId);
        this.log.error(
          { run: runId, dir: this.dir, maxRunFiles: this.maxFiles },
          'too many proxy event files; events of this run are NOT recorded (remove old files from the proxy-events volume)',
        );
        return undefined;
      }
    }
    if (this.runs.size >= 256) {
      const oldest = this.runs.keys().next().value;
      if (oldest !== undefined) this.runs.delete(oldest);
    }
    const file: RunFile = { path, bytes, truncated: false, failed: false };
    this.runs.set(runId, file);
    return file;
  }

  private writeLine(runId: string, value: object): void {
    const file = this.runFile(runId);
    if (!file || file.truncated || file.failed) return;
    let line = `${JSON.stringify(value)}\n`;
    if (file.bytes + Buffer.byteLength(line) > this.maxBytes) {
      // One marker line beyond the cap so the analyzer knows the record is incomplete.
      file.truncated = true;
      line = `${JSON.stringify({ v: PROXY_EVENT_LOG_VERSION, run: runId, truncated: true, maxBytes: this.maxBytes })}\n`;
      this.log.warn({ run: runId, maxBytes: this.maxBytes }, 'proxy event file reached its size cap; further events of this run are not recorded');
    }
    try {
      appendFileSync(file.path, line, { mode: 0o640 });
      file.bytes += Buffer.byteLength(line);
    } catch (error) {
      file.failed = true;
      this.log.error({ run: runId, path: file.path, err: (error as Error).message }, 'could not write proxy event file; events of this run are NOT recorded');
    }
  }
}

export interface TrustedSiteEvents {
  events: ProxyEvent[];
  dropped: number;
}

export interface TrustedProxyEvents {
  readonly path: string;
  /** False when the file does not exist (no connection was tagged with this run). */
  readonly found: boolean;
  readonly sites: Map<string, TrustedSiteEvents>;
  readonly truncated: boolean;
  readonly invalidLines: number;
  /** Every run id seen in the file. */
  readonly runIds: ReadonlySet<string>;
  readonly expectedRunId?: string;
}

/** `<dir>/<runId>.ndjson` → runId, or undefined for other names. */
export function runIdFromPath(path: string): string | undefined {
  return /^([A-Za-z0-9_-]{1,64})\.ndjson$/.exec(basename(path))?.[1];
}

/**
 * Read a run's proxy event file (analyzer side). Throws if it is larger than
 * `maxBytes`. Lines of runs other than `expectedRunId` (default: derived from
 * the `<runId>.ndjson` file name) are ignored and reported.
 */
export async function readProxyEventLog(path: string, maxBytes: number, expectedRunId = runIdFromPath(path)): Promise<TrustedProxyEvents> {
  const sites = new Map<string, TrustedSiteEvents & { blocked: ProxyEvent[]; allowed: ProxyEvent[] }>();
  const runIds = new Set<string>();
  let size: number;
  try {
    size = (await stat(path)).size;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return { path, found: false, sites: new Map(), truncated: false, invalidLines: 0, runIds, ...(expectedRunId ? { expectedRunId } : {}) };
    }
    throw error;
  }
  if (size > maxBytes) throw new Error(`Proxy event file ${path} is larger than ${maxBytes} bytes`);
  const text = await readFile(path, 'utf8');
  let truncated = false;
  let invalidLines = 0;
  const siteFor = (name: string) => {
    let s = sites.get(name);
    if (!s) {
      s = { events: [], dropped: 0, blocked: [], allowed: [] };
      sites.set(name, s);
    }
    return s;
  };
  for (const raw of text.split('\n')) {
    if (raw.trim() === '') continue;
    let parsed: z.infer<typeof LineSchema>;
    try {
      parsed = LineSchema.parse(JSON.parse(raw));
    } catch {
      invalidLines++;
      continue;
    }
    runIds.add(parsed.run);
    if (expectedRunId !== undefined && parsed.run !== expectedRunId) continue;
    if ('truncated' in parsed) {
      truncated = true;
    } else if ('event' in parsed) {
      const s = siteFor(parsed.site);
      const list = parsed.event.allowed ? s.allowed : s.blocked;
      if (list.length < PROXY_EVENTS_PER_SITE) list.push(parsed.event);
      else s.dropped++;
    } else {
      const s = siteFor(parsed.site);
      // Summary lines carry the proxy's running total; keep the largest.
      s.dropped = Math.max(s.dropped, parsed.dropped);
    }
  }
  const result = new Map<string, TrustedSiteEvents>();
  for (const [name, s] of sites) result.set(name, { events: [...s.blocked, ...s.allowed], dropped: s.dropped });
  return { path, found: true, sites: result, truncated, invalidLines, runIds, ...(expectedRunId ? { expectedRunId } : {}) };
}

/**
 * Replace every site's (untrusted, scanner-reported) proxyEvents with the
 * trusted events recorded by the egress proxy, and add issues for anything
 * that makes the record incomplete.
 */
export function applyTrustedProxyEvents(evidence: ScanEvidence, trusted: TrustedProxyEvents): ScanEvidence {
  const issues: Issue[] = [...evidence.issues];
  const known = new Set(evidence.sites.map((s) => s.name));
  if (!trusted.found) {
    const anyPageLoaded = evidence.sites.some((s) => s.pages.some((p) => p.status !== 'failed'));
    issues.push({
      level: anyPageLoaded ? 'error' : 'warning',
      code: 'proxy-events-missing',
      message: `No egress-proxy event record found at ${trusted.path}; blocked-connection evidence for this scan is unavailable. Check that the egress proxy runs with --events-dir on the proxy-events volume and that the scanner used the same run id.`,
    });
  }
  if (trusted.truncated) {
    issues.push({
      level: 'warning',
      code: 'proxy-events-truncated',
      message: 'The egress-proxy event record for this run reached its size cap; later connection events were not recorded.',
    });
  }
  if (trusted.invalidLines > 0) {
    issues.push({ level: 'warning', code: 'proxy-events-invalid', message: `${trusted.invalidLines} unreadable line(s) in the egress-proxy event record were ignored.` });
  }
  const foreignRuns = trusted.expectedRunId ? [...trusted.runIds].filter((r) => r !== trusted.expectedRunId) : [];
  if (foreignRuns.length > 0) {
    issues.push({ level: 'warning', code: 'proxy-events-foreign-run', message: `The egress-proxy event record contains events of other runs (${foreignRuns.slice(0, 5).join(', ')}); they were ignored.` });
  }
  const unknownSites = [...trusted.sites.keys()].filter((name) => !known.has(name));
  const unknownBlocked = unknownSites.reduce((n, name) => n + (trusted.sites.get(name)?.events.filter((e) => !e.allowed).length ?? 0), 0);
  if (unknownSites.length > 0) {
    issues.push({
      level: unknownBlocked > 0 ? 'warning' : 'info',
      code: 'proxy-events-unknown-site',
      message: `The egress proxy recorded connections tagged with sites that are not in this scan (${unknownSites.slice(0, 5).join(', ')}), ${unknownBlocked} of them blocked.`,
    });
  }
  const sites = evidence.sites.map((site) => {
    const own = trusted.sites.get(site.name) ?? { events: [], dropped: 0 };
    const siteIssues = [...site.issues];
    if (own.dropped > 0) {
      siteIssues.push({
        level: 'warning',
        code: 'proxy-events-dropped',
        message: `${own.dropped} connection event(s) of this site exceeded the egress proxy's per-site cap and were not recorded.`,
      });
    }
    return { ...site, issues: siteIssues, proxyEvents: own.events, proxyEventsDropped: own.dropped };
  });
  return { ...evidence, sites, issues };
}
