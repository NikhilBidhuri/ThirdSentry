import { rename } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import type { StoragePaths } from '../storage/paths.js';
import type { PageStatus, ScanResult, SiteResult } from '../types/index.js';
import { pathExists, readJsonFile, writeJsonAtomic } from '../utils/fs.js';
import { getLogger } from '../utils/logger.js';

/**
 * Scan health, per site: did the last scans work?
 *
 * Kept in state/health.json (written atomically; the storage lock held by the
 * CLI serialises writers). It is updated by analyzeScan (shared by `scan` and
 * the container `analyze`) and, for alert delivery, by the `alert` command.
 * It only drives the `scan-unhealthy` finding, `status` and `metrics`.
 */

const SiteHealthSchema = z.object({
  lastScanId: z.string(),
  lastScanAt: z.string(),
  lastCompleteAt: z.string().optional(),
  lastStatus: z.enum(['complete', 'partial', 'failed']),
  /** Failed (and, if configured, incomplete) scans in a row. */
  consecutiveFailures: z.number().int().min(0),
  /** Start time of the first scan of the current failure streak. */
  streakStart: z.string().optional(),
  lastError: z.string().optional(),
  lastDurationSeconds: z.number().min(0),
  pages: z.object({ complete: z.number().int(), partial: z.number().int(), failed: z.number().int() }),
  scripts: z.object({ firstParty: z.number().int(), thirdParty: z.number().int() }),
  blockedConnections: z.number().int(),
  lastRecovery: z.object({ since: z.string(), failures: z.number().int(), recoveredAt: z.string() }).optional(),
});

const AlertChannelHealthSchema = z.object({
  lastAttemptAt: z.string(),
  lastSuccessAt: z.string().optional(),
  consecutiveFailures: z.number().int().min(0),
  lastError: z.string().optional(),
});

const HealthStateSchema = z.object({
  version: z.literal(1),
  sites: z.record(z.string(), SiteHealthSchema),
  alerts: z.record(z.string(), AlertChannelHealthSchema).default({}),
});

export type SiteHealth = z.infer<typeof SiteHealthSchema>;
export type AlertChannelHealth = z.infer<typeof AlertChannelHealthSchema>;
export type HealthState = z.infer<typeof HealthStateSchema>;

export interface HealthRecoveryEvent {
  readonly site: string;
  readonly failures: number;
  readonly since: string;
  readonly recoveredAt: string;
}

export interface HealthPolicy {
  readonly failureThreshold: number;
  readonly countIncomplete: boolean;
}

export function healthStatePath(paths: StoragePaths): string {
  return join(paths.state, 'health.json');
}

export function emptyHealthState(): HealthState {
  return { version: 1, sites: {}, alerts: {} };
}

/**
 * Load the health state. A missing file is an empty state. An unreadable one
 * is also treated as empty (health is derived data, a reset only restarts
 * the streaks); with `quarantine` the bad file is first moved aside.
 */
export async function loadHealthState(paths: StoragePaths, options: { quarantine?: boolean } = {}): Promise<HealthState> {
  const path = healthStatePath(paths);
  if (!(await pathExists(path))) return emptyHealthState();
  let reason: string;
  try {
    const parsed = HealthStateSchema.safeParse(await readJsonFile(path, 16 * 1024 * 1024));
    if (parsed.success) return parsed.data;
    reason = `invalid structure: ${parsed.error.issues[0]?.message ?? 'schema mismatch'}`;
  } catch (error) {
    if (typeof (error as { code?: unknown }).code === 'string') throw error;
    reason = (error as Error).message;
  }
  getLogger('health').warn({ path, reason }, 'health state was unreadable; starting with an empty state');
  if (options.quarantine) await rename(path, `${path}.corrupt-${Date.now()}`).catch(() => undefined);
  return emptyHealthState();
}

export async function saveHealthState(paths: StoragePaths, state: HealthState): Promise<void> {
  await writeJsonAtomic(healthStatePath(paths), state);
}

/** True when this scan result counts towards the failure streak. */
export function countsAsFailure(status: PageStatus, policy: HealthPolicy): boolean {
  return status === 'failed' || (policy.countIncomplete && status === 'partial');
}

function clean(text: string, max: number): string {
  // eslint-disable-next-line no-control-regex
  const flat = text.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/** Short summary of why a site scan was not clean (never page content). */
export function summarizeSiteError(site: SiteResult): string | undefined {
  const issues = [...site.issues, ...site.pages.flatMap((p) => p.issues.map((i) => ({ ...i, message: `${p.key}: ${i.message}` })))].filter((i) => i.level !== 'info');
  if (issues.length === 0) return site.status === 'complete' ? undefined : `scan ${site.status}`;
  issues.sort((a, b) => Number(b.level === 'error') - Number(a.level === 'error'));
  const first = issues[0];
  const more = issues.length > 1 ? ` (+${issues.length - 1} more)` : '';
  return clean(`${first?.code ?? 'issue'}: ${first?.message ?? ''}${more}`, 300);
}

export function siteDurationSeconds(site: SiteResult): number {
  const ms = Date.parse(site.finishedAt) - Date.parse(site.startedAt);
  return Number.isFinite(ms) && ms > 0 ? Math.round(ms) / 1000 : 0;
}

/**
 * Apply one scan to the health state (in place). Idempotent per scan id:
 * analysing the same scan twice does not count it twice. Sites that are not in
 * the scan keep their state. Returns the recoveries this scan caused (a site
 * that had an unhealthy streak, i.e. reached the threshold, was not failing).
 */
export function recordScanHealth(state: HealthState, scan: ScanResult, policy: HealthPolicy): HealthRecoveryEvent[] {
  const recoveries: HealthRecoveryEvent[] = [];
  for (const site of scan.sites) {
    const prev = state.sites[site.name];
    if (prev?.lastScanId === scan.scanId) continue;
    const failed = countsAsFailure(site.status, policy);
    const previousFailures = prev?.consecutiveFailures ?? 0;
    const consecutiveFailures = failed ? previousFailures + 1 : 0;
    const streakStart = failed ? (previousFailures > 0 && prev?.streakStart ? prev.streakStart : site.startedAt) : undefined;
    const lastError = site.status === 'complete' ? undefined : summarizeSiteError(site);
    const lastCompleteAt = site.status === 'complete' ? site.finishedAt : prev?.lastCompleteAt;
    let lastRecovery = prev?.lastRecovery;
    if (!failed && prev && previousFailures >= policy.failureThreshold && prev.streakStart) {
      const event = { site: site.name, failures: previousFailures, since: prev.streakStart, recoveredAt: site.finishedAt };
      recoveries.push(event);
      lastRecovery = { since: event.since, failures: event.failures, recoveredAt: event.recoveredAt };
    }
    const resources = site.resources;
    state.sites[site.name] = {
      lastScanId: scan.scanId,
      lastScanAt: site.finishedAt,
      ...(lastCompleteAt ? { lastCompleteAt } : {}),
      lastStatus: site.status,
      consecutiveFailures,
      ...(streakStart ? { streakStart } : {}),
      ...(lastError ? { lastError } : {}),
      lastDurationSeconds: siteDurationSeconds(site),
      pages: {
        complete: site.pages.filter((p) => p.status === 'complete').length,
        partial: site.pages.filter((p) => p.status === 'partial').length,
        failed: site.pages.filter((p) => p.status === 'failed').length,
      },
      scripts: {
        firstParty: resources.filter((r) => r.party !== 'third-party').length,
        thirdParty: resources.filter((r) => r.party === 'third-party').length,
      },
      blockedConnections: site.blockedConnections.length,
      ...(lastRecovery ? { lastRecovery } : {}),
    };
  }
  return recoveries;
}

/** Record the outcome of one alert delivery attempt for a channel (in place). */
export function recordAlertDelivery(state: HealthState, channel: string, ok: boolean, now: Date, error?: string): void {
  const prev = state.alerts[channel];
  const at = now.toISOString();
  state.alerts[channel] = {
    lastAttemptAt: at,
    ...(ok ? { lastSuccessAt: at } : prev?.lastSuccessAt ? { lastSuccessAt: prev.lastSuccessAt } : {}),
    consecutiveFailures: ok ? 0 : (prev?.consecutiveFailures ?? 0) + 1,
    ...(!ok && error ? { lastError: clean(error, 300) } : {}),
  };
}
