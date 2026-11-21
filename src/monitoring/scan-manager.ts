// Type-only: the browser stack (Playwright) is loaded lazily, only when a scan collects.
import type { CollectRequest } from '../browser/collector.js';
import { newScanId } from '../utils/scan-id.js';
import { createNetworkPolicy, type ResolvedConfig, type ResolvedSite } from '../config/loader.js';
import { processEvidence, type ProcessedScan } from '../analysis/evidence-processor.js';
import { loadLibraryDb, type LibraryDb } from '../analysis/libraries/vulndb.js';
import { analyzeResources } from '../analysis/script-analysis.js';
import { effectivePort, validateTargetUrlWithDns } from '../security/url-validator.js';
import { runIsolatedCollection, validateEvidence } from '../security/worker-sandbox.js';
import { applyRetention, ContentStore, saveScanResult, saveScreenshots, scriptContentMode } from '../storage/filesystem-store.js';
import { loadBaseline } from '../baseline/baseline-manager.js';
import type { ScanEvidence } from '../types/evidence.js';
import type { ScanResult, ScriptResource } from '../types/index.js';
import { assertScanSitesConfigured } from './analysis-runner.js';
import { compareSite } from './comparison-engine.js';
import { ConfigError, ThirdSentryError } from '../utils/errors.js';
import { getLogger } from '../utils/logger.js';

export interface ScanRunOptions {
  readonly sites: readonly ResolvedSite[];
  readonly logLevel?: string;
  /** Skip DNS pre-flight validation (the egress proxy still validates every connection). */
  readonly skipPreflight?: boolean;
}

export interface ScanRunResult extends ProcessedScan {
  readonly scanPath: string;
}

export function buildCollectRequest(resolved: ResolvedConfig, sites: readonly ResolvedSite[], scanId = newScanId()): CollectRequest {
  const { config } = resolved;
  return {
    scanId,
    sites,
    limits: config.limits,
    network: config.security.network,
    serviceWorkers: config.serviceWorkers,
    chromiumSandbox: config.security.isolation.chromiumSandbox,
    isolation: config.security.isolation.mode,
  };
}

/**
 * Resolve every site host before launching a browser. Policy violations (a
 * configured site that resolves to a private or metadata address) are
 * configuration errors. Transient DNS failures are not: the page is then
 * reported as failed by the scan itself, so other sites are still scanned.
 */
export async function preflight(resolved: ResolvedConfig, sites: readonly ResolvedSite[]): Promise<void> {
  const log = getLogger('scan');
  const policy = createNetworkPolicy(resolved.config);
  const hosts = new Map<string, string>();
  for (const site of sites) for (const page of site.pages) hosts.set(new URL(page.url).origin, page.url);
  for (const url of hosts.values()) {
    const target = new URL(url);
    const decision = await policy.resolveDestination(target.hostname, effectivePort(target));
    if (decision.allowed) continue;
    if (decision.code === 'dns-failure') {
      log.warn({ origin: target.origin, reason: decision.reason }, 'pre-flight DNS resolution failed; the page will be reported as failed');
      continue;
    }
    try {
      await validateTargetUrlWithDns(url, policy);
    } catch (error) {
      if (error instanceof ThirdSentryError) throw new ConfigError(error.message, error.hint);
      throw error;
    }
  }
}

/** Run browser collection with the configured isolation mode and return validated evidence. */
export async function collect(resolved: ResolvedConfig, request: CollectRequest, logLevel?: string): Promise<ScanEvidence> {
  const log = getLogger('scan');
  if (request.isolation === 'process') {
    return runIsolatedCollection(request, {
      maxEvidenceBytes: resolved.config.limits.maxEvidenceBytes,
      timeoutMs: resolved.config.limits.maxScanDurationMs + 120_000,
      ...(logLevel ? { logLevel } : {}),
    });
  }
  log.warn('security.isolation.mode is "none": the browser runs inside the coordinator process. Use only for debugging.');
  const { collectEvidence } = await import('../browser/collector.js');
  // Validate with the same schema as the isolated modes (no JSON round-trip: one
  // string for a large scan can exceed V8's maximum string length).
  return validateEvidence(await collectEvidence(request));
}

/**
 * Static analysis of every captured script, grouped by content hash. A failure
 * while analysing one script is recorded on that script and never aborts the
 * scan (the analyser itself is size-bounded by analysis.maxScriptBytes).
 */
function analyzeAll(resolved: ResolvedConfig, result: ScanResult, contents: ReadonlyMap<string, Buffer>, libraryDb?: LibraryDb): void {
  const groups = new Map<string, ScriptResource[]>();
  for (const r of result.sites.flatMap((s) => s.resources)) {
    const key = r.hashes.sha256 ?? `\u0000${r.identity}`;
    const list = groups.get(key) ?? [];
    list.push(r);
    groups.set(key, list);
  }
  for (const group of groups.values()) {
    try {
      analyzeResources(group, contents, resolved.config, libraryDb);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      getLogger('analysis').warn({ resource: group[0]?.identity, err: message }, 'static analysis failed for a script; continuing');
      for (const r of group) r.indicators = { analyzed: false, error: `analysis failed: ${message.slice(0, 200)}`, counts: {}, matches: [], hosts: [] };
    }
  }
}

/**
 * Content hashes whose bodies are kept in the content cache.
 *
 *  none      nothing
 *  all       every captured body
 *  findings  approved versions (the "before" side of a future code diff) and
 *            versions behind a finding (the "after" side). For a site without
 *            a baseline yet, every script is awaiting approval, so all of its
 *            bodies are kept.
 */
export async function contentToRetain(resolved: ResolvedConfig, result: ScanResult, contents: ReadonlyMap<string, Buffer>): Promise<Set<string>> {
  const mode = scriptContentMode(resolved.config.retention);
  if (mode === 'none') return new Set();
  if (mode === 'all') return new Set(contents.keys());
  const keep = new Set<string>();
  for (const site of result.sites) {
    let baseline;
    try {
      baseline = await loadBaseline(resolved.paths, site.name);
    } catch {
      baseline = undefined; // an invalid baseline is reported by the analysis; treat everything as pending review
    }
    if (!baseline) {
      for (const r of site.resources) if (r.hashes.sha256) keep.add(r.hashes.sha256);
      continue;
    }
    const approved = new Set(baseline.resources.flatMap((b) => b.approvedHashes.map((h) => h.sha256)).filter((h): h is string => h !== null));
    for (const r of site.resources) if (r.hashes.sha256 && approved.has(r.hashes.sha256)) keep.add(r.hashes.sha256);
    for (const c of compareSite(site, baseline, resolved.config.domains).changes) {
      const sha = c.current?.hashes.sha256;
      if (sha) keep.add(sha);
    }
  }
  for (const sha of [...keep]) if (!contents.has(sha)) keep.delete(sha);
  return keep;
}

/**
 * Process validated evidence and persist results (never touches baselines).
 *
 * The raw inventory is saved BEFORE static analysis: if analysing a hostile
 * script hangs or exhausts memory, reports/scans/<scan-id>.json still records
 * what was observed. latest-scan.json is only updated once the analysed result
 * is complete.
 */
export async function persistScan(resolved: ResolvedConfig, evidence: ScanEvidence): Promise<ScanRunResult> {
  assertScanSitesConfigured(resolved, evidence.sites.map((s) => s.name), `Evidence for scan ${evidence.scanId}`);
  const processed = processEvidence(evidence, resolved.sites, {
    maxRequestsStoredPerPage: 1000,
    maxResourceBytes: resolved.config.limits.maxResourceBytes,
  });
  await saveScanResult(resolved.paths, processed.result, { updateLatest: false });
  await saveScreenshots(resolved.paths, processed.screenshots);
  const libraryDb = resolved.config.libraries.detect ? await loadLibraryDb(resolved.paths.cache, { maxAgeDays: resolved.config.libraries.maxDbAgeDays }) : undefined;
  analyzeAll(resolved, processed.result, processed.contents, libraryDb);
  const scanPath = await saveScanResult(resolved.paths, processed.result);
  const retain = await contentToRetain(resolved, processed.result, processed.contents);
  if (retain.size > 0) {
    const store = new ContentStore(resolved.paths.content);
    for (const sha of retain) await store.put(sha, processed.contents.get(sha) as Buffer);
  }
  await enforceRetention(resolved);
  return { ...processed, scanPath };
}

/** Content hashes referenced by any approved baseline (kept by retention). */
export async function baselineContentHashes(resolved: ResolvedConfig): Promise<Set<string>> {
  const keep = new Set<string>();
  for (const site of resolved.config.sites) {
    try {
      const baseline = await loadBaseline(resolved.paths, site.name);
      for (const r of baseline?.resources ?? []) for (const h of r.approvedHashes) if (h.sha256) keep.add(h.sha256);
    } catch {
      // An invalid baseline is reported elsewhere; retention stays conservative.
    }
  }
  return keep;
}

/** Apply the configured retention policy after a scan. Failures are logged, never fatal. */
export async function enforceRetention(resolved: ResolvedConfig): Promise<void> {
  try {
    const result = await applyRetention(resolved.paths, {
      maxScans: resolved.config.retention.maxScanReports,
      maxAgeDays: resolved.config.retention.maxAgeDays,
      keepContent: await baselineContentHashes(resolved),
    });
    if (result.removedScans + result.removedContent + result.removedScreenshots > 0) getLogger('retention').info(result, 'applied retention policy');
  } catch (error) {
    getLogger('retention').warn({ err: error instanceof Error ? error.message : String(error) }, 'could not apply retention policy');
  }
}

export async function runScan(resolved: ResolvedConfig, options: ScanRunOptions): Promise<ScanRunResult> {
  const log = getLogger('scan');
  if (options.sites.length === 0) throw new ConfigError('No enabled sites to scan', 'Enable a site or pass --site');
  if (!options.skipPreflight) await preflight(resolved, options.sites);
  const request = buildCollectRequest(resolved, options.sites);
  log.info({ scanId: request.scanId, sites: options.sites.map((s) => s.name) }, 'starting scan');
  const evidence = await collect(resolved, request, options.logLevel);
  return persistScan(resolved, evidence);
}
