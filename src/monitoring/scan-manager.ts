import { collectEvidence, newScanId, type CollectRequest } from '../browser/collector.js';
import { createNetworkPolicy, type ResolvedConfig, type ResolvedSite } from '../config/loader.js';
import { processEvidence, type ProcessedScan } from '../analysis/evidence-processor.js';
import { effectivePort, validateTargetUrlWithDns } from '../security/url-validator.js';
import { runIsolatedCollection, validateEvidence } from '../security/worker-sandbox.js';
import { ContentStore, saveScanResult, saveScreenshots } from '../storage/filesystem-store.js';
import type { ScanEvidence } from '../types/evidence.js';
import { ConfigError, ScriptDriftError } from '../utils/errors.js';
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
      if (error instanceof ScriptDriftError) throw new ConfigError(error.message, error.hint);
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
  // Round-trip through the validator so both modes apply identical checks.
  return validateEvidence(JSON.parse(JSON.stringify(await collectEvidence(request))));
}

/** Process validated evidence and persist results (never touches baselines). */
export async function persistScan(resolved: ResolvedConfig, evidence: ScanEvidence): Promise<ScanRunResult> {
  const processed = processEvidence(evidence, resolved.sites, {
    maxRequestsStoredPerPage: 1000,
    maxResourceBytes: resolved.config.limits.maxResourceBytes,
  });
  const scanPath = await saveScanResult(resolved.paths, processed.result);
  await saveScreenshots(resolved.paths, processed.screenshots);
  if (resolved.config.retention.storeScriptContent) {
    const store = new ContentStore(resolved.paths.content);
    for (const [sha, data] of processed.contents) await store.put(sha, data);
  }
  return { ...processed, scanPath };
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
