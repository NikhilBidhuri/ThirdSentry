import type { Limits, NetworkSecurityConfig } from '../config/schema.js';
import type { ResolvedSite } from '../config/loader.js';
import { EgressProxy } from '../security/egress-proxy.js';
import { NetworkPolicy } from '../security/network-policy.js';
import { EVIDENCE_SCHEMA_VERSION, type Issue, type PageEvidence, type PageStatus, type ScanEvidence } from '../types/evidence.js';
import { getLogger } from '../utils/logger.js';
import { toolVersion } from '../utils/version.js';
import { launchBrowser, type LaunchedBrowser } from './browser-manager.js';
import { getBrowserProfile } from './browser-profiles.js';
import { effectiveScanBudget, ScanEvidenceBudget } from './evidence-budget.js';
import { MemorySink, type EvidenceSink } from './evidence-sink.js';
import { runJourney } from './journey-runner.js';
import { scanPage } from './page-scanner.js';
import { ProxyTagRelay } from './proxy-tag-relay.js';

/**
 * Everything the browser worker needs. Deliberately excludes alert settings,
 * credentials and storage paths: the worker cannot see or modify baselines.
 */
export interface CollectRequest {
  readonly scanId: string;
  readonly sites: readonly ResolvedSite[];
  readonly limits: Limits;
  readonly network: NetworkSecurityConfig;
  readonly serviceWorkers: { strategy: 'block' | 'allow'; probeBlockedRegistrations: boolean };
  readonly chromiumSandbox: boolean;
  readonly isolation: 'process' | 'none' | 'container';
  /** Run id used to tag connections to an external egress proxy (default: scanId). */
  readonly proxyRunId?: string;
}

export { newScanId } from '../utils/scan-id.js';

function worst(a: PageStatus, b: PageStatus): PageStatus {
  if (a === 'failed' || b === 'failed') return 'failed';
  if (a === 'partial' || b === 'partial') return 'partial';
  return 'complete';
}

export function siteStatus(pages: ReadonlyArray<{ readonly status: PageStatus }>): PageStatus {
  if (pages.length === 0) return 'failed';
  if (pages.every((p) => p.status === 'failed')) return 'failed';
  return pages.reduce<PageStatus>((acc, p) => (p.status === 'complete' ? acc : worst(acc, 'partial')), 'complete');
}

export function skippedPage(page: ResolvedSite['pages'][number], code: string, message: string): PageEvidence {
  const now = new Date().toISOString();
  return {
    pageKey: page.key,
    pageUrl: page.url,
    sensitive: page.sensitive,
    status: 'failed',
    issues: [{ level: 'error', code, message }],
    startedAt: now,
    finishedAt: now,
    documentHeaders: {},
    cspHeaders: [],
    cspReportOnlyHeaders: [],
    frames: [],
    scriptResponses: [],
    domScripts: [],
    blobs: [],
    workers: [],
    requests: [],
    requestsDropped: 0,
    scriptsDropped: 0,
    consoleErrors: [],
    pageErrors: [],
  };
}

/** Run the browser collection for all requested sites and return the evidence in memory. */
export async function collectEvidence(request: CollectRequest): Promise<ScanEvidence> {
  const sink = new MemorySink();
  await runCollection(request, sink);
  return sink.result();
}

/**
 * Run the browser collection, emitting evidence to `sink` as each page and
 * site completes, so a later crash or timeout cannot lose finished work and
 * no single in-memory structure has to hold the evidence of the whole scan.
 */
export async function runCollection(request: CollectRequest, sink: EvidenceSink): Promise<void> {
  const log = getLogger('collector');
  const startedAt = new Date();
  const deadline = startedAt.getTime() + request.limits.maxScanDurationMs;
  const issues: Issue[] = [];
  const policy = new NetworkPolicy({
    allowedPorts: request.network.allowedPorts,
    allowedPrivateHosts: request.network.allowedPrivateHosts,
    blockedHosts: request.network.blockedHosts,
    resolverOverrides: Object.fromEntries(Object.entries(request.network.resolverOverrides).map(([k, v]) => [k.toLowerCase(), v])),
  });

  let proxy: EgressProxy | undefined;
  let relay: ProxyTagRelay | undefined;
  let proxyUrl: string;
  if (request.network.externalProxy) {
    // Connections are tagged <runId>.<site>; the egress proxy records them and
    // the analyzer reads that trusted record (analyze --proxy-events).
    const runId = request.proxyRunId ?? request.scanId;
    relay = new ProxyTagRelay({ upstream: request.network.externalProxy, runId });
    proxyUrl = (await relay.start()).url;
    issues.push({ level: 'info', code: 'external-proxy', message: `Using external egress proxy; connection events are recorded by the proxy under run id ${runId}` });
  } else {
    proxy = new EgressProxy({
      policy,
      maxBytesPerConnection: request.limits.maxBytesPerConnection,
      connectTimeoutMs: request.network.connectTimeoutMs,
      idleTimeoutMs: request.network.idleTimeoutMs,
      maxConnections: 512,
      maxRecordedEvents: 5_000, // per site, for blocked and allowed events each
    });
    proxyUrl = (await proxy.start()).url;
  }
  if (request.network.allowedPrivateHosts.length > 0) {
    log.warn({ hosts: request.network.allowedPrivateHosts }, 'private-network access is allowed for some hosts (security.network.allowedPrivateHosts)');
    issues.push({
      level: 'warning',
      code: 'private-network-allowed',
      message: `Private network access permitted for: ${request.network.allowedPrivateHosts.join(', ')}`,
    });
  }

  await sink.begin({
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    scanId: request.scanId,
    toolVersion: toolVersion(),
    startedAt: startedAt.toISOString(),
    isolation: request.isolation,
    serviceWorkerStrategy: request.serviceWorkers.strategy,
    issues,
  });
  const evidenceBudget = new ScanEvidenceBudget(effectiveScanBudget(request.limits));
  let pagesBudget = request.limits.maxPagesPerScan;
  try {
    for (const [siteIndex, site] of request.sites.entries()) {
      const siteStarted = new Date().toISOString();
      const profile = getBrowserProfile(site.profile);
      const siteIssues: Issue[] = [];
      const pages: Array<{ status: PageStatus }> = [];
      const emit = async (page: PageEvidence): Promise<void> => {
        await sink.page(siteIndex, pages.length, page);
        pages.push({ status: page.status });
      };
      await sink.siteStarted(siteIndex, {
        name: site.name,
        url: site.url,
        profile: site.profile,
        browserName: profile.engine,
        emulation: profile.emulation,
        startedAt: siteStarted,
      });
      relay?.setSite(site.name);
      let launched: LaunchedBrowser | undefined;
      try {
        launched = await launchBrowser({ profile, proxyUrl, chromiumSandbox: request.chromiumSandbox });
      } catch (error) {
        let message = error instanceof Error ? error.message.split('\n')[0] ?? error.message : String(error);
        if (profile.engine === 'chromium' && request.chromiumSandbox && process.platform === 'linux') {
          message +=
            " (Chromium's sandbox is enabled; hosts that restrict unprivileged user namespaces, such as Ubuntu 23.10+, block it — see docs/troubleshooting.md)";
        }
        siteIssues.push({
          level: 'error',
          code: 'browser-launch-failed',
          message: `Could not launch ${profile.engine}: ${message}`,
        });
        log.error({ site: site.name, err: message }, 'browser launch failed');
      }
      try {
        // Journey captures (page.journey) are listed after the plain pages and run below.
        for (const page of site.pages.filter((p) => !p.journey)) {
          if (!launched) {
            await emit(skippedPage(page, 'browser-launch-failed', 'Browser could not be launched'));
            continue;
          }
          if (pagesBudget <= 0) {
            await emit(skippedPage(page, 'page-limit', 'limits.maxPagesPerScan reached; page not scanned'));
            continue;
          }
          if (Date.now() > deadline - 5_000) {
            await emit(skippedPage(page, 'scan-time-limit', 'limits.maxScanDurationMs reached; page not scanned'));
            continue;
          }
          pagesBudget--;
          log.info({ site: site.name, page: page.key }, 'scanning page');
          await emit(
            await scanPage({
              browser: launched.browser,
              profile,
              page,
              scan: site.scan,
              limits: request.limits,
              serviceWorkers: request.serviceWorkers,
              deadline,
              budget: evidenceBudget,
            }),
          );
        }
        for (const journey of site.journeys ?? []) {
          const captures = journey.captures;
          const skipAll = async (code: string, message: string): Promise<void> => {
            for (const c of captures) await emit(skippedPage(c, code, message)); // sequential: emit() numbers pages in order
          };
          if (!launched) {
            await skipAll('browser-launch-failed', 'Browser could not be launched');
            continue;
          }
          if (pagesBudget < captures.length) {
            await skipAll('page-limit', 'limits.maxPagesPerScan reached; journey not run');
            continue;
          }
          if (Date.now() > deadline - 5_000) {
            await skipAll('scan-time-limit', 'limits.maxScanDurationMs reached; journey not run');
            continue;
          }
          pagesBudget -= captures.length;
          log.info({ site: site.name, journey: journey.name }, 'running journey');
          const results = await runJourney({
            browser: launched.browser,
            profile,
            site,
            journey,
            limits: request.limits,
            serviceWorkers: request.serviceWorkers,
            deadline,
            budget: evidenceBudget,
          });
          // Emitted in order, after the whole journey: a capture's evidence is only final once the journey ended.
          for (const result of results) await emit(result);
        }
      } finally {
        await launched?.close();
      }
      // Per-site accounting: drainEvents() returns this site's events (capped per
      // site by the proxy) and how many were dropped, then resets for the next site.
      const proxyEvents = proxy ? proxy.drainEvents() : { events: [], dropped: 0 };
      await sink.siteFinished(siteIndex, {
        name: site.name,
        url: site.url,
        profile: site.profile,
        browserName: profile.engine,
        browserVersion: launched?.version ?? 'unknown',
        emulation: profile.emulation,
        status: launched ? siteStatus(pages) : 'failed',
        issues: siteIssues,
        startedAt: siteStarted,
        finishedAt: new Date().toISOString(),
        proxyEvents: proxyEvents.events,
        proxyEventsDropped: proxyEvents.dropped,
      });
    }
  } finally {
    await proxy?.stop();
    await relay?.stop();
  }

  await sink.end({ finishedAt: new Date().toISOString(), issues });
}
