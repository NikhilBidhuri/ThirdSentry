import { randomUUID } from 'node:crypto';
import type { Limits, NetworkSecurityConfig } from '../config/schema.js';
import type { ResolvedSite } from '../config/loader.js';
import { EgressProxy, type ProxyConnectionEvent } from '../security/egress-proxy.js';
import { NetworkPolicy } from '../security/network-policy.js';
import { EVIDENCE_SCHEMA_VERSION, type Issue, type PageEvidence, type PageStatus, type ScanEvidence, type SiteEvidence } from '../types/evidence.js';
import { getLogger } from '../utils/logger.js';
import { toolVersion } from '../utils/version.js';
import { launchBrowser, type LaunchedBrowser } from './browser-manager.js';
import { getBrowserProfile } from './browser-profiles.js';
import { scanPage } from './page-scanner.js';

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
}

export function newScanId(now = new Date()): string {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  return `${stamp}-${randomUUID().slice(0, 8)}`;
}

function worst(a: PageStatus, b: PageStatus): PageStatus {
  if (a === 'failed' || b === 'failed') return 'failed';
  if (a === 'partial' || b === 'partial') return 'partial';
  return 'complete';
}

function siteStatus(pages: readonly PageEvidence[]): PageStatus {
  if (pages.length === 0) return 'failed';
  if (pages.every((p) => p.status === 'failed')) return 'failed';
  return pages.reduce<PageStatus>((acc, p) => (p.status === 'complete' ? acc : worst(acc, 'partial')), 'complete');
}

function skippedPage(page: ResolvedSite['pages'][number], code: string, message: string): PageEvidence {
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

/** Run the browser collection for all requested sites. */
export async function collectEvidence(request: CollectRequest): Promise<ScanEvidence> {
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
  let proxyUrl: string;
  if (request.network.externalProxy) {
    proxyUrl = request.network.externalProxy;
    issues.push({ level: 'info', code: 'external-proxy', message: 'Using external egress proxy; blocked-connection details are logged by the proxy container' });
  } else {
    proxy = new EgressProxy({
      policy,
      maxBytesPerConnection: request.limits.maxBytesPerConnection,
      connectTimeoutMs: request.network.connectTimeoutMs,
      idleTimeoutMs: request.network.idleTimeoutMs,
      maxConnections: 512,
      maxRecordedEvents: 20_000,
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

  const sites: SiteEvidence[] = [];
  let pagesBudget = request.limits.maxPagesPerScan;
  try {
    for (const site of request.sites) {
      const siteStarted = new Date().toISOString();
      const profile = getBrowserProfile(site.profile);
      const siteIssues: Issue[] = [];
      const pages: PageEvidence[] = [];
      const eventStart = proxy?.getEvents().events.length ?? 0;
      let launched: LaunchedBrowser | undefined;
      try {
        launched = await launchBrowser({ profile, proxyUrl, chromiumSandbox: request.chromiumSandbox });
      } catch (error) {
        const message = error instanceof Error ? error.message.split('\n')[0] ?? error.message : String(error);
        siteIssues.push({
          level: 'error',
          code: 'browser-launch-failed',
          message: `Could not launch ${profile.engine}: ${message}`,
        });
        log.error({ site: site.name, err: message }, 'browser launch failed');
      }
      try {
        for (const page of site.pages) {
          if (!launched) {
            pages.push(skippedPage(page, 'browser-launch-failed', 'Browser could not be launched'));
            continue;
          }
          if (pagesBudget <= 0) {
            pages.push(skippedPage(page, 'page-limit', 'limits.maxPagesPerScan reached; page not scanned'));
            continue;
          }
          if (Date.now() > deadline - 5_000) {
            pages.push(skippedPage(page, 'scan-time-limit', 'limits.maxScanDurationMs reached; page not scanned'));
            continue;
          }
          pagesBudget--;
          log.info({ site: site.name, page: page.key }, 'scanning page');
          pages.push(
            await scanPage({
              browser: launched.browser,
              profile,
              page,
              scan: site.scan,
              limits: request.limits,
              serviceWorkers: request.serviceWorkers,
              deadline,
            }),
          );
        }
      } finally {
        await launched?.close();
      }
      const events: ProxyConnectionEvent[] = proxy ? proxy.getEvents().events.slice(eventStart) : [];
      sites.push({
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
        pages,
        proxyEvents: events.filter((e) => !e.allowed).slice(0, 5_000).concat(events.filter((e) => e.allowed).slice(0, 5_000)),
        proxyEventsDropped: Math.max(0, events.length - 10_000),
      });
    }
  } finally {
    await proxy?.stop();
  }

  return {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    scanId: request.scanId,
    toolVersion: toolVersion(),
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    isolation: request.isolation,
    serviceWorkerStrategy: request.serviceWorkers.strategy,
    sites,
    issues,
  };
}
