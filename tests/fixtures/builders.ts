import { sha256Hex } from '../../src/analysis/hashing.js';
import { normalizeJavaScript, NORMALIZER_VERSION } from '../../src/analysis/normalizer.js';
import { externalIdentity, inlineIdentity, resourceKey } from '../../src/discovery/resource-identity.js';
import type { DestinationSummary, PageResult, ScanResult, ScriptResource, SiteResult } from '../../src/types/index.js';

/** Builders for synthetic scan results used by unit tests (no browser needed). */

export function scriptResource(url: string, content: string, overrides: Partial<ScriptResource> = {}): ScriptResource {
  const sha = sha256Hex(content);
  const n = normalizeJavaScript(content);
  const host = new URL(url).hostname;
  const domain = host.split('.').slice(-2).join('.');
  const identity = overrides.identity ?? externalIdentity(url);
  return {
    key: resourceKey(identity, sha),
    identity,
    type: 'script',
    originalUrl: url,
    finalUrl: url,
    redirectChain: [],
    hostname: host,
    registrableDomain: domain,
    origin: new URL(url).origin,
    party: domain === 'shop.example' ? 'first-party' : 'third-party',
    frameContext: 'main-frame',
    frameUrls: ['https://shop.example/'],
    pages: ['/'],
    occurrences: 1,
    dynamic: false,
    discovery: ['network'],
    httpStatus: 200,
    contentType: 'application/javascript',
    size: content.length,
    content: { status: 'captured' },
    hashes: { sha256: sha, sri: null, normalizedSha256: n.normalizedSha256 ?? null, normalizerVersion: n.normalizedSha256 ? NORMALIZER_VERSION : null },
    normalization: { status: n.status },
    fromServiceWorker: false,
    firstSeenAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

export function inlineResource(page: string, domPath: string, content: string, overrides: Partial<ScriptResource> = {}): ScriptResource {
  const sha = sha256Hex(content);
  const n = normalizeJavaScript(content);
  const identity = inlineIdentity(page, 'https://shop.example' + page, true, domPath);
  return {
    key: resourceKey(identity, sha),
    identity,
    type: 'inline-script',
    redirectChain: [],
    registrableDomain: 'shop.example',
    party: 'first-party',
    frameContext: 'main-frame',
    frameUrls: ['https://shop.example' + page],
    pages: [page],
    occurrences: 1,
    dynamic: false,
    discovery: ['dom-inline'],
    size: content.length,
    content: { status: 'captured' },
    hashes: { sha256: sha, sri: null, normalizedSha256: n.normalizedSha256 ?? null, normalizerVersion: NORMALIZER_VERSION },
    normalization: { status: n.status },
    fromServiceWorker: false,
    domPath,
    firstSeenAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

export function page(key: string, overrides: Partial<PageResult> = {}): PageResult {
  return {
    key,
    url: `https://shop.example${key}`,
    sensitive: false,
    status: 'complete',
    issues: [],
    startedAt: '2026-01-01T00:00:00.000Z',
    finishedAt: '2026-01-01T00:00:01.000Z',
    resourceKeys: [],
    iframeOrigins: [],
    requests: [],
    requestsTruncated: 0,
    consoleErrorCount: 0,
    pageErrors: [],
    cspHeaders: [],
    cspReportOnlyHeaders: [],
    ...overrides,
  };
}

export function destination(hostname: string, overrides: Partial<DestinationSummary> = {}): DestinationSummary {
  const domain = hostname.split('.').slice(-2).join('.');
  return {
    hostname,
    registrableDomain: domain,
    party: domain === 'shop.example' ? 'first-party' : 'third-party',
    methods: ['GET'],
    resourceTypes: ['script'],
    requestCount: 1,
    pages: ['/'],
    blocked: false,
    ...overrides,
  };
}

export function site(resources: ScriptResource[], options: { pages?: PageResult[]; destinations?: DestinationSummary[]; iframes?: string[] } = {}): SiteResult {
  const pages = options.pages ?? [page('/')];
  const destinations =
    options.destinations ??
    [...new Set(resources.filter((r) => r.hostname).map((r) => r.hostname as string))].map((h) => destination(h, { pages: resources.find((r) => r.hostname === h)?.pages ?? ['/'] }));
  return {
    name: 'shop',
    url: 'https://shop.example/',
    profile: 'desktop-chromium',
    browser: { name: 'chromium', version: 'test', emulation: 'test' },
    status: pages.every((p) => p.status === 'complete') ? 'complete' : 'partial',
    issues: [],
    startedAt: '2026-01-01T00:00:00.000Z',
    finishedAt: '2026-01-01T00:01:00.000Z',
    pages,
    resources,
    destinations,
    domains: {
      scripts: [...new Set(resources.filter((r) => r.hostname).map((r) => r.registrableDomain as string))].sort(),
      outbound: [...new Set(destinations.map((d) => d.registrableDomain))].sort(),
      iframes: options.iframes ?? [],
    },
    blockedConnections: [],
  };
}

export function scan(sites: SiteResult[], scanId = '20260101T000000Z-test0001'): ScanResult {
  return {
    schemaVersion: 1,
    kind: 'thirdsentry-scan',
    scanId,
    toolVersion: '0.0.0',
    startedAt: '2026-01-01T00:00:00.000Z',
    finishedAt: '2026-01-01T00:01:00.000Z',
    status: sites.every((s) => s.status === 'complete') ? 'complete' : 'partial',
    isolation: 'none',
    serviceWorkerStrategy: 'block',
    issues: [],
    summary: { sites: 1, pages: 1, pagesComplete: 1, pagesPartial: 0, pagesFailed: 0, resources: 0, firstPartyResources: 0, thirdPartyResources: 0, resourcesWithoutContent: 0, thirdPartyDomains: 0, blockedConnections: 0 },
    sites,
    coverageLimitations: [],
  };
}
