import type { ResolvedSite } from '../config/loader.js';
import { discoverPageResources, iframeOrigins, type ResourceCandidate } from '../discovery/index.js';
import { classifyParty, hostInfo, partyContextFor, type PartyContext } from '../discovery/resource-classifier.js';
import { resourceKey } from '../discovery/resource-identity.js';
import { redactText, redactUrl } from '../security/redaction.js';
import type { PageEvidence, ProxyEvent, ScanEvidence, SiteEvidence } from '../types/evidence.js';
import type {
  DestinationSummary,
  OutboundRequest,
  PageResult,
  ScanResult,
  ScanSummary,
  ScriptResource,
  SiteResult,
} from '../types/index.js';
import { compact } from '../utils/object.js';
import { sha256Hex, sriHash, verifySri } from './hashing.js';
import { NORMALIZER_VERSION, normalizeJavaScript } from './normalizer.js';
import { goalForResourceType } from './parser.js';
import { coverageLimitations } from './coverage.js';

/**
 * Trusted processing of validated browser evidence: discovery, de-duplication,
 * hashing, normalisation, party classification and outbound-request
 * summarisation. Produces the persisted ScanResult plus in-memory script
 * contents (for optional retention and static analysis).
 */

export interface ProcessOptions {
  readonly maxRequestsStoredPerPage: number;
  readonly maxResourceBytes: number;
}

export interface ProcessedScan {
  readonly result: ScanResult;
  /** Captured script bodies keyed by raw SHA-256. Never persisted unless retention is enabled. */
  readonly contents: ReadonlyMap<string, Buffer>;
  readonly screenshots: ReadonlyArray<{ readonly path: string; readonly data: Buffer }>;
}

interface MutableResource {
  key: string;
  identity: string;
  type: ScriptResource['type'];
  originalUrl?: string;
  finalUrl?: string;
  redirectChain: readonly string[];
  hostname?: string;
  registrableDomain?: string;
  origin?: string;
  party: ScriptResource['party'];
  frameContext: ScriptResource['frameContext'];
  frameUrls: Set<string>;
  pages: Set<string>;
  occurrences: number;
  dynamic: boolean;
  discovery: Set<string>;
  httpStatus?: number;
  contentType?: string;
  size?: number;
  content: ScriptResource['content'];
  hashes: ScriptResource['hashes'];
  normalization: ScriptResource['normalization'];
  sri?: ScriptResource['sri'];
  fromServiceWorker: boolean;
  responseHeaders?: Readonly<Record<string, string>>;
  domPath?: string;
  firstSeenAt: string;
}

const NON_JS_DISCOVERY = new Set(['importmap']);

function buildResource(c: ResourceCandidate, party: PartyContext, contents: Map<string, Buffer>, maxChars: number): MutableResource {
  const body = c.body;
  const sha = body ? sha256Hex(body) : null;
  if (body && sha) contents.set(sha, body);
  const isJs = c.type !== 'wasm' && !c.discovery.some((d) => NON_JS_DISCOVERY.has(d));
  let normalization: ScriptResource['normalization'];
  let normalizedSha: string | null = null;
  if (!body) normalization = { status: 'unavailable' };
  else if (!isJs) normalization = { status: 'not-javascript' };
  else if (c.contentStatus === 'truncated') normalization = { status: 'unavailable', error: 'content truncated' };
  else {
    const n = normalizeJavaScript(body.toString('utf8'), { maxChars, goal: goalForResourceType(c.type) });
    normalization = compact({ status: n.status, error: n.error });
    normalizedSha = n.normalizedSha256 ?? null;
  }
  const info = c.partyUrl ? hostInfo(c.partyUrl) : undefined;
  let origin: string | undefined;
  const hostUrl = c.finalUrl ?? c.originalUrl;
  if (hostUrl && /^https?:/i.test(hostUrl)) {
    try {
      origin = new URL(hostUrl).origin;
    } catch {
      origin = undefined;
    }
  }
  const external = c.finalUrl ?? (c.originalUrl && /^https?:/i.test(c.originalUrl) ? c.originalUrl : undefined);
  const externalInfo = external ? hostInfo(external) : undefined;
  return compact<MutableResource>({
    key: resourceKey(c.identity, sha),
    identity: c.identity,
    type: c.type,
    originalUrl: c.originalUrl,
    finalUrl: c.finalUrl,
    redirectChain: c.redirectChain,
    hostname: externalInfo?.hostname,
    registrableDomain: externalInfo?.registrableDomain ?? info?.registrableDomain,
    origin,
    party: classifyParty(info, party),
    frameContext: c.frameContext,
    frameUrls: new Set(c.frameUrl ? [redactUrl(c.frameUrl)] : []),
    pages: new Set([c.pageKey]),
    occurrences: 1,
    dynamic: c.dynamic,
    discovery: new Set(c.discovery),
    httpStatus: c.httpStatus,
    contentType: c.contentType,
    size: body?.length ?? c.declaredSize,
    content: compact({ status: c.contentStatus, note: c.contentNote }),
    hashes: {
      sha256: sha,
      sri: body ? sriHash(body) : null,
      normalizedSha256: normalizedSha,
      normalizerVersion: normalizedSha ? NORMALIZER_VERSION : null,
    },
    normalization,
    sri: c.integrity ? { attribute: c.integrity.slice(0, 512), valid: body && c.contentStatus === 'captured' ? verifySri(c.integrity, body) : null } : undefined,
    fromServiceWorker: c.fromServiceWorker,
    responseHeaders: c.responseHeaders,
    domPath: c.domPath,
    firstSeenAt: c.timestamp,
  });
}

function merge(target: MutableResource, c: ResourceCandidate): void {
  target.occurrences++;
  target.pages.add(c.pageKey);
  if (c.frameUrl) target.frameUrls.add(redactUrl(c.frameUrl));
  c.discovery.forEach((d) => target.discovery.add(d));
  target.dynamic ||= c.dynamic;
  target.fromServiceWorker ||= c.fromServiceWorker;
  if (c.timestamp < target.firstSeenAt) target.firstSeenAt = c.timestamp;
  if (target.frameContext !== c.frameContext && target.frameContext !== 'main-frame' && c.frameContext === 'main-frame') {
    target.frameContext = 'main-frame';
  }
}

function freeze(r: MutableResource): ScriptResource {
  return compact<ScriptResource>({
    ...r,
    frameUrls: [...r.frameUrls].sort().slice(0, 50),
    pages: [...r.pages].sort(),
    discovery: [...r.discovery].sort(),
  });
}

function isBlockedFailure(failure: string | undefined): boolean {
  return failure !== undefined && /TUNNEL_CONNECTION_FAILED|PROXY|403|blocked/i.test(failure);
}

function outboundRequests(page: PageEvidence, party: PartyContext, blockedHosts: ReadonlySet<string>, max: number): { requests: OutboundRequest[]; truncated: number } {
  const out: OutboundRequest[] = [];
  let truncated = 0;
  for (const req of page.requests) {
    let url: URL;
    try {
      url = new URL(req.url);
    } catch {
      continue;
    }
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol)) continue;
    if (out.length >= max) {
      truncated++;
      continue;
    }
    const info = hostInfo(url.hostname);
    if (!info) continue;
    out.push(
      compact<OutboundRequest>({
        url: redactUrl(req.url),
        method: req.method,
        hostname: info.hostname,
        registrableDomain: info.registrableDomain,
        party: classifyParty(info, party),
        resourceType: req.resourceType,
        frameUrl: req.frameUrl ? redactUrl(req.frameUrl) : undefined,
        isMainFrame: req.isMainFrame,
        page: page.pageKey,
        timestamp: req.timestamp,
        status: req.status,
        failure: req.failure ? redactText(req.failure, 300) : undefined,
        fromServiceWorker: req.fromServiceWorker,
        // blockedHosts comes from the egress proxy's blocked-connection events. HTTPS
        // (CONNECT) refusals surface as a failed request without a status; plain
        // http:// refusals are delivered to the page as the proxy's own 403 response.
        blocked: blockedHosts.has(info.hostname) && (req.failure === undefined || isBlockedFailure(req.failure)) && (req.status === undefined || req.status === 403),
      }),
    );
  }
  return { requests: out, truncated: truncated + page.requestsDropped };
}

function summariseDestinations(pages: readonly PageResult[]): DestinationSummary[] {
  const map = new Map<string, { s: Omit<DestinationSummary, 'methods' | 'resourceTypes' | 'pages'>; methods: Set<string>; types: Set<string>; pages: Set<string> }>();
  for (const page of pages) {
    for (const req of page.requests) {
      let entry = map.get(req.hostname);
      if (!entry) {
        entry = {
          s: { hostname: req.hostname, registrableDomain: req.registrableDomain, party: req.party, requestCount: 0, blocked: false },
          methods: new Set(),
          types: new Set(),
          pages: new Set(),
        };
        map.set(req.hostname, entry);
      }
      entry.s = { ...entry.s, requestCount: entry.s.requestCount + 1, blocked: entry.s.blocked || req.blocked };
      entry.methods.add(req.method);
      entry.types.add(req.resourceType);
      entry.pages.add(req.page);
    }
  }
  return [...map.values()]
    .map((e) => ({ ...e.s, methods: [...e.methods].sort(), resourceTypes: [...e.types].sort(), pages: [...e.pages].sort() }))
    .sort((a, b) => a.hostname.localeCompare(b.hostname));
}

function processSite(
  evidence: SiteEvidence,
  site: ResolvedSite | undefined,
  scanId: string,
  options: ProcessOptions,
  contents: Map<string, Buffer>,
  screenshots: Array<{ path: string; data: Buffer }>,
): SiteResult {
  const party = partyContextFor(evidence.url, site?.firstPartyDomains ?? []);
  const ignoreQueryParams = site?.ignoreQueryParams ?? [];
  const resources = new Map<string, MutableResource>();
  const blockedHosts = new Set(evidence.proxyEvents.filter((e: ProxyEvent) => !e.allowed).map((e) => e.host.toLowerCase()));
  const pages: PageResult[] = [];

  evidence.pages.forEach((page, index) => {
    const candidates = discoverPageResources(page, {
      pageKey: page.pageKey,
      ignoreQueryParams,
      maxResourceBytes: options.maxResourceBytes,
    });
    const pageKeys = new Set<string>();
    for (const c of candidates) {
      const sha = c.body ? sha256Hex(c.body) : null;
      const key = resourceKey(c.identity, sha);
      const existing = resources.get(key);
      if (existing) merge(existing, c);
      else resources.set(key, buildResource(c, party, contents, options.maxResourceBytes * 2));
      pageKeys.add(key);
    }
    const { requests, truncated } = outboundRequests(page, party, blockedHosts, options.maxRequestsStoredPerPage);
    let screenshot: string | undefined;
    if (page.screenshotBase64) {
      screenshot = `screenshots/${scanId}/${evidence.name}/${index}.png`;
      screenshots.push({ path: screenshot, data: Buffer.from(page.screenshotBase64, 'base64') });
    }
    pages.push(
      compact<PageResult>({
        key: page.pageKey,
        url: redactUrl(page.pageUrl),
        finalUrl: page.finalUrl ? redactUrl(page.finalUrl) : undefined,
        sensitive: page.sensitive,
        status: page.status,
        issues: page.issues,
        startedAt: page.startedAt,
        finishedAt: page.finishedAt,
        documentStatus: page.documentStatus,
        resourceKeys: [...pageKeys].sort(),
        iframeOrigins: iframeOrigins(page),
        requests,
        requestsTruncated: truncated,
        consoleErrorCount: page.consoleErrors.length,
        pageErrors: page.pageErrors.slice(0, 20),
        cspHeaders: page.cspHeaders,
        cspReportOnlyHeaders: page.cspReportOnlyHeaders,
        screenshot,
      }),
    );
  });

  const frozen = [...resources.values()].map(freeze).sort((a, b) => a.key.localeCompare(b.key));
  const destinations = summariseDestinations(pages);
  const scriptDomains = new Set(frozen.filter((r) => r.hostname).map((r) => r.registrableDomain as string));
  return {
    name: evidence.name,
    url: evidence.url,
    profile: evidence.profile,
    browser: { name: evidence.browserName, version: evidence.browserVersion, emulation: evidence.emulation },
    status: evidence.status,
    issues: evidence.issues,
    startedAt: evidence.startedAt,
    finishedAt: evidence.finishedAt,
    pages,
    resources: frozen,
    destinations,
    domains: {
      scripts: [...scriptDomains].sort(),
      outbound: [...new Set(destinations.map((d) => d.registrableDomain))].sort(),
      iframes: [...new Set(pages.flatMap((p) => p.iframeOrigins))].sort(),
    },
    blockedConnections: evidence.proxyEvents.filter((e) => !e.allowed).slice(0, 1000),
  };
}

export function summarise(sites: readonly SiteResult[]): ScanSummary {
  const pages = sites.flatMap((s) => s.pages);
  const resources = sites.flatMap((s) => s.resources);
  const thirdPartyDomains = new Set(
    sites.flatMap((s) => [...s.resources.filter((r) => r.party === 'third-party').map((r) => r.registrableDomain ?? ''), ...s.destinations.filter((d) => d.party === 'third-party').map((d) => d.registrableDomain)]).filter(Boolean),
  );
  return {
    sites: sites.length,
    pages: pages.length,
    pagesComplete: pages.filter((p) => p.status === 'complete').length,
    pagesPartial: pages.filter((p) => p.status === 'partial').length,
    pagesFailed: pages.filter((p) => p.status === 'failed').length,
    resources: resources.length,
    firstPartyResources: resources.filter((r) => r.party === 'first-party').length,
    thirdPartyResources: resources.filter((r) => r.party === 'third-party').length,
    resourcesWithoutContent: resources.filter((r) => r.hashes.sha256 === null).length,
    thirdPartyDomains: thirdPartyDomains.size,
    blockedConnections: sites.reduce((n, s) => n + s.blockedConnections.length, 0),
  };
}

export function overallStatus(sites: readonly SiteResult[]): ScanResult['status'] {
  if (sites.length === 0) return 'failed';
  if (sites.every((s) => s.status === 'failed')) return 'failed';
  if (sites.every((s) => s.status === 'complete')) return 'complete';
  return 'partial';
}

export function processEvidence(evidence: ScanEvidence, sites: readonly ResolvedSite[], options: ProcessOptions): ProcessedScan {
  const contents = new Map<string, Buffer>();
  const screenshots: Array<{ path: string; data: Buffer }> = [];
  const siteResults = evidence.sites.map((s) =>
    processSite(s, sites.find((cfg) => cfg.name === s.name), evidence.scanId, options, contents, screenshots),
  );
  const result: ScanResult = {
    schemaVersion: 1,
    kind: 'thirdsentry-scan',
    scanId: evidence.scanId,
    toolVersion: evidence.toolVersion,
    startedAt: evidence.startedAt,
    finishedAt: evidence.finishedAt,
    status: overallStatus(siteResults),
    isolation: evidence.isolation,
    serviceWorkerStrategy: evidence.serviceWorkerStrategy,
    issues: evidence.issues,
    summary: summarise(siteResults),
    sites: siteResults,
    coverageLimitations: coverageLimitations(evidence, siteResults),
  };
  return { result, contents, screenshots };
}
