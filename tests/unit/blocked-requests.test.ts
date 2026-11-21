import { describe, expect, it } from 'vitest';
import { processEvidence } from '../../src/analysis/evidence-processor.js';
import { skippedPage } from '../../src/browser/collector.js';
import { EVIDENCE_SCHEMA_VERSION, type PageEvidence, type RequestEvidence, type ScanEvidence } from '../../src/types/evidence.js';

/**
 * The egress proxy refuses a destination in two ways: an HTTPS (CONNECT) refusal makes
 * the browser request fail without a status, while a plain http:// refusal is delivered
 * to the page as the proxy's own 403. Both must count as blocked when the trusted proxy
 * record says the host was blocked.
 */
const T = '2026-01-01T00:00:00.000Z';

function request(url: string, overrides: Partial<RequestEvidence> = {}): RequestEvidence {
  return { url, method: 'GET', resourceType: 'fetch', isMainFrame: true, isNavigation: false, fromServiceWorker: false, timestamp: T, ...overrides };
}

function evidence(requests: RequestEvidence[], blockedHosts: string[]): ScanEvidence {
  const page: PageEvidence = {
    ...skippedPage({ key: '/', url: 'https://shop.example/', sensitive: false } as never, 'x', 'x'),
    status: 'complete',
    issues: [],
    requests,
  };
  return {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    scanId: '20260101T000000Z-test0001',
    toolVersion: 'test',
    startedAt: T,
    finishedAt: T,
    isolation: 'container',
    serviceWorkerStrategy: 'block',
    issues: [],
    sites: [
      {
        name: 'shop',
        url: 'https://shop.example/',
        profile: 'desktop-chromium',
        browserName: 'chromium',
        browserVersion: '1',
        emulation: 'desktop',
        status: 'complete',
        issues: [],
        startedAt: T,
        finishedAt: T,
        pages: [page],
        proxyEvents: blockedHosts.map((host) => ({ timestamp: T, host, port: 80, method: 'GET', allowed: false, code: 'cloud-metadata' })),
        proxyEventsDropped: 0,
      },
    ],
  };
}

function blockedFlags(ev: ScanEvidence): Record<string, boolean> {
  const { result } = processEvidence(ev, [], { maxRequestsStoredPerPage: 100, maxResourceBytes: 1_000_000 });
  const site = result.sites[0]!;
  return Object.fromEntries(site.destinations.map((d) => [d.hostname, d.blocked]));
}

describe('blocked outbound requests', () => {
  it('counts a plain http:// refusal (the proxy\'s 403) as blocked', () => {
    const flags = blockedFlags(evidence([request('http://169.254.169.254/latest/meta-data/', { status: 403 })], ['169.254.169.254']));
    expect(flags['169.254.169.254']).toBe(true);
  });

  it('counts an HTTPS (CONNECT) refusal without a status as blocked', () => {
    const ev = evidence([request('https://169.254.169.254/', { failure: 'net::ERR_TUNNEL_CONNECTION_FAILED' })], []);
    ev.sites[0]!.proxyEvents.push({ timestamp: T, host: '169.254.169.254', port: 443, method: 'CONNECT', allowed: false, code: 'cloud-metadata' });
    const flags = blockedFlags(ev);
    expect(flags['169.254.169.254']).toBe(true);
  });

  it('counts a refused http:// fetch that the browser reports as a generic CORS failure (net::ERR_FAILED)', () => {
    // Seen in Docker: fetch() from the page to the proxy's 403 fails CORS, so there is no status.
    const flags = blockedFlags(evidence([request('http://169.254.169.254/latest/meta-data/', { failure: 'net::ERR_FAILED' })], ['169.254.169.254']));
    expect(flags['169.254.169.254']).toBe(true);
  });

  it('matches the refused port: a failed request to another port of the host is not counted as blocked', () => {
    // The proxy refused api.example:80 (helper records port 80); this request went to :443.
    const flags = blockedFlags(evidence([request('https://api.example/', { failure: 'net::ERR_CONNECTION_RESET' })], ['api.example']));
    expect(flags['api.example']).toBe(false);
  });

  it('does not mark a 403 as blocked when the proxy did not block that host', () => {
    const flags = blockedFlags(evidence([request('http://cdn.example/x.js', { status: 403 })], []));
    expect(flags['cdn.example']).toBe(false);
  });

  it('does not mark a successful response as blocked even if the host was blocked on another port', () => {
    const flags = blockedFlags(evidence([request('https://api.example/', { status: 200 })], ['api.example']));
    expect(flags['api.example']).toBe(false);
  });
});
