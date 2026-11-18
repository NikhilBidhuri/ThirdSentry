import { describe, expect, it } from 'vitest';
import { createBaseline } from '../../src/baseline/baseline-manager.js';
import { compareSite } from '../../src/monitoring/comparison-engine.js';
import { buildFindings } from '../../src/monitoring/finding-engine.js';
import { destination, inlineResource, page, scriptResource, site } from '../fixtures/builders.js';

const GTM = 'https://www.vendor-tags.example/gtm.js?id=GTM-1';
const PAY = 'https://js.payments.example/v3/';

function baselineOf(resources: Parameters<typeof site>[0], opts: Parameters<typeof site>[1] = {}) {
  return createBaseline(site(resources, opts), { scanId: 'base', now: new Date('2026-01-01T00:00:00Z') });
}

const kinds = (changes: ReadonlyArray<{ kind: string }>): string[] => changes.map((c) => c.kind).sort();

describe('comparison engine', () => {
  it('reports nothing when everything matches the baseline', () => {
    const resources = [scriptResource(GTM, 'gtm()'), inlineResource('/', 'html>head>script', 'var a=1')];
    const result = compareSite(site(resources), baselineOf(resources));
    expect(result.changes).toEqual([]);
    expect(result.unchanged).toBe(2);
  });

  it('detects modified resources and does not auto-approve them', () => {
    const base = baselineOf([scriptResource(GTM, 'gtm(1)')]);
    const result = compareSite(site([scriptResource(GTM, 'gtm(2); exfil()')]), base);
    expect(kinds(result.changes)).toEqual(['resource-modified']);
    expect(base.resources[0]?.approvedHashes).toHaveLength(1);
  });

  it('classifies formatting-only changes', () => {
    const base = baselineOf([scriptResource(GTM, 'function f(a){return a+1}')]);
    const result = compareSite(site([scriptResource(GTM, '/* v2 */\nfunction f(a) {\n  return a + 1;\n}\n')]), base);
    expect(kinds(result.changes)).toEqual(['resource-formatting-changed']);
  });

  it('detects added and removed resources and new script domains', () => {
    const base = baselineOf([scriptResource(GTM, 'gtm()'), scriptResource('https://cdn.old-vendor.example/a.js', 'a()')]);
    const result = compareSite(site([scriptResource(GTM, 'gtm()'), scriptResource('https://evil-cdn.example/x.js', 'x()')]), base);
    expect(kinds(result.changes)).toEqual(['new-outbound-domain', 'new-script-domain', 'resource-added', 'resource-removed']);
  });

  it('does not report removals for pages that were not scanned completely', () => {
    const base = baselineOf([scriptResource(GTM, 'gtm()')]);
    const partial = site([], { pages: [page('/', { status: 'partial' })] });
    const result = compareSite(partial, base);
    expect(result.changes.filter((c) => c.kind === 'resource-removed')).toEqual([]);
    expect(result.pagesNotCompared).toEqual(['/']);
  });

  it('detects redirect destination changes for the same requested URL', () => {
    const approved = scriptResource('https://cdn.vendor.example/latest.js', 'v1', { finalUrl: 'https://cdn.vendor.example/v1.js' });
    const current = scriptResource('https://cdn.vendor.example/latest.js', 'v1', { finalUrl: 'https://cdn.attacker.example/v1.js' });
    const result = compareSite(site([current]), baselineOf([approved]));
    const redirect = result.changes.find((c) => c.kind === 'redirect-changed');
    expect(redirect?.details.crossHost).toBe('true');
  });

  it('reports approved code served from a new domain as moved', () => {
    const base = baselineOf([scriptResource('https://cdn-a.example/lib.js', 'lib()')]);
    const result = compareSite(site([scriptResource('https://cdn-b.example/lib.js', 'lib()')]), base);
    expect(result.changes.map((c) => c.kind)).toContain('resource-moved');
    expect(result.changes.map((c) => c.kind)).not.toContain('resource-removed');
  });

  it('matches inline scripts by position and by content', () => {
    const base = baselineOf([inlineResource('/', 'html>head>script:nth-of-type(1)', 'var cfg = 1')]);
    // Same content at a different DOM position: not a change.
    expect(compareSite(site([inlineResource('/', 'html>head>script:nth-of-type(2)', 'var cfg = 1')]), base).changes).toEqual([]);
    // Same position, different content: modified.
    const modified = compareSite(site([inlineResource('/', 'html>head>script:nth-of-type(1)', 'var cfg = 2; steal()')]), base);
    expect(kinds(modified.changes)).toEqual(['resource-modified']);
  });

  it('flags SRI mismatches regardless of baseline', () => {
    const r = scriptResource(GTM, 'gtm()', { sri: { attribute: 'sha384-abc', valid: false } });
    expect(kinds(compareSite(site([r]), baselineOf([scriptResource(GTM, 'gtm()')])).changes)).toEqual(['sri-mismatch']);
  });

  it('flags content that can no longer be captured', () => {
    const now = scriptResource(GTM, 'x', { hashes: { sha256: null, sri: null, normalizedSha256: null, normalizerVersion: null }, content: { status: 'too-large' } });
    expect(kinds(compareSite(site([now]), baselineOf([scriptResource(GTM, 'gtm()')])).changes)).toEqual(['content-unavailable']);
  });

  it('detects new outbound domains and hosts', () => {
    const resources = [scriptResource(GTM, 'gtm()')];
    const base = baselineOf(resources);
    const current = site(resources, {
      destinations: [destination('www.vendor-tags.example'), destination('collect.vendor-tags.example'), destination('data.exfil.example', { methods: ['POST'] })],
    });
    expect(kinds(compareSite(current, base).changes)).toEqual(['new-outbound-domain', 'new-outbound-host']);
  });

  it('detects iframe origin changes', () => {
    const base = baselineOf([], { iframes: ['https://pay.example'] });
    const result = compareSite(site([], { iframes: ['https://fake-pay.example'] }), base);
    expect(kinds(result.changes)).toEqual(['iframe-origin-added', 'iframe-origin-removed']);
  });

  it('flags unexpected resource types', () => {
    const base = baselineOf([]);
    const wasm = scriptResource('https://shop.example/m.wasm', 'x', { type: 'wasm' });
    const added = compareSite(site([wasm]), base).changes.find((c) => c.kind === 'resource-added');
    expect(added?.details.unexpectedType).toBe('wasm');
  });

  it('accepts any approved variant', () => {
    const base = baselineOf([scriptResource(GTM, 'variant-a'), scriptResource(GTM, 'variant-b')]);
    expect(base.resources[0]?.approvedHashes).toHaveLength(2);
    expect(compareSite(site([scriptResource(GTM, 'variant-b')]), base).changes).toEqual([]);
  });
});

describe('findings and risk scoring', () => {
  it('rates a changed payment-page script that now talks to a new domain as high priority, without calling it malware', () => {
    const base = baselineOf([scriptResource(PAY, 'pay(1)', { pages: ['/checkout'] })], { pages: [page('/checkout', { sensitive: true })] });
    const current = site([scriptResource(PAY, 'pay(2)', { pages: ['/checkout'] })], {
      pages: [page('/checkout', { sensitive: true })],
      destinations: [destination('js.payments.example', { pages: ['/checkout'] }), destination('cdn-metrics.exfil.example', { pages: ['/checkout'], methods: ['POST'] })],
    });
    const findings = buildFindings(compareSite(current, base).changes, { site: current });
    const modified = findings.find((f) => f.kind === 'resource-modified');
    expect(modified?.severity).toBe('high');
    expect(modified?.category).toBe('high-priority');
    expect(modified?.signals.map((s) => s.id)).toEqual(expect.arrayContaining(['hash-changed-third-party', 'sensitive-page', 'correlated-new-destination']));
    expect(modified?.previousHash).toMatch(/^[0-9a-f]{64}$/);
    expect(modified?.currentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(`${modified?.title ?? ''} ${modified?.reason ?? ''}`.toLowerCase()).not.toMatch(/malware|malicious script detected/);
    const outbound = findings.find((f) => f.kind === 'new-outbound-domain');
    expect(outbound?.signals.map((s) => s.id)).toContain('data-sending-request');
  });

  it('keeps a plain hash change on a normal page at review level', () => {
    const base = baselineOf([scriptResource(GTM, 'gtm(1)')]);
    const findings = buildFindings(compareSite(site([scriptResource(GTM, 'gtm(2)')]), base).changes, { site: site([]) });
    expect(findings[0]?.category).toBe('review');
    expect(['low', 'medium']).toContain(findings[0]?.severity);
  });

  it('treats formatting-only changes as informational', () => {
    const base = baselineOf([scriptResource(GTM, 'a(1)')]);
    const findings = buildFindings(compareSite(site([scriptResource(GTM, 'a( 1 )\n')]), base).changes, { site: site([]) });
    expect(findings[0]?.severity).toBe('info');
    expect(findings[0]?.category).toBe('informational');
  });

  it('produces stable finding IDs for the same change', () => {
    const base = baselineOf([scriptResource(GTM, 'gtm(1)')]);
    const s = site([scriptResource(GTM, 'gtm(2)')]);
    const a = buildFindings(compareSite(s, base).changes, { site: s, now: new Date('2026-01-01') });
    const b = buildFindings(compareSite(s, base).changes, { site: s, now: new Date('2026-02-01') });
    expect(a[0]?.id).toBe(b[0]?.id);
    const c = buildFindings(compareSite(site([scriptResource(GTM, 'gtm(3)')]), base).changes, { site: s });
    expect(c[0]?.id).not.toBe(a[0]?.id);
  });

  it('honours configurable thresholds and weights', () => {
    const base = baselineOf([scriptResource(GTM, 'gtm(1)')]);
    const s = site([scriptResource(GTM, 'gtm(2)')]);
    const findings = buildFindings(compareSite(s, base).changes, {
      site: s,
      risk: { thresholds: { low: 5, medium: 10, high: 20, critical: 90 }, weights: { 'hash-changed-third-party': 30 } },
    });
    expect(findings[0]?.score).toBe(30);
    expect(findings[0]?.severity).toBe('high');
  });
});
