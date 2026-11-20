import { describe, expect, it } from 'vitest';
import { analyzeJavaScript } from '../../src/analysis/ast-analyzer.js';
import { normalizeJavaScript } from '../../src/analysis/normalizer.js';
import { diffScripts } from '../../src/analysis/structural-diff.js';
import { createBaseline } from '../../src/baseline/baseline-manager.js';
import { ConfigSchema, DEFAULT_IGNORE_QUERY_PARAMS } from '../../src/config/schema.js';
import { compareSite } from '../../src/monitoring/comparison-engine.js';
import { buildFindings } from '../../src/monitoring/finding-engine.js';
import { destination, inlineResource, page, scriptResource, site } from '../fixtures/builders.js';

const GTM = 'https://www.vendor-tags.example/gtm.js?id=GTM-1';
const kinds = (changes: ReadonlyArray<{ kind: string }>): string[] => changes.map((c) => c.kind).sort();
const baselineOf = (resources: Parameters<typeof site>[0], opts: Parameters<typeof site>[1] = {}) =>
  createBaseline(site(resources, opts), { scanId: 'base', now: new Date('2026-01-01T00:00:00Z') });
const findingsFor = (current: ReturnType<typeof site>, base: ReturnType<typeof baselineOf>) => buildFindings(compareSite(current, base).changes, { site: current });

describe('HTML-like comments (parser/browser desync)', () => {
  const hidden = 'a <!--b /*\neval(p); document.querySelector("#cvv");\n// */';
  it('analyses a classic script the way the browser runs it', () => {
    const r = analyzeJavaScript(hidden, { goal: 'script' });
    expect(r.counts['TS-EVAL']).toBe(1);
    expect(r.counts['TS-SENSITIVE-FIELD-ACCESS']).toBe(1);
    expect(analyzeJavaScript(hidden).counts['TS-EVAL']).toBe(1); // unknown goal: classic script first
  });
  it('does not equate two scripts that differ only inside the payload line', () => {
    const a = normalizeJavaScript('a <!--b /*\nstepOne()\n// */', { goal: 'script' });
    const b = normalizeJavaScript('a <!--b /*\nstealCards()\n// */', { goal: 'script' });
    expect(a.normalizedSha256).not.toBe(b.normalizedSha256);
    const d = diffScripts('a <!--b /*\nstepOne()\n// */', 'a <!--b /*\nstealCards()\n// */', { resourceType: 'script' });
    expect(JSON.stringify(d)).toContain('stealCards');
  });
  it('still treats `<!--` as an operator sequence in modules (negative)', () => {
    const r = analyzeJavaScript('export const x = 1; if (a <!--b) { eval(p) }', { goal: 'module' });
    expect(r.counts['TS-EVAL']).toBe(1);
  });
  it('keeps real formatting-only changes classified as formatting-only', () => {
    const base = baselineOf([scriptResource(GTM, 'function f(a){return a+1}')]);
    expect(kinds(compareSite(site([scriptResource(GTM, 'function f(a) {\n  return a + 1; // c\n}')]), base).changes)).toEqual(['resource-formatting-changed']);
  });
});

describe('truncated content', () => {
  const truncated = (content: string) => scriptResource(GTM, content, { content: { status: 'truncated' } });
  it('never counts a truncated body as an unchanged match, even when the prefix hash is approved', () => {
    const base = baselineOf([scriptResource(GTM, 'gtm()')]);
    const result = compareSite(site([truncated('gtm()')]), base);
    expect(kinds(result.changes)).toEqual(['content-unavailable']);
    expect(result.unchanged).toBe(0);
  });
  it('treats a captured identical body as unchanged (negative)', () => {
    const base = baselineOf([scriptResource(GTM, 'gtm()')]);
    expect(compareSite(site([scriptResource(GTM, 'gtm()')]), base).changes).toEqual([]);
  });
  it('does not accept truncated inline content at another position', () => {
    const base = baselineOf([inlineResource('/', 'html>head>script:nth-of-type(1)', 'var a=1')]);
    const cur = inlineResource('/', 'html>head>script:nth-of-type(2)', 'var a=1', { content: { status: 'truncated' } });
    expect(kinds(compareSite(site([cur]), base).changes)).not.toEqual([]);
  });
});

describe('analysis unavailable', () => {
  const analysed = { analyzed: true, counts: {}, matches: [], hosts: [] };
  const failed = { analyzed: false, error: 'parse error: x', counts: {}, matches: [], hosts: [] };
  const signalIds = (f: { signals: ReadonlyArray<{ id: string }> } | undefined): string[] => f?.signals.map((s) => s.id) ?? [];
  it('adds a heavier signal when the approved version was analysed', () => {
    const base = baselineOf([scriptResource(GTM, 'gtm(1)', { indicators: analysed })]);
    const f = findingsFor(site([scriptResource(GTM, 'gtm(2', { indicators: failed })]), base).find((x) => x.kind === 'resource-modified');
    expect(signalIds(f)).toContain('analysis-regression');
  });
  it('adds the plain signal for a new unanalysable script and none when analysis worked (negative)', () => {
    const base = baselineOf([]);
    const added = findingsFor(site([scriptResource(GTM, 'gtm(2', { indicators: failed })]), base).find((x) => x.kind === 'resource-added');
    expect(signalIds(added)).toContain('analysis-unavailable');
    const ok = findingsFor(site([scriptResource(GTM, 'gtm(2)', { indicators: analysed })]), base).find((x) => x.kind === 'resource-added');
    expect(signalIds(ok)).not.toContain('analysis-unavailable');
    expect(signalIds(ok)).not.toContain('analysis-regression');
  });
});

describe('coverage loss', () => {
  const failedPage = (key: string, sensitive = false) => page(key, { status: 'failed', sensitive, issues: [{ level: 'error', code: 'navigation-failed', message: 'boom' }] });
  const base = baselineOf([scriptResource(GTM, 'gtm()')]);
  it('reports failed and partial pages with stable IDs and higher severity on sensitive pages', () => {
    const cur = site([], { pages: [failedPage('/')] });
    const f1 = findingsFor(cur, base).filter((f) => f.kind === 'page-failed');
    const f2 = findingsFor(cur, base).filter((f) => f.kind === 'page-failed');
    expect(f1).toHaveLength(1);
    expect(f1[0]?.id).toBe(f2[0]?.id);
    const sens = findingsFor(site([], { pages: [failedPage('/', true)] }), base).find((f) => f.kind === 'page-failed');
    expect(sens?.score ?? 0).toBeGreaterThan(f1[0]?.score ?? 0);
    const partial = findingsFor(site([], { pages: [page('/', { status: 'partial', issues: [{ level: 'error', code: 'scan-time-limit', message: 't' }] })] }), base);
    expect(partial.map((f) => f.kind)).toContain('coverage-degraded');
  });
  it('changes the ID when the failure escalates or the reason changes', () => {
    const partial = findingsFor(site([], { pages: [page('/', { status: 'partial', issues: [{ level: 'error', code: 'navigation-timeout', message: 't' }] })] }), base).find((f) => f.kind === 'coverage-degraded');
    const failed = findingsFor(site([], { pages: [failedPage('/')] }), base).find((f) => f.kind === 'page-failed');
    expect(partial?.id).toBeDefined();
    expect(partial?.id).not.toBe(failed?.id);
  });
  it('reports baseline pages that were not scanned, and nothing for a clean scan (negative)', () => {
    const b2 = baselineOf([], { pages: [page('/'), page('/checkout')] });
    expect(compareSite(site([], { pages: [page('/')] }), b2).changes.map((c) => `${c.kind}:${c.pages.join()}`)).toEqual(['coverage-degraded:/checkout']);
    expect(compareSite(site([], { pages: [page('/'), page('/checkout')] }), b2).changes).toEqual([]);
  });
});

describe('finding IDs include the host', () => {
  const deny = { allow: [], deny: ['evil.test'], suspicious: [] } as never;
  it('separates hosts under one domain', () => {
    const mk = (host: string) => {
      const cur = site([], { destinations: [destination(host)] });
      return compareSite(cur, baselineOf([]), deny).changes.filter((c) => c.kind === 'denylisted-domain').map((c) => buildFindings([c], { site: cur })[0]?.id);
    };
    expect(mk('a.evil.test')[0]).toBeDefined();
    expect(mk('a.evil.test')[0]).not.toBe(mk('b.evil.test')[0]);
    expect(mk('a.evil.test')[0]).toBe(mk('a.evil.test')[0]);
  });
  it('keeps new-outbound-domain per domain (negative)', () => {
    const idFor = (host: string) => {
      const cur = site([], { destinations: [destination(host)] });
      return buildFindings(compareSite(cur, baselineOf([])).changes.filter((c) => c.kind === 'new-outbound-domain'), { site: cur })[0]?.id;
    };
    expect(idFor('a.evil.test')).toBeDefined();
    expect(idFor('a.evil.test')).toBe(idFor('b.evil.test'));
  });
});

describe('position-independent inline pairing', () => {
  const pos = (n: number) => `html>head>script:nth-of-type(${n})`;
  const body = (n: number) => `var cfg${n} = { id: ${n}, name: "thing-${n}" };`;
  it('does not flag approved scripts shifted by an injected script, and pairs an edited one as modified', () => {
    const base = baselineOf([inlineResource('/', pos(1), body(1)), inlineResource('/', pos(2), body(2))]);
    const injected = inlineResource('/', pos(1), 'window.__x = 1;');
    const cur = site([injected, inlineResource('/', pos(2), body(1)), inlineResource('/', pos(3), body(2) + 'steal();')]);
    const changes = compareSite(cur, base).changes;
    expect(kinds(changes)).toEqual(['resource-added', 'resource-modified']);
    expect(changes.find((c) => c.kind === 'resource-modified')?.current?.identity).toContain('nth-of-type(3)');
  });
  it('reports an unrelated replacement as added plus removed (negative)', () => {
    const base = baselineOf([inlineResource('/', pos(1), body(1))]);
    const result = compareSite(site([inlineResource('/', pos(2), 'y;'.repeat(5000))]), base);
    expect(kinds(result.changes)).toContain('resource-added');
    expect(kinds(result.changes)).toContain('resource-removed');
  });
  it('does not pair across pages (negative)', () => {
    const pages = [page('/a'), page('/b')];
    const base = baselineOf([inlineResource('/a', pos(1), body(1))], { pages });
    const cur = site([inlineResource('/b', pos(1), body(1) + 'evil();')], { pages });
    expect(kinds(compareSite(cur, base).changes)).toEqual(['resource-added', 'resource-removed']);
  });
});

describe('cache-buster query parameters', () => {
  it('ships a default ignore list that can be overridden', () => {
    expect(DEFAULT_IGNORE_QUERY_PARAMS).toEqual(expect.arrayContaining(['cb', '_', 't', 'ts', 'timestamp', 'nocache']));
    const parse = (extra: object) => ConfigSchema.parse({ sites: [{ name: 's', url: 'https://shop.example', ...extra }] }).sites[0]?.ignoreQueryParams;
    expect(parse({})).toEqual([...DEFAULT_IGNORE_QUERY_PARAMS]);
    expect(parse({ ignoreQueryParams: [] })).toEqual([]);
    expect(parse({ ignoreQueryParams: ['v'] })).toEqual(['v']);
  });
});

describe('formatting-only with source reflection', () => {
  const reflective = 'function f(){return 1}; var s = f.toString();';
  it('lowers confidence and adds a signal when the script reflects on its own source', () => {
    const cur = scriptResource(GTM, reflective + ' // note', { indicators: analyzeJavaScript(reflective) });
    const base = baselineOf([scriptResource(GTM, reflective)]);
    const f = findingsFor(site([cur]), base)[0];
    expect(f?.kind).toBe('resource-formatting-changed');
    expect(f?.confidence).toBe('medium');
    expect(f?.signals.map((s) => s.id)).toContain('formatting-with-reflection');
  });
  it('keeps plain comment-only changes at high confidence (negative)', () => {
    const base = baselineOf([scriptResource(GTM, 'var a=1;')]);
    const f = findingsFor(site([scriptResource(GTM, 'var a=1; // c', { indicators: analyzeJavaScript('var a=1;') })]), base)[0];
    expect(f?.confidence).toBe('high');
    expect(f?.signals.map((s) => s.id)).not.toContain('formatting-with-reflection');
  });
});
