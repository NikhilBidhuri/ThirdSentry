import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createBaseline } from '../../src/baseline/baseline-manager.js';
import { detectFromContent, detectFromUrl, detectLibraries, mergeDetections } from '../../src/analysis/libraries/detector.js';
import { findVulnerabilities } from '../../src/analysis/libraries/matcher.js';
import { checkPattern } from '../../src/analysis/libraries/safe-regex.js';
import { loadLibraryDb, parseVulnDb, vulnDbDir } from '../../src/analysis/libraries/vulndb.js';
import { compareVersions, inVulnerableRange, parseVersion } from '../../src/analysis/libraries/version.js';
import { analyzeResources } from '../../src/analysis/script-analysis.js';
import { ConfigSchema } from '../../src/config/schema.js';
import { analyzeScan } from '../../src/monitoring/analysis-runner.js';
import { compareSite } from '../../src/monitoring/comparison-engine.js';
import { buildFindings } from '../../src/monitoring/finding-engine.js';
import { buildLibraryFindings } from '../../src/monitoring/library-findings.js';
import type { DetectedLibrary } from '../../src/types/index.js';
import { page, scan, scriptResource, site } from '../fixtures/builders.js';
import { makeProject, tempDir } from '../helpers.js';

const LIBS = ConfigSchema.parse({ sites: [{ name: 'shop', url: 'https://shop.example' }] }).libraries;

const lib = (name: string, version: string, method: DetectedLibrary['method'] = 'banner'): DetectedLibrary => ({ name, version, method, confidence: 'high' });

describe('version parsing and ranges', () => {
  it('orders releases, pre-releases and short versions', () => {
    expect(compareVersions('1.9.0b1', '1.9.0')).toBe(-1);
    expect(compareVersions('3.0.0-beta1', '3.0.0')).toBe(-1);
    expect(compareVersions('3.0.0-alpha1', '3.0.0-beta1')).toBe(-1);
    expect(compareVersions('3.0.0-beta2', '3.0.0-beta10')).toBe(-1);
    expect(compareVersions('3.0.0-rc.1', '3.0.0-rc.2')).toBe(-1);
    expect(compareVersions('1.4', '1.4.0')).toBe(0);
    expect(compareVersions('1.10.0', '1.9.9')).toBe(1);
    expect(compareVersions('4.17.20', '4.17.21')).toBe(-1);
    expect(compareVersions('1.2.3.4', '1.2.3')).toBe(1);
    expect(compareVersions('nonsense', '1.0.0')).toBeUndefined();
    expect(parseVersion('1.2.3; drop table')).toBeUndefined();
  });

  it('applies atOrAbove (inclusive) and below (exclusive)', () => {
    const r = { atOrAbove: '1.12.3', below: '3.0.0-beta1' };
    expect(inVulnerableRange('1.12.4', r)).toBe(true);
    expect(inVulnerableRange('1.12.3', r)).toBe(true);
    expect(inVulnerableRange('1.12.2', r)).toBe(false);
    expect(inVulnerableRange('3.0.0-alpha5', r)).toBe(true);
    expect(inVulnerableRange('3.0.0-beta1', r)).toBe(false);
    expect(inVulnerableRange('3.0.0', r)).toBe(false);
    expect(inVulnerableRange('1.9.0b1', { below: '1.9.0b1' })).toBe(false);
    expect(inVulnerableRange('1.9.0b0', { below: '1.9.0b1' })).toBe(true);
    expect(inVulnerableRange('1.8.3', { below: '1.9.0b1' })).toBe(true);
    expect(inVulnerableRange('garbage', { below: '1.0.0' })).toBe(false);
    expect(inVulnerableRange('1.0.0', { below: 'garbage' })).toBe(false);
  });
});

describe('library detection', () => {
  it('reads license banners', () => {
    expect(detectFromContent('/*! jQuery v3.5.1 | (c) JS Foundation and other contributors | jquery.org/license */!function(e,t){}')).toContainEqual(lib('jquery', '3.5.1'));
    expect(detectFromContent('/*!\n * jQuery JavaScript Library v1.12.4\n * http://jquery.com/\n */')).toContainEqual(lib('jquery', '1.12.4'));
    expect(detectFromContent('/*! jQuery UI - v1.12.1 - 2016-09-14 */')).toContainEqual(lib('jquery-ui', '1.12.1'));
    expect(detectFromContent('/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n */')).toContainEqual(lib('bootstrap', '3.3.7'));
    expect(detectFromContent('/**\n * @license\n * Lodash <https://lodash.com/>\n */')).toEqual([]);
    expect(detectFromContent('/**\n * @license\n * lodash 4.17.20 <https://lodash.com/>\n */')).toContainEqual(lib('lodash', '4.17.20'));
    expect(detectFromContent('/*! @license DOMPurify 2.0.8 | (c) Cure53 and other contributors */')).toContainEqual(lib('dompurify', '2.0.8'));
  });

  it('reads well-known version assignments, gated by context', () => {
    expect(detectFromContent('var x={jquery:"3.5.1",a:1}')).toContainEqual({ name: 'jquery', version: '3.5.1', method: 'code', confidence: 'medium' });
    expect(detectFromContent("var VERSION = '1.12.4';")).toEqual([]);
    expect(detectFromContent("var VERSION = '4.17.20'; var HASH_UNDEFINED = '__lodash_hash_undefined__';")).toContainEqual({ name: 'lodash', version: '4.17.20', method: 'code', confidence: 'medium' });
    expect(detectFromContent('Handlebars.VERSION = "4.0.5";')).toContainEqual({ name: 'handlebars', version: '4.0.5', method: 'code', confidence: 'medium' });
  });

  it('detects a generic banner but ignores copyright lines', () => {
    expect(detectFromContent('/*! Chart.js v2.9.4 */').map((d) => `${d.name}@${d.version}`)).toEqual(['chart@2.9.4']);
    expect(detectFromContent('/* Copyright 2020 Acme. Version 1.2.3 */')).toEqual([]);
  });

  it('reads versions from URLs and CDN paths', () => {
    const names = (u: string): string[] => detectFromUrl(u).map((d) => `${d.name}@${d.version}:${d.method}:${d.confidence}`);
    expect(names('https://code.jquery.com/jquery-3.5.1.min.js')).toEqual(['jquery@3.5.1:url:medium']);
    expect(names('https://cdn.example.com/lodash@4.17.20/lodash.min.js')).toContain('lodash@4.17.20:url:medium');
    expect(names('https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.1/moment.min.js')).toContain('moment@2.29.1:url:medium');
    expect(names('https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/js/bootstrap.bundle.min.js')).toContain('bootstrap@4.6.0:url:medium');
    expect(names('https://unpkg.com/dompurify@2.3.0/dist/purify.min.js')).toContain('dompurify@2.3.0:url:medium');
    expect(names('https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js')).toContain('angularjs@1.8.2:url:medium');
    expect(names('https://cdn.example.com/jquery-ui-1.12.1.custom.min.js')).toEqual(['jquery-ui@1.12.1:url:medium']);
    expect(names('https://cdn.example.com/js/jquery/3.4.1/jquery.min.js').some((n) => n.startsWith('jquery@3.4.1'))).toBe(true);
    expect(names('https://shop.example/app-1.2.3.min.js')).toEqual([]);
    expect(names('https://shop.example/jquery.min.js')).toEqual([]);
    expect(names('data:text/javascript,jquery-3.5.1.js')).toEqual([]);
  });

  it('matches exact content hashes (configured SHA-256)', async () => {
    const body = 'console.log("my forked lib")';
    const { createHash } = await import('node:crypto');
    const sha256 = createHash('sha256').update(body).digest('hex');
    const found = detectLibraries({ body, knownHashes: [{ sha256, name: 'acme-widget', version: '2.1.0' }] });
    expect(found).toEqual([{ name: 'acme-widget', version: '2.1.0', method: 'content-hash', confidence: 'high' }]);
  });

  it('prefers content over a conflicting URL and keeps the strongest method', () => {
    const merged = detectLibraries({ url: 'https://cdn.example.com/jquery-3.5.1.min.js', body: '/*! jQuery v3.6.0 | x */' });
    expect(merged.map((d) => `${d.name}@${d.version}:${d.method}`)).toEqual(['jquery@3.6.0:banner']);
    const same = mergeDetections([lib('jquery', '3.5.1', 'url'), lib('jquery', '3.5.1', 'banner')]);
    expect(same).toHaveLength(1);
    expect(same[0]?.method).toBe('banner');
  });

  it('is deterministic and handles empty/binary input', () => {
    const body = '/*! jQuery v3.5.1 */';
    expect(detectLibraries({ body, url: 'https://x.test/jquery-3.5.1.js' })).toEqual(detectLibraries({ body, url: 'https://x.test/jquery-3.5.1.js' }));
    expect(detectLibraries({})).toEqual([]);
    expect(detectLibraries({ body: Buffer.from([0, 1, 2, 255, 254]) })).toEqual([]);
  });

  it('uses extractors from the (seed) database and stores libraries on the resource', async () => {
    const db = await loadLibraryDb(await tempDir('libdb-'));
    expect(db.info.source).toBe('bundled-seed');
    expect(db.info.skippedPatterns).toBe(0);
    expect(detectFromContent('/*! jQuery v3.3.1 | x */', db)).toContainEqual(lib('jquery', '3.3.1'));
    const r = scriptResource('https://cdn.vendor.example/jquery-3.5.1.min.js', '/*! jQuery v3.5.1 | (c) */');
    const cfg = ConfigSchema.parse({ sites: [{ name: 'shop', url: 'https://shop.example' }] });
    analyzeResources([r], new Map([[r.hashes.sha256 as string, Buffer.from('/*! jQuery v3.5.1 | (c) */')]]), cfg, db);
    expect(r.libraries).toEqual([lib('jquery', '3.5.1')]);
    const off = scriptResource('https://cdn.vendor.example/jquery-3.5.1.min.js', 'x');
    analyzeResources([off], new Map(), { ...cfg, libraries: { ...cfg.libraries, detect: false } });
    expect(off.libraries).toBeUndefined();
  });
});

describe('vulnerability matching with the bundled seed', () => {
  it('matches known advisories and the fixed-in version', async () => {
    const db = await loadLibraryDb(await tempDir('libdb-'));
    const [v] = findVulnerabilities([lib('jquery', '3.4.1')], db);
    expect(v?.advisories.map((a) => a.id).sort()).toEqual(['CVE-2020-11022', 'CVE-2020-11023']);
    expect(v?.fixedIn).toBe('3.5.0');
    expect(v?.highestSeverity).toBe('medium');
    expect(findVulnerabilities([lib('jquery', '3.5.1')], db)).toEqual([]);
    expect(findVulnerabilities([lib('jquery', '3.4.1')], db, 'high')).toEqual([]);
    const lodash = findVulnerabilities([lib('lodash', '4.17.20')], db)[0];
    expect(lodash?.advisories.map((a) => a.id)).toEqual(['CVE-2021-23337']);
    expect(lodash?.highestSeverity).toBe('high');
    expect(findVulnerabilities([lib('lodash', '4.17.21')], db)).toEqual([]);
    expect(findVulnerabilities([lib('jquery', '3.0.0-beta1')], db).flatMap((x) => x.advisories.map((a) => a.id))).not.toContain('CVE-2015-9251');
    expect(findVulnerabilities([lib('jquery', '3.0.0-alpha1')], db).flatMap((x) => x.advisories.map((a) => a.id))).toContain('CVE-2015-9251');
    expect(findVulnerabilities([lib('unknown-lib', '1.0.0')], db)).toEqual([]);
    // Display aliases fold into the same entry.
    expect(findVulnerabilities([lib('moment.js', '2.10.0')], db)[0]?.advisories.length).toBeGreaterThan(0);
  });
});

describe('database validation and regex safety', () => {
  const entry = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
    vulnerabilities: [{ below: '2.0.0', severity: 'high', identifiers: { CVE: ['CVE-2020-0001'], summary: 's' }, info: ['https://example.com/a', 'javascript:alert(1)'] }],
    extractors: { filecontent: ['/\\*! Foo v(§§version§§)'], ...extra },
  });

  it('accepts a valid database and drops non-https links', () => {
    const parsed = parseVulnDb({ foo: entry() });
    const a = parsed.libraries.get('foo')?.advisories[0];
    expect(a?.links).toEqual(['https://nvd.nist.gov/vuln/detail/CVE-2020-0001', 'https://example.com/a']);
  });

  it('rejects schema violations', () => {
    expect(() => parseVulnDb([])).toThrow();
    expect(() => parseVulnDb({ foo: { vulnerabilities: [{ below: '1.0', severity: 'catastrophic' }] } })).toThrow();
    expect(() => parseVulnDb({ foo: { vulnerabilities: 'x' } })).toThrow();
    expect(() => parseVulnDb({ foo: { extractors: { hashes: { nothex: '1.0' } } } })).toThrow();
    expect(() => parseVulnDb(JSON.parse('{"__proto__": {"vulnerabilities": []}}'))).toThrow();
    expect(() => parseVulnDb(Object.fromEntries(Array.from({ length: 2001 }, (_, i) => [`l${i}`, { vulnerabilities: [] }])))).toThrow(/libraries/);
  });

  it('skips advisories with unusable version ranges', () => {
    const parsed = parseVulnDb({ foo: { vulnerabilities: [{ below: 'banana', severity: 'low' }, { below: '1.0.0', severity: 'low' }] } });
    expect(parsed.skippedAdvisories).toBe(1);
    expect(parsed.advisoryCount).toBe(1);
  });

  it('rejects catastrophic-backtracking shapes', () => {
    for (const p of ['(a+)+$', '(a*)*b', '(a|aa)+c', '(.*a){2,}', '(\\w+\\s?)*$', '^(([a-z])+.)+[A-Z]([a-z])+$', '(a+){2,}', '((a+))+', 'a'.repeat(601), '(?:x+y)+', '(a|b)*\\1+', 'a{1,99999}']) {
      expect(checkPattern(p).ok, p).toBe(false);
    }
    expect(checkPattern('.*.*.*.*.*.*.*').ok).toBe(false);
    expect(checkPattern('(unterminated').ok).toBe(false);
  });

  it('accepts ordinary extractor shapes', () => {
    for (const p of ['/\\*!? jQuery v([0-9.]+)', 'jquery-([0-9.]+)(\\.min)?\\.js', '[^a-z.]jquery:[ ]?"([0-9.]+)"', '=\\"(1)\\",.{50,300}(.)\\.fn=(\\2)\\.prototype', '(?:Lo-Dash|lodash) v?([0-9.]+) <', 'a{1,3}(b|c)?']) {
      expect(checkPattern(p), p).toEqual({ ok: true });
    }
  });

  it('skips hostile patterns from a database and stays fast on adversarial input', () => {
    const parsed = parseVulnDb({ evil: { vulnerabilities: [], extractors: { filecontent: ['(a+)+$', '(§§version§§)x(a|aa)+y', 'evil v(§§version§§)'] } } });
    expect(parsed.skippedPatterns).toBe(2);
    expect(parsed.libraries.get('evil')?.filecontent).toHaveLength(1);
    const db = { libraries: parsed.libraries, info: { source: 'cache' as const, libraries: 1, advisories: 0, skippedPatterns: 2, skippedAdvisories: 0, stale: false, warnings: [] } };
    const t = Date.now();
    detectFromContent(`${'a'.repeat(5_000)}!${'evil v1'.repeat(1000)}`, db);
    expect(Date.now() - t).toBeLessThan(1500);
  });

  it('falls back to the seed for a corrupted, edited or stale cache', async () => {
    const cache = await tempDir('libdb-');
    const dir = vulnDbDir(cache);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'jsrepository.json'), JSON.stringify({ foo: entry() }));
    const sha = (await import('node:crypto')).createHash('sha256').update(JSON.stringify({ foo: entry() })).digest('hex');
    const meta = { sourceUrl: 'https://example.test/db.json', fetchedAt: '2026-01-01T00:00:00.000Z', sha256: sha, bytes: 1, libraries: 1, advisories: 1 };
    await writeFile(join(dir, 'meta.json'), JSON.stringify(meta));
    const ok = await loadLibraryDb(cache, { now: new Date('2026-01-11T00:00:00.000Z'), maxAgeDays: 30 });
    expect(ok.info).toMatchObject({ source: 'cache', ageDays: 10, stale: false, sourceUrl: 'https://example.test/db.json' });
    const stale = await loadLibraryDb(cache, { now: new Date('2026-03-01T00:00:00.000Z'), maxAgeDays: 30 });
    expect(stale.info.stale).toBe(true);
    expect(stale.info.warnings.join(' ')).toMatch(/59 days old/);
    await writeFile(join(dir, 'meta.json'), JSON.stringify({ ...meta, sha256: '0'.repeat(64) }));
    const tampered = await loadLibraryDb(cache);
    expect(tampered.info.source).toBe('bundled-seed');
    expect(tampered.info.warnings.join(' ')).toMatch(/SHA-256/);
    await writeFile(join(dir, 'meta.json'), JSON.stringify(meta));
    await writeFile(join(dir, 'jsrepository.json'), '{not json');
    expect((await loadLibraryDb(cache)).info.source).toBe('bundled-seed');
  });
});

describe('vulnerable-library findings', () => {
  const jq = (version: string, extra: Partial<DetectedLibrary> = {}): DetectedLibrary[] => [{ name: 'jquery', version, method: 'banner', confidence: 'high', ...extra }];

  async function ctx(): Promise<{ db: Awaited<ReturnType<typeof loadLibraryDb>>; libraries: typeof LIBS }> {
    return { db: await loadLibraryDb(await tempDir('libdb-')), libraries: LIBS };
  }

  it('builds an explainable finding with upgrade path and links', async () => {
    const r = scriptResource('https://cdn.vendor.example/jquery.js', '/*! jQuery v3.4.1 */', { libraries: jq('3.4.1'), pages: ['/'] });
    const s = site([r]);
    const [f] = buildLibraryFindings(s, await ctx());
    expect(f).toBeDefined();
    expect(f?.kind).toBe('vulnerable-library');
    expect(f?.severity).toBe('medium');
    expect(f?.confidence).toBe('high');
    expect(f?.title).toContain('jQuery 3.4.1');
    expect(f?.recommendedAction).toContain('3.5.0');
    expect(f?.evidence.some((e) => e.label.startsWith('CVE-2020-11022'))).toBe(true);
    expect(f?.evidence.find((e) => e.label === 'References')?.value).toContain('https://nvd.nist.gov/vuln/detail/CVE-2020-11023');
    expect(f?.signals.length).toBeGreaterThan(0);
  });

  it('raises severity one level on sensitive pages and takes confidence from the detection method', async () => {
    const r = scriptResource('https://cdn.vendor.example/jquery-3.4.1.js', 'x', { libraries: jq('3.4.1', { method: 'url', confidence: 'medium' }), pages: ['/checkout'] });
    const s = site([r], { pages: [page('/checkout', { sensitive: true })] });
    const [f] = buildLibraryFindings(s, await ctx());
    expect(f?.severity).toBe('high');
    expect(f?.confidence).toBe('medium');
    expect(f?.category).toBe('high-priority');
    expect(f?.title).toContain('sensitive page');
    expect(f?.signals.some((x) => x.id === 'sensitive-page')).toBe(true);
  });

  it('has stable IDs: same inputs, same ID; different version or advisory set, different ID', async () => {
    const c = await ctx();
    const mk = (v: string): string | undefined => buildLibraryFindings(site([scriptResource('https://cdn.vendor.example/j.js', 'x', { libraries: jq(v) })]), c)[0]?.id;
    expect(mk('3.4.1')).toBe(mk('3.4.1'));
    expect(mk('3.4.1')).toMatch(/^TS-[0-9a-f]{12}$/);
    expect(mk('3.4.1')).not.toBe(mk('3.3.1'));
    // Same site/resource/library/version, but the database learns a new advisory: the ID changes (alerts again).
    const extra = parseVulnDb({ jquery: { vulnerabilities: [{ below: '3.5.0', severity: 'medium', identifiers: { CVE: ['CVE-2020-11022'] } }, { below: '3.6.0', severity: 'low', identifiers: { CVE: ['CVE-2099-0001'] } }] } });
    const db2 = { libraries: extra.libraries, info: { ...c.db.info } };
    const one = buildLibraryFindings(site([scriptResource('https://cdn.vendor.example/j.js', 'x', { libraries: jq('3.4.1') })]), { ...c, db: db2 })[0]?.id;
    expect(one).not.toBe(mk('3.4.1'));
    // The same code content on another page does not change the ID.
    const other = buildLibraryFindings(site([scriptResource('https://cdn.vendor.example/j.js', 'x', { libraries: jq('3.4.1'), pages: ['/other'] })]), c)[0]?.id;
    expect(other).toBe(mk('3.4.1'));
  });

  it('respects minSeverity, vulnerabilities:false and detect:false', async () => {
    const c = await ctx();
    const s = site([scriptResource('https://cdn.vendor.example/j.js', 'x', { libraries: jq('3.4.1') })]);
    expect(buildLibraryFindings(s, { ...c, libraries: { ...LIBS, minSeverity: 'high' } })).toEqual([]);
    expect(buildLibraryFindings(s, { ...c, libraries: { ...LIBS, vulnerabilities: false } })).toEqual([]);
    expect(buildLibraryFindings(s, { ...c, libraries: { ...LIBS, detect: false } })).toEqual([]);
  });

  it('flows through analyzeScan with suppressions and a report section', async () => {
    const project = await makeProject(80);
    try {
      const r = scriptResource('https://cdn.vendor.example/jquery.js', '/*! jQuery v3.4.1 */', { libraries: jq('3.4.1') });
      const sc = scan([site([r])]);
      const { report } = await analyzeScan(project.resolved, sc, { scanPath: 'x' });
      const f = report.findings.find((x) => x.kind === 'vulnerable-library');
      expect(f).toBeDefined();
      expect(report.libraries?.inventory).toMatchObject([{ name: 'jquery', version: '3.4.1', advisories: ['CVE-2020-11022', 'CVE-2020-11023'] }]);
      expect(report.libraries?.db.source).toBe('bundled-seed');
      const resolved = { ...project.resolved, config: { ...project.resolved.config, suppressions: [{ kind: 'vulnerable-library', reason: 'accepted until migration' }] } };
      const suppressed = (await analyzeScan(resolved, sc, { scanPath: 'x' })).report.findings.find((x) => x.kind === 'vulnerable-library');
      expect(suppressed?.suppressed?.reason).toBe('accepted until migration');
    } finally {
      await project.cleanup();
    }
  });

  it('explains library version changes in resource-modified findings', () => {
    const before = scriptResource('https://cdn.vendor.example/jquery.js', '/*! jQuery v3.5.1 */', { libraries: jq('3.5.1') });
    const after = scriptResource('https://cdn.vendor.example/jquery.js', '/*! jQuery v3.7.1 */ more', { libraries: jq('3.7.1') });
    const base = createBaseline(site([before]), { scanId: 's1' });
    expect(base.resources[0]?.libraries).toEqual([{ name: 'jquery', version: '3.5.1' }]);
    const s = site([after]);
    const [f] = buildFindings(compareSite(s, base).changes, { site: s });
    expect(f?.kind).toBe('resource-modified');
    expect(f?.title).toContain('jQuery 3.5.1 → 3.7.1');
    expect(f?.reason).toContain('jQuery 3.5.1 → 3.7.1');
    expect(f?.evidence).toContainEqual({ label: 'Library version', value: 'jQuery 3.5.1 → 3.7.1' });
    // Without library data the finding is unchanged.
    const plain = scriptResource('https://cdn.vendor.example/jquery.js', 'changed');
    const s2 = site([plain]);
    const [g] = buildFindings(compareSite(s2, base).changes, { site: s2 });
    expect(g?.title).not.toContain('→');
  });
});
