import { describe, expect, it } from 'vitest';
import { createBaseline } from '../../src/baseline/baseline-manager.js';
import { buildInventory, checkFailures, editInventoryText, matchInventoryEntry, parseInventory } from '../../src/pci/inventory.js';
import { toCsv, toMarkdown, toTable, formatInventory } from '../../src/pci/inventory-export.js';
import { inventoryFindings } from '../../src/pci/inventory-findings.js';
import { page, scriptResource, site } from '../fixtures/builders.js';

const NOW = new Date('2026-06-01T00:00:00Z');
const complete = { purpose: 'Card payments', owner: 'payments', authorizedBy: 'ciso', authorizedAt: '2026-01-10', reviewBy: '2027-01-10' };

function scene(extra: Record<string, unknown> = {}) {
  const pay = scriptResource('https://js.vendor.test/v3/pay.js', 'pay();', { pages: ['/checkout'] });
  const tag = scriptResource('https://tags.vendor.test/t.js', 'tag();', { pages: ['/checkout'] });
  const home = scriptResource('https://cdn.vendor.test/home.js', 'home();', { pages: ['/'] });
  const s = site([pay, tag, home], { pages: [page('/checkout', { sensitive: true }), page('/')], ...extra });
  return { s, pay, tag, home };
}

describe('inventory matching', () => {
  it('matches by identity and by URL pattern, so metadata survives version changes', () => {
    const v1 = scriptResource('https://js.vendor.test/v3/pay.js', 'a();');
    const v2 = scriptResource('https://js.vendor.test/v4/pay.js', 'b();');
    const entries = parseInventory(`scripts:\n  - url: "https://js.vendor.test/*/pay.js"\n    purpose: x\n  - identity: "${v1.identity}"\n    purpose: exact\n`, 't').scripts;
    expect(matchInventoryEntry(entries, v1)?.purpose).toBe('exact'); // exact identity beats pattern
    expect(matchInventoryEntry(entries, v2)?.purpose).toBe('x');
    expect(matchInventoryEntry(entries, scriptResource('https://other.test/pay.js', 'c();'))).toBeUndefined();
  });

  it('prefers the longer wildcard pattern', () => {
    const r = scriptResource('https://js.vendor.test/v3/pay.js', 'a();');
    const entries = parseInventory('scripts:\n  - url: "https://js.vendor.test/*"\n    purpose: broad\n  - url: "https://js.vendor.test/v3/*"\n    purpose: narrow\n', 't').scripts;
    expect(matchInventoryEntry(entries, r)?.purpose).toBe('narrow');
  });

  it('rejects invalid files with a clear error', () => {
    expect(() => parseInventory('scripts:\n  - purpose: no match key\n', 'f')).toThrow(/identity.*url|needs/);
    expect(() => parseInventory('scripts:\n  - url: a\n    authorizedAt: tomorrow\n', 'f')).toThrow(/date/);
    expect(() => parseInventory('scripts:\n  - url: a\n    bogus: 1\n', 'f')).toThrow();
  });
});

describe('inventory status', () => {
  it('computes authorized / missing-justification / review-overdue / not-approved', () => {
    const { s, pay, tag } = scene();
    const baseline = createBaseline(s, { scanId: 's' });
    const entries = parseInventory(
      `scripts:\n  - url: "${pay.finalUrl}"\n    purpose: ${complete.purpose}\n    owner: payments\n    authorizedBy: ciso\n    authorizedAt: 2026-01-10\n    reviewBy: 2027-01-10\n` +
        `  - url: "${tag.finalUrl}"\n    purpose: tags\n    owner: marketing\n    authorizedBy: cmo\n    authorizedAt: 2025-01-10\n    reviewBy: 2026-01-10\n`,
      't',
    ).scripts;
    const { rows } = buildInventory({ site: s, baseline, entries, now: NOW });
    const by = (u: string): string => rows.find((r) => r.url === u)?.status ?? '';
    expect(by(pay.finalUrl as string)).toBe('authorized');
    expect(by(tag.finalUrl as string)).toBe('review-overdue');
    expect(by('https://cdn.vendor.test/home.js')).toBe('missing-justification');
    expect(rows.find((r) => r.url === pay.finalUrl)?.sensitive).toBe(true);
    expect(rows.find((r) => r.url === pay.finalUrl)?.approvedSha256).toBe(pay.hashes.sha256);

    // Not approved: content changed since the baseline, or no baseline at all.
    const changed = scene().s;
    const modified = { ...changed, resources: changed.resources.map((r) => (r.identity === pay.identity ? scriptResource(pay.finalUrl as string, 'evil();', { pages: ['/checkout'] }) : r)) };
    expect(buildInventory({ site: modified, baseline, entries, now: NOW }).rows.find((r) => r.url === pay.finalUrl)?.status).toBe('not-approved');
    expect(buildInventory({ site: s, entries, now: NOW }).rows.find((r) => r.url === pay.finalUrl)?.approval).toBe('no-baseline');
  });

  it('requires purpose, owner, authorizedBy and authorizedAt', () => {
    const { s } = scene();
    const entries = parseInventory(`scripts:\n  - url: "https://js.vendor.test/*"\n    purpose: only a purpose\n`, 't').scripts;
    const row = buildInventory({ site: s, entries, now: NOW }).rows.find((r) => r.url.includes('pay.js'));
    expect(row?.status).toBe('missing-justification');
    expect(row?.issues.join(' ')).toMatch(/owner/);
  });

  it('lists stale entries and reports integrity (SRI) state', () => {
    const sri = scriptResource('https://js.vendor.test/v3/pay.js', 'pay();', { pages: ['/checkout'], sri: { attribute: 'sha256-bad', valid: false } });
    const s = site([sri], { pages: [page('/checkout', { sensitive: true })] });
    const result = buildInventory({ site: s, entries: parseInventory('scripts:\n  - url: "https://gone.test/*"\n', 't').scripts, now: NOW });
    expect(result.unmatchedEntries).toHaveLength(1);
    expect(result.rows[0]?.sri).toBe('mismatch');
  });

  it('--check fails only for scripts on sensitive pages without justification or overdue', () => {
    const { s, pay } = scene();
    const ok = parseInventory(`scripts:\n  - url: "https://*.vendor.test/*"\n    purpose: p\n    owner: o\n    authorizedBy: a\n    authorizedAt: 2026-01-01\n    reviewBy: 2027-01-01\n`, 't').scripts;
    expect(checkFailures(buildInventory({ site: s, entries: ok, now: NOW }).rows)).toEqual([]);
    // Only the non-sensitive home script lacks an entry: still passes.
    const onlyCheckout = parseInventory(`scripts:\n  - url: "https://js.vendor.test/*"\n    purpose: p\n    owner: o\n    authorizedBy: a\n    authorizedAt: 2026-01-01\n  - url: "https://tags.vendor.test/*"\n    purpose: p\n    owner: o\n    authorizedBy: a\n    authorizedAt: 2026-01-01\n`, 't').scripts;
    expect(checkFailures(buildInventory({ site: s, entries: onlyCheckout, now: NOW }).rows)).toEqual([]);
    const failing = checkFailures(buildInventory({ site: s, entries: [], now: NOW }).rows);
    expect(failing.map((r) => r.url).sort()).toEqual([pay.finalUrl, 'https://tags.vendor.test/t.js'].sort());
  });
});

describe('inventory export', () => {
  const { s } = scene();
  const hostile = scriptResource('https://x.test/=HYPERLINK("http://e")|a.js', 'h();', { pages: ['/checkout'] });
  const result = buildInventory({
    site: { ...s, resources: [...s.resources, hostile] },
    entries: parseInventory(`scripts:\n  - url: "https://js.vendor.test/*"\n    purpose: "=cmd|' /C calc'!A0"\n    owner: o, "quoted"\n    authorizedBy: a\n    authorizedAt: 2026-01-01\n`, 't').scripts,
    now: NOW,
  });

  it('exports csv with formula and quote protection', () => {
    const csv = toCsv(result.rows);
    expect(csv.split('\r\n')[0]).toContain('Status');
    expect(csv).toContain(",'=cmd|' /C calc'!A0,");
    expect(csv).toContain('"o, ""quoted"""');
    expect(csv.split('\r\n').filter(Boolean)).toHaveLength(result.rows.length + 1);
  });

  it('exports markdown, json and a table', () => {
    const md = toMarkdown(result);
    expect(md).toContain('| Status |');
    expect(md).not.toMatch(/[^\\]\|a\.js/); // pipe in a URL is escaped
    const json = JSON.parse(formatInventory(result, 'json')) as { rows: unknown[] };
    expect(json.rows).toHaveLength(result.rows.length);
    expect(toTable(result.rows).split('\n')[0]).toMatch(/^STATUS/);
  });
});

describe('inventory findings and editing', () => {
  it('produces info/low script-unjustified findings with stable ids for sensitive pages only', () => {
    const { s } = scene();
    const result = buildInventory({ site: s, entries: [], now: NOW });
    const a = inventoryFindings(result, { now: NOW });
    const b = inventoryFindings(result, { now: new Date('2026-07-01') });
    expect(a).toHaveLength(2);
    expect(a.map((f) => f.id)).toEqual(b.map((f) => f.id));
    expect(a.every((f) => f.kind === 'script-unjustified' && (f.severity === 'low' || f.severity === 'info'))).toBe(true);
    expect(a.some((f) => f.resourceUrl?.includes('home.js'))).toBe(false);
  });

  it('adds and sets entries, preserving comments, and never creates duplicates', () => {
    const first = editInventoryText(undefined, 'https://js.vendor.test/*', { purpose: 'Payments', owner: 'pay', authorizedBy: 'ciso', authorizedAt: '2026-01-10' }, 'add', 'f');
    expect(first.created).toBe(true);
    const commented = first.text.replace('scripts:', '# keep me\nscripts:');
    expect(() => editInventoryText(commented, 'https://js.vendor.test/*', {}, 'add', 'f')).toThrow(/already has/);
    expect(() => editInventoryText(commented, 'https://nope.test/*', { purpose: 'x' }, 'set', 'f')).toThrow(/no entry/);
    const set = editInventoryText(commented, 'https://js.vendor.test/*', { reviewBy: '2027-02-02' }, 'set', 'f');
    expect(set.text).toContain('# keep me');
    const entry = parseInventory(set.text, 'f').scripts[0];
    expect(entry).toMatchObject({ url: 'https://js.vendor.test/*', purpose: 'Payments', reviewBy: '2027-02-02' });
    const byIdentity = editInventoryText(set.text, 'url:https://a.test/x.js', { purpose: 'x' }, 'add', 'f');
    expect(parseInventory(byIdentity.text, 'f').scripts[1]?.identity).toBe('url:https://a.test/x.js');
    expect(() => editInventoryText(set.text, 'https://b.test/x.js', { reviewBy: 'soon' }, 'add', 'f')).toThrow(/date/);
  });
});
