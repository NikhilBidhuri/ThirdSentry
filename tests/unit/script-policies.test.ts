import { describe, expect, it } from 'vitest';
import { approveSelected, createBaseline } from '../../src/baseline/baseline-manager.js';
import { sha256Hex, sriHash } from '../../src/analysis/hashing.js';
import { approvalItemsFor } from '../../src/cli/commands/baseline.js';
import { parseConfigText } from '../../src/config/loader.js';
import type { ThirdSentryConfig } from '../../src/config/schema.js';
import { compareSite } from '../../src/monitoring/comparison-engine.js';
import { buildFindings } from '../../src/monitoring/finding-engine.js';
import { applySuppressions } from '../../src/monitoring/suppressions.js';
import { applyPoliciesToSite, compareSiteWithPolicies } from '../../src/policies/apply.js';
import { isSilentPolicyFinding } from '../../src/policies/finding-hooks.js';
import { buildPolicyReport } from '../../src/policies/report.js';
import { ConfigError } from '../../src/utils/errors.js';
import type { ScriptResource } from '../../src/types/index.js';
import { externalIdentity } from '../../src/discovery/resource-identity.js';
import { destination, page, scriptResource, site } from '../fixtures/builders.js';

const NOW = new Date('2026-11-20T12:00:00Z');
const BASE = 'https://cdn.vendor.example/sdk/v3/';

function config(policies: string, siteExtra = ''): ThirdSentryConfig {
  return parseConfigText(
    `sites:\n  - name: shop\n    url: https://shop.example\n${siteExtra}\nscriptPolicies:\n${policies}`,
    'test.yml',
  );
}

const PATH_POLICY = `
  - name: vendor-sdk
    match:
      urlPrefix: ${BASE}
    mode: path-versions
    reason: Vendor ships hash-named bundles on every release
    owner: web-platform
`;

function ind(counts: Record<string, number> = {}): Pick<ScriptResource, 'indicators'> {
  return { indicators: { analyzed: true, counts, matches: [], hosts: [] } };
}

function bundle(hash: string, body: string, counts: Record<string, number> = {}, overrides: Partial<ScriptResource> = {}): ScriptResource {
  return scriptResource(`${BASE}main.${hash}.js`, body, { ...ind(counts), ...overrides });
}

function run(cfg: ThirdSentryConfig, baselineResources: ScriptResource[], current: ScriptResource[], extra: Parameters<typeof site>[1] = {}) {
  const baseline = createBaseline(site(baselineResources), { scanId: 'base', now: new Date('2026-01-01T00:00:00Z') });
  const applied = compareSiteWithPolicies(site(current, extra), baseline, cfg, { now: NOW });
  const findings = buildFindings(applied.comparison.changes, { site: applied.site, now: NOW });
  return { ...applied, findings };
}

const kinds = (changes: ReadonlyArray<{ kind: string }>): string[] => changes.map((c) => c.kind).sort();

describe('scriptPolicies configuration', () => {
  it('requires a reason, a matcher and hashes for pin', () => {
    expect(() => config(`  - name: a\n    match: { urlPrefix: ${BASE} }\n    mode: path-versions\n`)).toThrow(ConfigError);
    expect(() => config(`  - name: a\n    match: {}\n    mode: path-versions\n    reason: because\n`)).toThrow(/at least one of/);
    expect(() => config(`  - name: a\n    match: { url: ${BASE}x.js }\n    mode: pin\n    reason: because\n`)).toThrow(/hashes/);
    expect(() => config(`  - name: a\n    match: { url: ${BASE}x.js }\n    mode: domain-only\n    reason: because\n    hashes: [${'a'.repeat(64)}]\n`)).toThrow(/only valid with mode "pin"/);
  });

  it('rejects inline, blob and data matchers with a clear error', () => {
    for (const m of ['identity: "inline:/|main|html>head>script:nth-of-type(1)"', 'url: "blob:https://shop.example/abc"', 'urlPrefix: "data:text/javascript,1"', 'identity: "blob:/|main|abc"']) {
      expect(() => config(`  - name: a\n    match: { ${m} }\n    mode: path-versions\n    reason: because\n`)).toThrow(/URL-identified scripts only/);
    }
  });

  it('rejects matchers that could cover other domains', () => {
    const bad = (m: string): void => {
      expect(() => config(`  - name: a\n    match: { ${m} }\n    mode: domain-only\n    reason: because\n`)).toThrow(ConfigError);
    };
    bad('glob: "https://*/sdk/*.js"');
    bad('glob: "https://cdn.*.com/sdk/*.js"');
    bad('glob: "https://*.com/sdk/*.js"');
    bad('host: "*"');
    bad('host: "*.com"');
    bad('domain: "cdn.vendor.example"'); // not a registrable domain
    bad('domain: "*.vendor.example"');
  });

  it('rejects duplicate policy names, also across global and site scope', () => {
    expect(() => config(`${PATH_POLICY}${PATH_POLICY}`)).toThrow(/duplicate/);
    expect(() =>
      config(PATH_POLICY, `    scriptPolicies:\n      - name: vendor-sdk\n        match: { domain: vendor.example }\n        mode: domain-only\n        reason: x y z\n`),
    ).toThrow(/same name as a global policy/);
  });

  it('accepts SRI and hex pins, and scalar or list matchers', () => {
    const cfg = config(`  - name: pay\n    match: { url: ${BASE}pay.js, pages: /checkout }\n    mode: pin\n    reason: payments\n    hashes: [${'a'.repeat(64)}, ${sriHash('x', 'sha384')}, ${sriHash('x')}]\n`);
    expect(cfg.scriptPolicies[0]?.match.pages).toEqual(['/checkout']);
  });
});

describe('path-versions', () => {
  it('maps a renamed, hash-named bundle to one identity: no new + removed pair', () => {
    const result = run(config(PATH_POLICY), [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2()')]);
    expect(kinds(result.comparison.changes)).toEqual(['policy-accepted-update']);
    const f = result.findings[0];
    expect(f?.severity).toBe('info');
    expect(f?.policy?.name).toBe('vendor-sdk');
    expect(f?.resourceIdentity).toBe('policy:vendor-sdk');
    expect(f?.reason).toContain('vendor-sdk');
    expect(f?.evidence.some((e) => e.label === 'Policy')).toBe(true);
  });

  it('reports nothing when only the file name rotates', () => {
    const result = run(config(PATH_POLICY), [bundle('ab12cd', 'same()')], [bundle('ef34ab', 'same()')]);
    expect(result.comparison.changes).toEqual([]);
  });

  it('works for a baseline created before the policy existed and after adopting it', () => {
    const cfg = config(PATH_POLICY);
    const before = createBaseline(site([bundle('ab12cd', 'v1()')]), { scanId: 'a', now: NOW });
    expect(before.resources[0]?.identity).toMatch(/^url:/);
    const result = compareSiteWithPolicies(site([bundle('ab12cd', 'v1()')]), before, cfg, { now: NOW });
    expect(result.comparison.changes).toEqual([]);
    expect(result.comparison.unchanged).toBe(1);
  });

  it('still alerts when the update adds sendBeacon, at the severity of an unpoliced change', () => {
    const cfg = config(PATH_POLICY);
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2(); navigator.sendBeacon(u, d)', { 'TS-BEACON': 1 })]);
    const f = result.findings.find((x) => x.kind === 'policy-accepted-update');
    expect(f?.signals.some((s) => s.id === 'new-rule:TS-BEACON')).toBe(true);
    expect(f?.severity).not.toBe('info');
    expect(f?.policy?.name).toBe('vendor-sdk');
    // Same severity and score as the ordinary modified-script finding without a policy.
    const plainBase = createBaseline(site([scriptResource(`${BASE}main.js`, 'v1()', ind())]), { scanId: 'b', now: NOW });
    const plain = compareSite(site([scriptResource(`${BASE}main.js`, 'v2(); navigator.sendBeacon(u, d)', ind({ 'TS-BEACON': 1 }))]), plainBase);
    const plainFinding = buildFindings(plain.changes, { site: site([]), now: NOW })[0];
    expect(plainFinding?.kind).toBe('resource-modified');
    expect(f?.score).toBe(plainFinding?.score);
    expect(f?.severity).toBe(plainFinding?.severity);
  });

  it('still alerts on new cookie access and sensitive-field access', () => {
    const cfg = config(PATH_POLICY);
    const cookie = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2(); document.cookie', { 'TS-COOKIE-ACCESS': 1 })]);
    expect(cookie.findings[0]?.signals.some((s) => s.id === 'new-rule:TS-COOKIE-ACCESS')).toBe(true);
    expect(cookie.findings[0]?.score).toBeGreaterThan(0);
    const fields = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2()', { 'TS-SENSITIVE-FIELD-ACCESS': 1, 'TS-KEYSTROKE-CAPTURE': 2 })]);
    expect(fields.findings[0]?.severity).not.toBe('info');
  });

  it('ignores routine growth of behaviour that already existed', () => {
    const cfg = config(PATH_POLICY);
    const result = run(cfg, [bundle('ab12cd', 'v1()', { 'TS-COOKIE-ACCESS': 1 })], [bundle('ef34ab', 'v2()', { 'TS-COOKIE-ACCESS': 3 })]);
    expect(result.findings[0]?.severity).toBe('info');
    expect(result.findings[0]?.signals.map((s) => s.id)).toEqual(['policy-accepted-update']);
  });

  it('treats an update that can no longer be analysed as suspicious', () => {
    const cfg = config(PATH_POLICY);
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2()', {}, { indicators: { analyzed: false, error: 'parse error', counts: {}, matches: [], hosts: [] } })]);
    expect(result.findings[0]?.signals.some((s) => s.id === 'analysis-regression')).toBe(true);
    expect(result.findings[0]?.score).toBeGreaterThan(0);
  });

  it('still reports a new outbound domain and a new script domain', () => {
    const cfg = config(PATH_POLICY);
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2()'), scriptResource('https://evil-cdn.example/x.js', 'x()')], {
      destinations: [destination('cdn.vendor.example'), destination('evil-cdn.example'), destination('collect.exfil.example', { methods: ['POST'] })],
    });
    expect(kinds(result.comparison.changes)).toEqual(expect.arrayContaining(['new-outbound-domain', 'new-script-domain', 'policy-accepted-update', 'resource-added']));
  });

  it('does not cover requests that match the domain but fall outside the path', () => {
    const cfg = config(PATH_POLICY);
    const outside = scriptResource('https://cdn.vendor.example/other/tracker.js', 'x()', ind());
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ab12cd', 'v1()'), outside]);
    expect(kinds(result.comparison.changes)).toEqual(['resource-added']);
    expect(result.comparison.changes[0]?.policy).toBeUndefined();
  });

  it('a policy for domain A does not cover domain B, including lookalike hosts and cross-domain redirects', () => {
    const cfg = config(PATH_POLICY);
    const other = scriptResource('https://cdn.other.example/sdk/v3/main.aa.js', 'v1()', ind());
    const lookalike = scriptResource('https://cdn.vendor.example.evil.example/sdk/v3/main.aa.js', 'v1()', ind());
    const redirected = scriptResource(`${BASE}latest.js`, 'v1()', { ...ind(), finalUrl: 'https://cdn.attacker.example/latest.js' });
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ab12cd', 'v1()'), other, lookalike, redirected]);
    const added = result.comparison.changes.filter((c) => c.kind === 'resource-added');
    expect(added).toHaveLength(3);
    expect(added.every((c) => c.policy === undefined)).toBe(true);
  });

  it('an expired policy stops applying and is reported', () => {
    const cfg = config(`${PATH_POLICY}    expires: 2026-06-30\n`);
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2()')]);
    expect(kinds(result.comparison.changes)).toEqual(['resource-added', 'resource-removed']);
    expect(result.usage.expired.map((e) => e.ref.name)).toEqual(['vendor-sdk']);
    const report = buildPolicyReport(cfg, [result.usage], result.findings, NOW);
    expect(report?.expired.map((e) => e.name)).toEqual(['vendor-sdk']);
    expect(report?.active).toEqual([]);
  });

  it('a date-only expiry is valid through the end of that day', () => {
    const cfg = config(`${PATH_POLICY}    expires: 2026-11-20\n`);
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2()')]);
    expect(kinds(result.comparison.changes)).toEqual(['policy-accepted-update']);
  });

  it('reports a removal of the policy-governed script normally, naming the policy', () => {
    const result = run(config(PATH_POLICY), [bundle('ab12cd', 'v1()')], []);
    expect(kinds(result.comparison.changes)).toEqual(['resource-removed']);
    expect(result.findings[0]?.policy?.name).toBe('vendor-sdk');
  });

  it('lists active and unused policies in the report', () => {
    const cfg = config(`${PATH_POLICY}  - name: never-matches\n    match: { url: https://cdn.vendor.example/gone.js }\n    mode: domain-only\n    reason: leftover from an old integration\n`);
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2()')]);
    const report = buildPolicyReport(cfg, [result.usage], result.findings, NOW);
    expect(report?.active.map((e) => e.name)).toEqual(['vendor-sdk']);
    expect(report?.active[0]).toMatchObject({ matchedResources: 1, acceptedUpdates: 1, findings: 1, owner: 'web-platform' });
    expect(report?.unused.map((e) => e.name)).toEqual(['never-matches']);
    expect(report?.matches[0]).toMatchObject({ policy: 'vendor-sdk', identity: 'policy:vendor-sdk' });
  });

  it('baseline approval under the policy approves the policy identity', () => {
    const cfg = config(PATH_POLICY);
    const baseline = createBaseline(site([bundle('ab12cd', 'v1()')]), { scanId: 'base', now: NOW });
    const current = site([bundle('ef34ab', 'v2(); document.cookie', { 'TS-COOKIE-ACCESS': 1 })]);
    const applied = compareSiteWithPolicies(current, baseline, cfg, { now: NOW });
    const change = applied.comparison.changes[0];
    expect(change?.kind).toBe('policy-accepted-update');
    const items = approvalItemsFor(change as NonNullable<typeof change>);
    expect(items).toEqual([{ kind: 'resource', value: 'policy:vendor-sdk', sha256: sha256Hex('v2(); document.cookie') }]);
    const next = approveSelected(applied.baseline, applied.site, items, { scanId: 's2', now: NOW });
    expect(next.resources.map((r) => r.identity)).toEqual(['policy:vendor-sdk']);
    expect(next.resources[0]?.indicators).toEqual({ 'TS-COOKIE-ACCESS': 1 });
    const again = compareSiteWithPolicies(current, next, cfg, { now: NOW });
    expect(again.comparison.changes).toEqual([]);
    // A first baseline created under the policy uses the policy identity too.
    const first = createBaseline(applyPoliciesToSite(current, cfg, NOW), { scanId: 's3', now: NOW });
    expect(first.resources.map((r) => r.identity)).toEqual(['policy:vendor-sdk']);
  });

  it('honours ignoreQueryParams when matching exact URLs', () => {
    const cfg = config(`  - name: tag\n    match: { url: "${BASE}tag.js?cb=1" }\n    mode: path-versions\n    reason: cache-busted tag\n`, `    ignoreQueryParams: [cb]\n`);
    const identity = externalIdentity(`${BASE}tag.js?cb=1`, ['cb']);
    const a = scriptResource(`${BASE}tag.js?cb=111`, 'a()', { ...ind(), identity });
    const b = scriptResource(`${BASE}tag.js?cb=222`, 'b()', { ...ind(), identity });
    expect(kinds(run(cfg, [a], [b]).comparison.changes)).toEqual(['policy-accepted-update']);
  });

  it('restricts a policy to its pages', () => {
    const cfg = config(`  - name: checkout-sdk\n    match: { urlPrefix: ${BASE}, pages: ["/checkout"] }\n    mode: path-versions\n    reason: only checkout\n`);
    const home = bundle('ef34ab', 'v2()', {}, { pages: ['/'] });
    const result = run(cfg, [bundle('ab12cd', 'v1()', {}, { pages: ['/'] })], [home]);
    expect(kinds(result.comparison.changes)).toEqual(['resource-added', 'resource-removed']);
    const onCheckout = bundle('ef34ab', 'v2()', {}, { pages: ['/checkout'] });
    const baseline = createBaseline(site([bundle('ab12cd', 'v1()', {}, { pages: ['/checkout'] })], { pages: [page('/checkout')] }), { scanId: 'b', now: NOW });
    const covered = compareSiteWithPolicies(site([onCheckout], { pages: [page('/checkout')] }), baseline, cfg, { now: NOW });
    expect(kinds(covered.comparison.changes)).toEqual(['policy-accepted-update']);
  });
});

describe('pin', () => {
  const PAY = `${BASE}pay.js`;
  const pinFor = (...hashes: string[]): string => `  - name: payments-sdk\n    match: { url: ${PAY} }\n    mode: pin\n    reason: Payment SDK must never change silently\n    hashes: [${hashes.join(', ')}]\n`;

  it('accepts allowed hashes, even when they differ from the baseline', () => {
    const v1 = scriptResource(PAY, 'pay1()', ind());
    const v2 = scriptResource(PAY, 'pay2()', ind());
    const result = run(config(pinFor(sha256Hex('pay1()'), sha256Hex('pay2()').toUpperCase())), [v1], [v2]);
    expect(result.comparison.changes).toEqual([]);
  });

  it('reports any other content as a high-severity pinned-hash-mismatch', () => {
    const v1 = scriptResource(PAY, 'pay1()', ind());
    const evil = scriptResource(PAY, 'pay1(); skim()', ind());
    const result = run(config(pinFor(sha256Hex('pay1()'))), [v1], [evil]);
    expect(kinds(result.comparison.changes)).toEqual(['pinned-hash-mismatch']);
    const f = result.findings[0];
    expect(f?.kind).toBe('pinned-hash-mismatch');
    expect(f?.severity).toBe('high');
    expect(f?.policy?.name).toBe('payments-sdk');
    expect(f?.reason).toContain('payments-sdk');
  });

  it('stays high on sensitive pages', () => {
    const evil = scriptResource(PAY, 'skim()', ind());
    const baseline = createBaseline(site([scriptResource(PAY, 'pay1()', ind())]), { scanId: 'b', now: NOW });
    const sensitive = site([evil], { pages: [page('/', { sensitive: true })] });
    const applied = compareSiteWithPolicies(sensitive, baseline, config(pinFor(sha256Hex('pay1()'))), { now: NOW });
    const f = buildFindings(applied.comparison.changes, { site: applied.site, now: NOW })[0];
    expect(f?.severity).toBe('high');
  });

  it('is high even if the new hash was approved in the baseline', () => {
    const evil = scriptResource(PAY, 'skim()', ind());
    const result = run(config(pinFor(sha256Hex('pay1()'))), [evil], [evil]);
    expect(result.comparison.unchanged).toBeGreaterThanOrEqual(0);
    expect(kinds(result.comparison.changes)).toEqual(['pinned-hash-mismatch']);
    expect(result.findings[0]?.severity).toBe('high');
    expect(approvalItemsFor(result.comparison.changes[0] as NonNullable<(typeof result.comparison.changes)[0]>)).toEqual([]);
  });

  it('supports SRI sha384 pins and treats an unverifiable script as a finding', () => {
    const good = scriptResource(PAY, 'pay1()', { ...ind(), hashes: { ...scriptResource(PAY, 'pay1()').hashes, sri384: sriHash('pay1()', 'sha384') } });
    const cfg = config(pinFor(sriHash('pay1()', 'sha384')));
    expect(run(cfg, [good], [good]).comparison.changes).toEqual([]);
    const old = scriptResource(PAY, 'pay1()', ind()); // scan from before sri384 was recorded
    expect(kinds(run(cfg, [old], [old]).comparison.changes)).toEqual(['pinned-hash-mismatch']);
    const truncated = scriptResource(PAY, 'pay1()', { ...ind(), content: { status: 'truncated' } });
    const r = run(config(pinFor(sha256Hex('pay1()'))), [old], [truncated]);
    expect(r.comparison.changes.find((c) => c.kind === 'pinned-hash-mismatch')?.details.verdict).toBe('unverifiable');
  });

  it('still reports the absence of a pinned script normally', () => {
    const result = run(config(pinFor(sha256Hex('pay1()'))), [scriptResource(PAY, 'pay1()', ind())], []);
    expect(kinds(result.comparison.changes)).toEqual(['resource-removed']);
    expect(result.findings[0]?.policy?.name).toBe('payments-sdk');
  });

  it('is enforced even when a more specific policy of another mode wins', () => {
    const cfg = config(`${pinFor(sha256Hex('pay1()'))}`.replace('match: { url: ' + PAY + ' }', `match: { domain: vendor.example }`) + `  - name: exact\n    match: { url: ${PAY} }\n    mode: domain-only\n    reason: looser policy for the exact URL\n`);
    const result = run(cfg, [scriptResource(PAY, 'pay1()', ind())], [scriptResource(PAY, 'skim()', ind())]);
    expect(kinds(result.comparison.changes)).toContain('pinned-hash-mismatch');
  });
});

describe('domain-only', () => {
  const DOMAIN = `  - name: tagmgr\n    match: { domain: vendor.example }\n    mode: domain-only\n    reason: Tag manager that rotates constantly\n`;

  it('produces no findings for URL and content changes', () => {
    const cfg = config(DOMAIN);
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2()'), scriptResource('https://static.vendor.example/other.js', 'o()', ind())]);
    const visible = result.findings.filter((f) => !isSilentPolicyFinding(f));
    expect(visible.map((f) => f.kind)).not.toContain('resource-added');
    expect(visible.map((f) => f.kind)).not.toContain('resource-removed');
    expect(visible.filter((f) => f.kind === 'policy-accepted-update')).toEqual([]);
  });

  it('still surfaces new behaviour signals', () => {
    const cfg = config(DOMAIN);
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2()', { 'TS-BEACON': 1, 'TS-EXFIL-COMBINATION': 1 })]);
    const f = result.findings.filter((x) => !isSilentPolicyFinding(x))[0];
    expect(f?.kind).toBe('policy-accepted-update');
    expect(f?.policy?.mode).toBe('domain-only');
    expect(f?.severity).not.toBe('info');
  });

  it('a new domain is still a new domain', () => {
    const cfg = config(DOMAIN);
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2()'), scriptResource('https://evil-cdn.example/x.js', 'x()')]);
    expect(kinds(result.comparison.changes)).toContain('new-script-domain');
  });
});

describe('precedence', () => {
  it('the most specific matcher wins, then pages, site over global, then declaration order', () => {
    const cfg = config(
      `  - name: by-domain\n    match: { domain: vendor.example }\n    mode: domain-only\n    reason: broad\n` +
        `  - name: by-glob\n    match: { glob: "https://cdn.vendor.example/sdk/*/main.*.js" }\n    mode: path-versions\n    reason: glob\n` +
        `  - name: by-prefix\n    match: { urlPrefix: ${BASE} }\n    mode: path-versions\n    reason: prefix\n`,
      `    scriptPolicies:\n      - name: site-prefix\n        match: { urlPrefix: ${BASE} }\n        mode: path-versions\n        reason: site level\n`,
    );
    const r = bundle('ef34ab', 'v2()');
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [r]);
    // prefix (site) beats prefix (global), which beats the glob and the domain.
    expect(result.comparison.changes[0]?.policy?.name).toBe('site-prefix');
    const globOnly = run(
      config(`  - name: by-domain\n    match: { domain: vendor.example }\n    mode: domain-only\n    reason: broad\n  - name: by-glob\n    match: { glob: "https://cdn.vendor.example/sdk/*/main.*.js" }\n    mode: path-versions\n    reason: glob\n`),
      [bundle('ab12cd', 'v1()')],
      [r],
    );
    expect(globOnly.comparison.changes[0]?.policy?.name).toBe('by-glob');
  });
});

describe('suppressions', () => {
  it('can target findings by policy name', () => {
    const cfg = config(PATH_POLICY);
    const result = run(cfg, [bundle('ab12cd', 'v1()')], [bundle('ef34ab', 'v2(); document.cookie', { 'TS-COOKIE-ACCESS': 1 })]);
    const unsuppressed = applySuppressions(result.findings, [{ policy: 'other', reason: 'not this one' }], { now: NOW });
    expect(unsuppressed.findings[0]?.suppressed).toBeUndefined();
    const suppressed = applySuppressions(result.findings, [{ policy: 'vendor-sdk', reason: 'reviewed with the vendor' }], { now: NOW });
    expect(suppressed.findings[0]?.suppressed?.reason).toBe('reviewed with the vendor');
  });
});
