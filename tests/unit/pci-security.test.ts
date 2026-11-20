import { describe, expect, it } from 'vitest';
import { createBaseline, approveSelected, approveFullScan } from '../../src/baseline/baseline-manager.js';
import { validateBaseline } from '../../src/baseline/baseline-validator.js';
import { compareSite } from '../../src/monitoring/comparison-engine.js';
import { buildFindings } from '../../src/monitoring/finding-engine.js';
import { approvalItemsFor } from '../../src/cli/commands/baseline.js';
import { diffFormFingerprints, fingerprintForms, isPaymentLike } from '../../src/pci/form-fingerprint.js';
import { diffSecurityHeaders, extractSecurityHeaders } from '../../src/pci/security-headers.js';
import { FormSnapshotEvidenceSchema, type FormEvidence, type FormSnapshotEvidence } from '../../src/types/evidence.js';
import type { Finding } from '../../src/types/findings.js';
import type { SiteResult } from '../../src/types/index.js';
import { page, scriptResource, site } from '../fixtures/builders.js';

const hdr = (h: Record<string, string>, csp: string[] = [], ro: string[] = []): Record<string, string> => extractSecurityHeaders(h, csp, ro);

describe('security header diffing', () => {
  const csp = (v: string): Record<string, string> => hdr({}, [v]);

  it('does not report re-ordered or re-cased headers', () => {
    const a = hdr({ 'X-Frame-Options': 'DENY', 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' }, ["script-src 'self' a.test b.test; object-src 'none'"]);
    const b = hdr({ 'x-frame-options': 'deny', 'strict-transport-security': 'includeSubDomains;  max-age=31536000' }, ["object-src 'none'; script-src b.test a.test 'self'"]);
    expect(diffSecurityHeaders(a, b)).toEqual([]);
  });

  it("classifies a new 'unsafe-inline' as weakened", () => {
    const [c] = diffSecurityHeaders(csp("script-src 'self'"), csp("script-src 'self' 'unsafe-inline'"));
    expect(c?.direction).toBe('weakened');
    expect(c?.reasons).toContain('csp-unsafe-keyword');
    expect(c?.weight).toBeGreaterThanOrEqual(40);
  });

  it('classifies a new script host as weakened, with less weight than unsafe-inline', () => {
    const [c] = diffSecurityHeaders(csp("script-src 'self'"), csp("script-src 'self' cdn.evil.test"));
    expect(c?.direction).toBe('weakened');
    expect(c?.reasons).toContain('csp-new-script-host');
    expect(c?.weight).toBeLessThan(40);
  });

  it('classifies a removed CSP directive as weakened', () => {
    const [c] = diffSecurityHeaders(csp("script-src 'self'; form-action 'self'"), csp("script-src 'self'"));
    expect(c?.direction).toBe('weakened');
    expect(c?.summary).toMatch(/form-action removed/);
  });

  it('classifies removed sources and added directives as strengthened (not weakened)', () => {
    const [removed] = diffSecurityHeaders(csp("script-src 'self' a.test b.test"), csp("script-src 'self' a.test"));
    expect(removed?.direction).toBe('strengthened');
    const [added] = diffSecurityHeaders(csp("script-src 'self'"), csp("script-src 'self'; frame-ancestors 'none'"));
    expect(added?.direction).toBe('strengthened');
    expect(added?.weight).toBeLessThan(5);
  });

  it('rates a removed header higher than an added one', () => {
    const removed = diffSecurityHeaders(hdr({ 'x-frame-options': 'DENY' }), hdr({}))[0];
    const added = diffSecurityHeaders(hdr({}), hdr({ 'x-frame-options': 'DENY' }))[0];
    expect(removed?.direction).toBe('weakened');
    expect(added?.direction).toBe('strengthened');
    expect((removed?.weight ?? 0) > (added?.weight ?? 99)).toBe(true);
    const cspRemoved = diffSecurityHeaders(csp("script-src 'self'"), hdr({}))[0];
    expect(cspRemoved?.weight).toBeGreaterThan(removed?.weight ?? 0);
  });

  it('classifies HSTS, referrer policy and permissions policy changes', () => {
    expect(diffSecurityHeaders(hdr({ 'strict-transport-security': 'max-age=31536000' }), hdr({ 'strict-transport-security': 'max-age=0' }))[0]?.direction).toBe('weakened');
    expect(diffSecurityHeaders(hdr({ 'strict-transport-security': 'max-age=100' }), hdr({ 'strict-transport-security': 'max-age=200; includeSubDomains' }))[0]?.direction).toBe('strengthened');
    expect(diffSecurityHeaders(hdr({ 'referrer-policy': 'no-referrer' }), hdr({ 'referrer-policy': 'unsafe-url' }))[0]?.direction).toBe('weakened');
    expect(diffSecurityHeaders(hdr({ 'x-frame-options': 'SAMEORIGIN' }), hdr({ 'x-frame-options': 'DENY' }))[0]?.direction).toBe('strengthened');
    expect(diffSecurityHeaders(hdr({ 'permissions-policy': 'payment=(self)' }), hdr({ 'permissions-policy': 'payment=(self "https://x.test")' }))[0]?.direction).toBe('weakened');
  });
});

function formEvidence(overrides: Partial<FormEvidence> & { fields: FormEvidence['fields'] }): FormEvidence {
  return { action: 'https://shop.example/pay', buttonActions: [], method: 'post', frameOrigin: 'https://shop.example', formless: false, ...overrides };
}

const snapshot = (forms: FormEvidence[], paymentFrames: string[] = []): FormSnapshotEvidence => ({ status: 'captured', forms, paymentFrames });
const card = { name: 'cardnumber', type: 'text', autocomplete: 'cc-number' };
const cvc = { name: 'cvc', type: 'text', autocomplete: 'cc-csc' };
const exp = { name: 'exp', type: 'text', autocomplete: 'cc-exp' };
const email = { name: 'email', type: 'email' };

const base = formEvidence({ fields: [card, cvc, exp, email] });

function diff(before: FormSnapshotEvidence, after: FormSnapshotEvidence): string[] {
  const a = fingerprintForms(before);
  const b = fingerprintForms(after);
  if (!a || !b) throw new Error('snapshot failed');
  return diffFormFingerprints(a, b, 'https://shop.example').map((d) => d.type);
}

describe('form fingerprints', () => {
  it('recognises payment-like fields from autocomplete and names', () => {
    expect(isPaymentLike({ name: 'x', autocomplete: 'cc-number' })).toBe(true);
    for (const n of ['card_number', 'CVV', 'cvc2', 'pan', 'expiry-date', 'ccNum']) expect(isPaymentLike({ name: n })).toBe(true);
    for (const n of ['email', 'company', 'panel', 'span', 'address']) expect(isPaymentLike({ name: n })).toBe(false);
  });

  it('ignores field order, query strings, name case and duplicates', () => {
    const a = snapshot([base]);
    const b = snapshot([formEvidence({ action: 'https://shop.example/pay?x=1#f', method: 'POST', fields: [email, { ...exp, name: 'EXP' }, cvc, card, card] })]);
    expect(fingerprintForms(a)?.hash).toBe(fingerprintForms(b)?.hash);
    expect(diff(a, b)).toEqual([]);
  });

  it('is undefined for a failed snapshot and never trusts a worker-supplied payment flag', () => {
    expect(fingerprintForms({ status: 'failed', forms: [], paymentFrames: [] })).toBeUndefined();
    const fp = fingerprintForms(snapshot([formEvidence({ fields: [{ ...card, payment: false } as never] })]));
    expect(fp?.forms[0]?.fields[0]?.payment).toBe(true);
  });

  it('detects a re-targeted action origin; a path change on the same origin is lower', () => {
    expect(diff(snapshot([base]), snapshot([{ ...base, action: 'https://evil.example/collect' }]))).toEqual(['action-origin-changed']);
    expect(diff(snapshot([base]), snapshot([{ ...base, action: 'https://shop.example/other' }]))).toEqual(['action-path-changed']);
  });

  it('flags the external action origin', () => {
    const a = fingerprintForms(snapshot([base]));
    const b = fingerprintForms(snapshot([{ ...base, action: 'https://evil.example/collect' }]));
    const [d] = diffFormFingerprints(a as never, b as never, 'https://shop.example');
    expect(d?.externalOrigin).toBe(true);
  });

  it('detects an added payment input and an injected fake card form', () => {
    expect(diff(snapshot([base]), snapshot([{ ...base, fields: [...base.fields, { name: 'card2', type: 'text' }] }]))).toEqual(['payment-field-added']);
    const fake = formEvidence({ action: 'https://evil.example/c', fields: [{ name: 'cc_number', type: 'text' }, { name: 'cvv', type: 'text' }] });
    expect(diff(snapshot([base]), snapshot([base, fake]))).toEqual(['payment-form-added']);
  });

  it('classifies removed and renamed payment fields', () => {
    expect(diff(snapshot([base]), snapshot([{ ...base, fields: [card, exp, email] }]))).toEqual(['payment-field-removed']);
    expect(diff(snapshot([base]), snapshot([{ ...base, fields: [card, { ...cvc, name: 'security_code', autocomplete: 'cc-csc' }, exp, email] }]))).toEqual(['payment-field-renamed']);
  });

  it('reports a new payment iframe origin', () => {
    expect(diff(snapshot([base]), snapshot([base], ['https://pay.vendor.test']))).toEqual(['payment-frame-added']);
  });

  it('validates and size-caps evidence in the schema', () => {
    const many = Array.from({ length: 300 }, (_, i) => ({ name: `f${i}`, type: 'text' }));
    expect(FormSnapshotEvidenceSchema.safeParse(snapshot([{ ...base, fields: many }])).success).toBe(false);
    expect(FormSnapshotEvidenceSchema.safeParse(snapshot([{ ...base, fields: [{ name: 'x'.repeat(300), type: 'text' }] }])).success).toBe(false);
    expect(FormSnapshotEvidenceSchema.safeParse({ status: 'captured', forms: [], paymentFrames: [], extra: 1 }).success).toBe(true);
  });
});

function sitePage(headers: Record<string, string> | undefined, forms: FormSnapshotEvidence | undefined, key = '/checkout'): SiteResult {
  return site([scriptResource('https://shop.example/app.js', 'x', { pages: [key] })], {
    pages: [
      page(key, {
        sensitive: true,
        documentStatus: 200,
        ...(headers ? { securityHeaders: headers } : {}),
        ...(forms ? { formFingerprint: fingerprintForms(forms) as never } : {}),
      }),
    ],
  });
}

function findingsFor(baselineSite: SiteResult, current: SiteResult): Finding[] {
  const baseline = createBaseline(baselineSite, { scanId: 's1' });
  return buildFindings(compareSite(current, baseline).changes, { site: current }).filter((f) => f.kind !== 'resource-added');
}

describe('PCI findings', () => {
  const goodHeaders = hdr({ 'x-frame-options': 'DENY', 'strict-transport-security': 'max-age=31536000' }, ["script-src 'self'; form-action 'self'"]);

  it('weakened CSP on a sensitive page is high; strengthened is info', () => {
    const base = sitePage(goodHeaders, undefined);
    const weaker = findingsFor(base, sitePage(hdr({ 'x-frame-options': 'DENY', 'strict-transport-security': 'max-age=31536000' }, ["script-src 'self' 'unsafe-inline'; form-action 'self'"]), undefined));
    expect(weaker.map((f) => [f.kind, f.severity])).toEqual([['security-header-changed', 'high']]);
    expect(weaker[0]?.signals.map((s) => s.id)).toContain('sensitive-page');
    const stronger = findingsFor(base, sitePage({ ...goodHeaders, 'referrer-policy': 'no-referrer' }, undefined));
    expect(stronger.map((f) => [f.kind, f.severity])).toEqual([['security-header-changed', 'info']]);
    expect(stronger[0]?.signals.some((s) => s.id === 'sensitive-page')).toBe(false);
  });

  it('removed header is rated higher than added header; both have stable ids', () => {
    const base = sitePage(goodHeaders, undefined);
    const removed = findingsFor(base, sitePage({ 'strict-transport-security': 'max-age=31536000' }, undefined));
    const again = findingsFor(base, sitePage({ 'strict-transport-security': 'max-age=31536000' }, undefined));
    expect(removed[0]?.id).toBe(again[0]?.id);
    expect(['high', 'critical']).toContain(removed[0]?.severity);
    expect(removed[0]?.title).toMatch(/removed/);
  });

  it('a re-targeted form action and an injected card form are high or critical', () => {
    const base = sitePage(goodHeaders, snapshot([base0()]));
    const retargeted = findingsFor(base, sitePage(goodHeaders, snapshot([{ ...base0(), action: 'https://evil.example/c' }])));
    expect(retargeted[0]?.kind).toBe('payment-form-changed');
    expect(['high', 'critical']).toContain(retargeted[0]?.severity);
    const fake = formEvidence({ action: 'https://evil.example/c', fields: [{ name: 'cc_number', type: 'text' }, { name: 'cvv', type: 'text' }] });
    const injected = findingsFor(base, sitePage(goodHeaders, snapshot([base0(), fake])));
    expect(['high', 'critical']).toContain(injected[0]?.severity);
    const added = findingsFor(base, sitePage(goodHeaders, snapshot([{ ...base0(), fields: [...base0().fields, { name: 'card_backup', type: 'text' }] }])));
    expect(added[0]?.severity).toBe('high');
    const removed = findingsFor(base, sitePage(goodHeaders, snapshot([{ ...base0(), fields: [card, exp, email] }])));
    expect(removed[0]?.severity).toBe('medium');
  });

  it('formatting/order-only changes produce no finding', () => {
    const base = sitePage(goodHeaders, snapshot([base0()]));
    const reordered = sitePage(goodHeaders, snapshot([{ ...base0(), fields: [...base0().fields].reverse(), action: 'https://shop.example/pay?cb=1' }]));
    expect(findingsFor(base, reordered)).toEqual([]);
  });

  it('every new finding has the explanation fields and flows through approval items', () => {
    const base = sitePage(goodHeaders, snapshot([base0()]));
    const current = sitePage(hdr({}), snapshot([{ ...base0(), action: 'https://evil.example/c' }]));
    const baseline = createBaseline(base, { scanId: 's1' });
    const changes = compareSite(current, baseline).changes.filter((c) => c.kind === 'security-header-changed' || c.kind === 'payment-form-changed');
    const findings = buildFindings(changes, { site: current });
    for (const f of findings) {
      expect(f.title.length).toBeGreaterThan(5);
      expect(f.reason.length).toBeGreaterThan(20);
      expect(f.recommendedAction).toMatch(/--approve|approve/);
      expect(f.signals.length).toBeGreaterThan(0);
    }
    const items = changes.flatMap(approvalItemsFor);
    expect(items.map((i) => (i.kind === 'page-security' ? `${i.value}#${i.part}` : i.kind)).sort()).toEqual(['/checkout#forms', '/checkout#headers']);
    // Selective approval: only the headers.
    const next = approveSelected(baseline, current, items.filter((i) => i.kind === 'page-security' && i.part === 'headers'), { scanId: 's2' });
    expect(next.pageSecurity?.['/checkout']?.headers).toEqual({});
    expect(next.pageSecurity?.['/checkout']?.forms?.hash).toBe(baseline.pageSecurity?.['/checkout']?.forms?.hash);
    const after = compareSite(current, next).changes.map((c) => c.kind);
    expect(after).toContain('payment-form-changed');
    expect(after).not.toContain('security-header-changed');
  });
});

function base0(): FormEvidence {
  return formEvidence({ fields: [card, cvc, exp, email] });
}

describe('baselines written before security headers and forms existed', () => {
  it('a version 1 baseline loads and yields one low-severity notice, not a flood of changes', () => {
    const baseline = createBaseline(sitePage(undefined, undefined), { scanId: 's1' });
    const v1 = JSON.parse(JSON.stringify({ ...baseline, schemaVersion: 1 })) as Record<string, unknown>;
    delete v1.pageSecurity;
    const loaded = validateBaseline(v1, 'shop', 'old.json');
    expect(loaded.schemaVersion).toBe(2);
    expect(loaded.pageSecurity).toBeUndefined();

    const current = sitePage(hdr({ 'x-frame-options': 'DENY' }, ["script-src 'self'"]), snapshot([base0()]));
    const changes = compareSite(current, loaded).changes;
    const security = changes.filter((c) => ['security-header-changed', 'payment-form-changed', 'security-baseline-missing'].includes(c.kind));
    expect(security.map((c) => c.kind)).toEqual(['security-baseline-missing']);
    const findings = buildFindings(security, { site: current });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('low');
    expect(findings[0]?.pages).toEqual([]);

    // Approving the notice records the state; the next comparison is clean.
    const items = security.flatMap(approvalItemsFor);
    const next = approveSelected(loaded, current, items, { scanId: 's2' });
    expect(next.pageSecurity?.['/checkout']?.headers?.['x-frame-options']).toBe('deny');
    expect(next.pageSecurity?.['/checkout']?.forms).toBeDefined();
    expect(compareSite(current, next).changes.filter((c) => c.kind.startsWith('security') || c.kind === 'payment-form-changed')).toEqual([]);
  });

  it('a full approval records the security state and keeps pages that were not scanned completely', () => {
    const current = sitePage(hdr({ 'x-frame-options': 'DENY' }), snapshot([base0()]));
    const old = createBaseline(sitePage(undefined, undefined, '/other'), { scanId: 's0' });
    const next = approveFullScan({ ...old, pageSecurity: { '/gone': { headers: {}, approvedAt: 'x' } } }, current, { scanId: 's1' });
    expect(Object.keys(next.pageSecurity ?? {}).sort()).toEqual(['/checkout', '/gone']);
  });

  it('ignores scans that carry no header evidence (older scan results)', () => {
    const baseline = createBaseline(sitePage(hdr({ 'x-frame-options': 'DENY' }), snapshot([base0()])), { scanId: 's1' });
    const oldScan = site([scriptResource('https://shop.example/app.js', 'x', { pages: ['/checkout'] })], { pages: [page('/checkout', { sensitive: true })] });
    expect(compareSite(oldScan, baseline).changes.filter((c) => c.kind === 'security-header-changed' || c.kind === 'security-baseline-missing')).toEqual([]);
  });

  it('a failed form snapshot on a baselined page degrades coverage instead of reading as "no forms"', () => {
    const baseline = createBaseline(sitePage(goodH(), snapshot([base0()])), { scanId: 's1' });
    const current = site([scriptResource('https://shop.example/app.js', 'x', { pages: ['/checkout'] })], { pages: [page('/checkout', { sensitive: true, documentStatus: 200, securityHeaders: goodH(), formSnapshotFailed: true })] });
    const c = compareSite(current, baseline).changes.find((x) => x.details.reason === 'form-snapshot-failed');
    expect(c?.kind).toBe('coverage-degraded');
  });
});

function goodH(): Record<string, string> {
  return hdr({ 'x-frame-options': 'DENY' });
}
