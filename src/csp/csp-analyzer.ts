import { effectiveDirective, type Directive, type Policy, type SourceExpression } from './csp-parser.js';
import { RECOMMENDATIONS, type CspCheckId } from './csp-recommendations.js';

/**
 * CSP analysis with correct directive fallback and CSP3 semantics.
 *
 * Multiple enforced policies are all applied by the browser, so a weakness in
 * one policy is mitigated if another enforced policy blocks the same thing.
 * Findings are therefore evaluated across the whole policy set and marked as
 * mitigated where appropriate. Report-only policies never protect anything.
 *
 * Levels:
 *  - error:   a policy defect that leaves a known attack path open
 *  - warning: a recommendation that needs human review
 *  - info:    informational (e.g. a configuration that is fine but often misunderstood)
 */

export type CspLevel = 'error' | 'warning' | 'info';

export interface CspFinding {
  readonly id: CspCheckId;
  readonly level: CspLevel;
  readonly category: 'policy-error' | 'recommendation' | 'informational';
  readonly title: string;
  readonly explanation: string;
  readonly recommendation: string;
  readonly directive?: string;
  readonly policyIndex?: number;
  readonly detail?: string;
}

/** Hosts known to serve user-controlled content or JSONP/AngularJS gadgets that bypass host allowlists. */
export const RISKY_SCRIPT_HOSTS: readonly string[] = [
  '*.googleapis.com',
  'ajax.googleapis.com',
  'www.google.com',
  'accounts.google.com',
  '*.gstatic.com',
  'cdnjs.cloudflare.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'raw.githubusercontent.com',
  '*.github.io',
  '*.cloudfront.net',
  '*.amazonaws.com',
  '*.s3.amazonaws.com',
  '*.herokuapp.com',
  '*.azurewebsites.net',
  '*.firebaseapp.com',
  '*.web.app',
  '*.appspot.com',
  '*.vercel.app',
  '*.netlify.app',
  '*.blob.core.windows.net',
  '*.googleusercontent.com',
  'www.youtube.com',
  'api.twitter.com',
  '*.yandex.ru',
];

function sourceMatchesRisky(source: SourceExpression): string | undefined {
  if (source.kind !== 'host' || !source.host) return undefined;
  const host = source.host;
  for (const risky of RISKY_SCRIPT_HOSTS) {
    if (risky.startsWith('*.')) {
      const suffix = risky.slice(1);
      if (host === risky || host.endsWith(suffix)) return risky;
    } else if (host === risky || (host.startsWith('*.') && risky.endsWith(host.slice(1)))) {
      return risky;
    }
  }
  return undefined;
}

export interface ScriptPolicyProfile {
  readonly directive?: Directive;
  readonly restricts: boolean;
  readonly hasNonce: boolean;
  readonly hasHash: boolean;
  readonly strictDynamic: boolean;
  /** 'unsafe-inline' that browsers actually honour (not neutralised by nonce/hash). */
  readonly effectiveUnsafeInline: boolean;
  readonly unsafeEval: boolean;
  /** Host/scheme sources that are honoured (ignored under strict-dynamic). */
  readonly honouredSources: readonly SourceExpression[];
  readonly allowsAnyHost: boolean;
  readonly allowsData: boolean;
  readonly allowsBlob: boolean;
  readonly nonces: readonly string[];
}

/** How a policy governs script execution (script-src-elem → script-src → default-src). */
export function scriptProfile(policy: Policy): ScriptPolicyProfile {
  const directive = effectiveDirective(policy, 'script-src-elem') ?? effectiveDirective(policy, 'script-src');
  if (!directive) {
    return { restricts: false, hasNonce: false, hasHash: false, strictDynamic: false, effectiveUnsafeInline: true, unsafeEval: true, honouredSources: [], allowsAnyHost: true, allowsData: true, allowsBlob: true, nonces: [] };
  }
  const sources = directive.sources;
  const keyword = (k: string): boolean => sources.some((s) => s.kind === 'keyword' && s.value === k);
  const hasNonce = sources.some((s) => s.kind === 'nonce');
  const hasHash = sources.some((s) => s.kind === 'hash');
  const strictDynamic = keyword('strict-dynamic');
  const none = keyword('none') && sources.length === 1;
  // CSP2+: unsafe-inline is ignored when a nonce or hash is present.
  const effectiveUnsafeInline = !none && keyword('unsafe-inline') && !hasNonce && !hasHash;
  // CSP3: with strict-dynamic, host/scheme sources and 'self' are ignored.
  const honoured = strictDynamic ? [] : sources.filter((s) => s.kind === 'host' || s.kind === 'scheme' || s.kind === 'wildcard' || (s.kind === 'keyword' && s.value === 'self'));
  const schemes = new Set(honoured.filter((s) => s.kind === 'scheme').map((s) => s.value));
  return {
    directive,
    restricts: true,
    hasNonce,
    hasHash,
    strictDynamic,
    effectiveUnsafeInline,
    unsafeEval: keyword('unsafe-eval'),
    honouredSources: honoured,
    allowsAnyHost: honoured.some((s) => s.kind === 'wildcard') || schemes.has('https:') || schemes.has('http:'),
    allowsData: schemes.has('data:'),
    allowsBlob: schemes.has('blob:'),
    nonces: sources.filter((s) => s.kind === 'nonce').map((s) => s.value),
  };
}

function make(id: CspCheckId, extra: Partial<CspFinding> = {}): CspFinding {
  const r = RECOMMENDATIONS[id];
  const level = extra.level ?? r.level;
  return {
    id,
    level,
    category: level === 'error' ? 'policy-error' : level === 'warning' ? 'recommendation' : 'informational',
    title: r.title,
    explanation: r.explanation,
    recommendation: r.recommendation,
    ...extra,
  };
}

export interface CspAnalysis {
  readonly enforced: readonly Policy[];
  readonly reportOnly: readonly Policy[];
  readonly findings: readonly CspFinding[];
  /** Whether at least one enforced policy meaningfully restricts script execution. */
  readonly scriptsRestricted: boolean;
}

export function analyzePolicies(policies: readonly Policy[]): CspAnalysis {
  const enforced = policies.filter((p) => p.disposition === 'enforce');
  const reportOnly = policies.filter((p) => p.disposition === 'report');
  const findings: CspFinding[] = [];

  if (enforced.length === 0) {
    findings.push(make(reportOnly.length > 0 ? 'report-only' : 'no-policy'));
    for (const p of reportOnly) findings.push(...analyzeOne(p, [], true));
    return { enforced, reportOnly, findings, scriptsRestricted: false };
  }

  for (const p of enforced) findings.push(...analyzeOne(p, enforced.filter((o) => o !== p), false));

  const profiles = enforced.map(scriptProfile);
  const strong = profiles.some((pr) => pr.restricts && !pr.effectiveUnsafeInline && !pr.allowsAnyHost && !pr.allowsData);
  const anyHas = (name: string): boolean => enforced.some((p) => p.directives.has(name));
  if (!anyHas('report-uri') && !anyHas('report-to')) findings.push(make('missing-reporting'));
  if (!anyHas('frame-ancestors')) findings.push(make('missing-frame-ancestors'));
  if (!anyHas('require-trusted-types-for')) findings.push(make('trusted-types'));
  return { enforced, reportOnly, findings, scriptsRestricted: strong };
}

function analyzeOne(policy: Policy, others: readonly Policy[], reportOnly: boolean): CspFinding[] {
  const out: CspFinding[] = [];
  const at = { policyIndex: policy.index };
  const mitigation = (check: (o: Policy) => boolean): string | undefined => {
    const covering = others.find(check);
    return covering ? `Mitigated by enforced policy #${covering.index + 1}, which blocks this.` : undefined;
  };
  const demote = (f: CspFinding, note: string | undefined): CspFinding =>
    note ? { ...f, level: 'info', category: 'informational', detail: [f.detail, note].filter(Boolean).join(' ') } : f;
  const add = (f: CspFinding, note?: string): void => {
    out.push(reportOnly ? { ...f, level: 'info', category: 'informational', detail: [f.detail, 'Report-only policy: not enforced.'].filter(Boolean).join(' ') } : demote(f, note));
  };

  for (const d of policy.duplicateDirectives) add(make('duplicate-directive', { ...at, directive: d, detail: `"${d}" appears more than once; browsers ignore every occurrence after the first.` }));
  for (const d of policy.unknownDirectives) add(make('unknown-directive', { ...at, directive: d, detail: `"${d}" is not a known directive (typo?).` }));
  for (const d of policy.directives.values()) {
    for (const s of d.sources) {
      if (s.kind === 'invalid' || (s.kind === 'host' && ['self', 'none', 'unsafe-inline', 'unsafe-eval', 'strict-dynamic'].includes(s.value))) {
        add(make('invalid-source', { ...at, directive: d.name, detail: `"${s.raw}" is not a valid source expression${s.kind === 'host' ? ' (keywords must be quoted, e.g. \'self\')' : ''}.` }));
      }
    }
  }

  if (!policy.directives.has('default-src')) add(make('missing-default-src', at));

  const sp = scriptProfile(policy);
  const scriptCovered = (o: Policy): boolean => {
    const op = scriptProfile(o);
    return op.restricts && !op.effectiveUnsafeInline && !op.allowsAnyHost;
  };
  if (!sp.restricts) {
    add(make('no-script-restriction', at), mitigation(scriptCovered));
  } else {
    const dname = sp.directive?.name;
    if (sp.effectiveUnsafeInline) add(make('unsafe-inline', { ...at, ...(dname ? { directive: dname } : {}) }), mitigation((o) => { const op = scriptProfile(o); return op.restricts && !op.effectiveUnsafeInline; }));
    else if (sp.directive?.sources.some((s) => s.kind === 'keyword' && s.value === 'unsafe-inline')) {
      add(make('unsafe-inline-neutralised', { ...at, ...(dname ? { directive: dname } : {}) }));
    }
    if (sp.unsafeEval) add(make('unsafe-eval', { ...at, ...(dname ? { directive: dname } : {}) }), mitigation((o) => { const op = scriptProfile(o); return op.restricts && !op.unsafeEval; }));
    if (sp.allowsAnyHost) add(make('wildcard-script-source', { ...at, ...(dname ? { directive: dname } : {}), detail: sp.honouredSources.filter((s) => s.kind === 'wildcard' || s.kind === 'scheme').map((s) => s.raw).join(' ') }), mitigation(scriptCovered));
    if (sp.allowsData) add(make('data-script-source', { ...at, ...(dname ? { directive: dname } : {}) }), mitigation((o) => { const op = scriptProfile(o); return op.restricts && !op.allowsData; }));
    if (sp.strictDynamic && !sp.hasNonce && !sp.hasHash) add(make('strict-dynamic-without-nonce', { ...at, ...(dname ? { directive: dname } : {}) }));
    if (sp.strictDynamic && (sp.hasNonce || sp.hasHash)) add(make('strict-dynamic-ok', { ...at, ...(dname ? { directive: dname } : {}) }));
    if (!sp.hasNonce && !sp.hasHash && !sp.strictDynamic && !sp.effectiveUnsafeInline) add(make('allowlist-only', { ...at, ...(dname ? { directive: dname } : {}) }));
    const risky = [...new Set(sp.honouredSources.map(sourceMatchesRisky).filter((x): x is string => x !== undefined))];
    if (risky.length) add(make('risky-script-hosts', { ...at, ...(dname ? { directive: dname } : {}), detail: `Allowed: ${risky.join(', ')}` }));
    const hostCount = sp.honouredSources.filter((s) => s.kind === 'host').length;
    if (hostCount > 15) add(make('broad-script-allowlist', { ...at, ...(dname ? { directive: dname } : {}), detail: `${hostCount} hosts may serve scripts.` }));
    if (sp.directive?.sources.some((s) => s.kind === 'keyword' && s.value === 'unsafe-hashes')) add(make('unsafe-hashes', at));
    for (const nonce of sp.nonces) {
      if (nonce.length < 16) add(make('weak-nonce', { ...at, detail: `Nonce "${nonce}" is only ${nonce.length} characters.` }));
    }
  }

  const objectSrc = effectiveDirective(policy, 'object-src');
  const objectNone = objectSrc?.sources.length === 1 && objectSrc.sources[0]?.kind === 'keyword' && objectSrc.sources[0].value === 'none';
  if (!objectNone) {
    add(make('object-src', { ...at, ...(objectSrc ? { directive: objectSrc.name } : {}) }), mitigation((o) => { const d = effectiveDirective(o, 'object-src'); return d?.sources.length === 1 && d.sources[0]?.value === 'none'; }));
  }
  if (!policy.directives.has('base-uri')) {
    const nonceBased = sp.hasNonce || sp.strictDynamic;
    add(make('missing-base-uri', { ...at, level: nonceBased ? 'error' : 'warning' }), mitigation((o) => o.directives.has('base-uri')));
  }
  if (!policy.directives.has('form-action')) add(make('missing-form-action', at), mitigation((o) => o.directives.has('form-action')));
  return out;
}
