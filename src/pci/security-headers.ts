import { analyzePolicies } from '../csp/csp-analyzer.js';
import { parsePolicies, type Policy } from '../csp/csp-parser.js';

/**
 * Security-relevant HTTP response headers of a page's main document
 * (PCI DSS 11.6.1) and how a change of each one is classified.
 *
 * Headers are stored normalised (lower-case names, canonical value order), so
 * a header that is merely re-ordered or re-cased is not a change. The CSP is
 * compared semantically with the existing CSP analyzer: a new `'unsafe-inline'`
 * or a new script host is a weakening, a removed source is a strengthening.
 */

export const SECURITY_HEADERS = [
  'content-security-policy',
  'content-security-policy-report-only',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
] as const;

export type SecurityHeaderName = (typeof SECURITY_HEADERS)[number];
export type SecurityHeaders = Record<string, string>;

const CSP = 'content-security-policy';
const CSP_RO = 'content-security-policy-report-only';

function squash(v: string): string {
  return v.trim().replace(/\s+/g, ' ');
}

function normalizeCsp(raw: string, disposition: 'enforce' | 'report'): string {
  const policies = parsePolicies(disposition === 'enforce' ? [raw] : [], disposition === 'report' ? [raw] : []);
  return policies
    .map((p) =>
      [...p.directives.values()]
        .map((d) => [d.name, ...(d.name === 'sandbox' || d.name === 'trusted-types' || d.name === 'require-trusted-types-for' || d.name === 'report-uri' || d.name === 'report-to' ? d.values : [...new Set(d.values.map(squash))].sort())].join(' '))
        .sort()
        .join('; '),
    )
    .filter(Boolean)
    .sort()
    .join(', ');
}

export function normalizeHeaderValue(name: string, value: string): string {
  const v = squash(value);
  switch (name) {
    case CSP:
      return normalizeCsp(v, 'enforce');
    case CSP_RO:
      return normalizeCsp(v, 'report');
    case 'strict-transport-security':
      return v
        .toLowerCase()
        .split(';')
        .map((s) => s.trim().replace(/\s*=\s*/, '='))
        .filter(Boolean)
        .sort()
        .join('; ');
    case 'x-frame-options':
    case 'x-content-type-options':
    case 'cross-origin-opener-policy':
    case 'cross-origin-embedder-policy':
    case 'cross-origin-resource-policy':
      return v.toLowerCase();
    case 'referrer-policy':
      return v.toLowerCase().replace(/\s*,\s*/g, ', ');
    case 'permissions-policy':
      return v
        .split(/,(?![^(]*\))/)
        .map((s) => squash(s))
        .filter(Boolean)
        .sort()
        .join(', ');
    default:
      return v;
  }
}

/**
 * Extract and normalise the security headers of a document response. CSP values
 * come from the dedicated per-header arrays (they are not merged by the browser API).
 */
export function extractSecurityHeaders(
  documentHeaders: Readonly<Record<string, string>>,
  cspHeaders: readonly string[],
  cspReportOnlyHeaders: readonly string[],
): SecurityHeaders {
  const out: SecurityHeaders = {};
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(documentHeaders)) lower[k.toLowerCase()] = v;
  for (const name of SECURITY_HEADERS) {
    let raw: string | undefined;
    if (name === CSP) raw = cspHeaders.length > 0 ? cspHeaders.join(', ') : lower[CSP];
    else if (name === CSP_RO) raw = cspReportOnlyHeaders.length > 0 ? cspReportOnlyHeaders.join(', ') : lower[CSP_RO];
    else raw = lower[name];
    if (raw === undefined || raw.trim() === '') continue;
    out[name] = normalizeHeaderValue(name, raw);
  }
  return out;
}

export type HeaderDirection = 'weakened' | 'strengthened' | 'changed';

export interface HeaderChange {
  readonly header: string;
  readonly kind: 'added' | 'removed' | 'modified';
  readonly direction: HeaderDirection;
  readonly before?: string;
  readonly after?: string;
  /** Risk weight of this change (only meaningful for `weakened`; tiny for the others). */
  readonly weight: number;
  /** Stable ids of the reasons (used as signal ids suffixes). */
  readonly reasons: readonly string[];
  readonly summary: string;
}

/** Weight of removing each header (the more it protects against, the higher). */
const REMOVED_WEIGHT: Record<string, number> = {
  [CSP]: 45,
  'strict-transport-security': 35,
  'x-frame-options': 30,
  'x-content-type-options': 20,
  'referrer-policy': 12,
  'permissions-policy': 12,
  'cross-origin-opener-policy': 10,
  'cross-origin-embedder-policy': 8,
  'cross-origin-resource-policy': 8,
  [CSP_RO]: 3,
};

const SCRIPT_DIRECTIVES = new Set(['script-src', 'script-src-elem', 'default-src']);
const CRITICAL_DIRECTIVES = new Set(['script-src', 'script-src-elem', 'default-src', 'form-action', 'frame-ancestors', 'object-src', 'base-uri', 'connect-src']);
const DANGEROUS_KEYWORDS = new Set(["'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'"]);

interface CspDelta {
  weakened: Array<{ reason: string; weight: number; text: string }>;
  strengthened: string[];
}

function directiveSources(p: Policy[]): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  for (const policy of p) {
    for (const d of policy.directives.values()) {
      const set = map.get(d.name) ?? new Set<string>();
      for (const v of d.values) set.add(v.toLowerCase());
      map.set(d.name, set);
    }
  }
  return map;
}

function errorKeys(policies: Policy[]): Set<string> {
  return new Set(analyzePolicies(policies).findings.filter((f) => f.level === 'error').map((f) => `${f.id}${f.directive ? `:${f.directive}` : ''}`));
}

/** Semantic comparison of two enforced CSPs (or two report-only CSPs). */
function cspDelta(before: string, after: string, disposition: 'enforce' | 'report'): CspDelta {
  const parse = (v: string): Policy[] => (disposition === 'enforce' ? parsePolicies([v]) : parsePolicies([], [v]));
  const b = parse(before);
  const a = parse(after);
  const delta: CspDelta = { weakened: [], strengthened: [] };
  const bs = directiveSources(b);
  const as = directiveSources(a);
  for (const [name, sources] of as) {
    const old = bs.get(name);
    if (!old) {
      delta.strengthened.push(`directive ${name} added`);
      continue;
    }
    for (const s of sources) {
      if (old.has(s)) continue;
      if (DANGEROUS_KEYWORDS.has(s)) delta.weakened.push({ reason: 'csp-unsafe-keyword', weight: 40, text: `${name}: added ${s}` });
      else if (s === '*' || s === 'https:' || s === 'http:' || s === 'data:' || s === 'blob:') {
        if (CRITICAL_DIRECTIVES.has(name)) delta.weakened.push({ reason: 'csp-broad-source', weight: 40, text: `${name}: added ${s}` });
      } else if (SCRIPT_DIRECTIVES.has(name) && !s.startsWith("'")) delta.weakened.push({ reason: 'csp-new-script-host', weight: 25, text: `${name}: new script source ${s}` });
      else if (name === 'form-action' || name === 'frame-ancestors') {
        if (!s.startsWith("'")) delta.weakened.push({ reason: 'csp-new-host', weight: 15, text: `${name}: new source ${s}` });
      } else if (!s.startsWith("'") && (name === 'connect-src' || name === 'frame-src' || name === 'child-src')) {
        delta.weakened.push({ reason: 'csp-new-host', weight: 8, text: `${name}: new source ${s}` });
      }
    }
    for (const s of old) {
      if (sources.has(s)) continue;
      // Dropping 'none' while adding nothing else equals broadening.
      if (s === "'none'" && sources.size > 0) delta.weakened.push({ reason: 'csp-none-dropped', weight: 20, text: `${name}: 'none' replaced by ${[...sources].join(' ')}` });
      else delta.strengthened.push(`${name}: removed ${s}`);
    }
  }
  for (const [name] of bs) {
    if (as.has(name)) continue;
    if (CRITICAL_DIRECTIVES.has(name)) {
      const heavy = name === 'script-src' || name === 'default-src' || name === 'script-src-elem';
      delta.weakened.push({ reason: 'csp-directive-removed', weight: heavy ? 40 : 25, text: `directive ${name} removed` });
    } else delta.weakened.push({ reason: 'csp-directive-removed', weight: 8, text: `directive ${name} removed` });
  }
  // Findings of the existing analyzer that are new (or resolved) at error level.
  if (disposition === 'enforce') {
    const eb = errorKeys(b);
    const ea = errorKeys(a);
    for (const k of ea) if (!eb.has(k) && !delta.weakened.some((w) => k.startsWith('unsafe-inline') && w.text.includes("'unsafe-inline'"))) delta.weakened.push({ reason: 'csp-new-analyzer-error', weight: 20, text: `CSP analyzer: new problem "${k}"` });
    for (const k of eb) if (!ea.has(k)) delta.strengthened.push(`CSP analyzer: problem "${k}" resolved`);
  }
  return delta;
}

const XFO_RANK: Record<string, number> = { deny: 3, sameorigin: 2 };
const REFERRER_RANK = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'origin', 'origin-when-cross-origin', 'no-referrer-when-downgrade', 'unsafe-url'];
const COOP_RANK: Record<string, number> = { 'unsafe-none': 0, 'same-origin-allow-popups': 1, 'same-origin': 2 };
const COEP_RANK: Record<string, number> = { 'unsafe-none': 0, credentialless: 1, 'require-corp': 2 };
const CORP_RANK: Record<string, number> = { 'cross-origin': 0, 'same-site': 1, 'same-origin': 2 };

function hstsParts(v: string): { maxAge: number; sub: boolean; preload: boolean } {
  const m = /max-age=(\d+)/.exec(v);
  return { maxAge: m ? Number(m[1]) : 0, sub: v.includes('includesubdomains'), preload: v.includes('preload') };
}

function lastReferrerToken(v: string): number {
  const tokens = v.split(',').map((s) => s.trim()).filter((t) => REFERRER_RANK.includes(t));
  const last = tokens.at(-1);
  return REFERRER_RANK.length - (last ? REFERRER_RANK.indexOf(last) : REFERRER_RANK.indexOf('no-referrer-when-downgrade'));
}

function permissionsMap(v: string): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const part of v.split(/,(?![^(]*\))/)) {
    const m = /^\s*([a-z0-9-]+)\s*=\s*(.*)$/i.exec(part);
    if (!m) continue;
    const list = (m[2] as string).replace(/^\(|\)$/g, '').split(/\s+/).filter(Boolean);
    out.set((m[1] as string).toLowerCase(), new Set(list));
  }
  return out;
}

function ranked(name: string, before: string, after: string, rank: (v: string) => number | undefined, weight: number, label: string): HeaderChange | undefined {
  const rb = rank(before);
  const ra = rank(after);
  if (rb === undefined || ra === undefined || rb === ra) {
    return { header: name, kind: 'modified', direction: 'changed', before, after, weight: 2, reasons: [`${name}-changed`], summary: `${label} changed from "${before}" to "${after}"` };
  }
  const weaker = ra < rb;
  return {
    header: name,
    kind: 'modified',
    direction: weaker ? 'weakened' : 'strengthened',
    before,
    after,
    weight: weaker ? weight : 2,
    reasons: [`${name}-${weaker ? 'weakened' : 'strengthened'}`],
    summary: `${label} ${weaker ? 'weakened' : 'strengthened'}: "${before}" to "${after}"`,
  };
}

function modified(name: string, before: string, after: string): HeaderChange {
  const base = { header: name, kind: 'modified' as const, before, after };
  if (name === CSP || name === CSP_RO) {
    const d = cspDelta(before, after, name === CSP ? 'enforce' : 'report');
    if (d.weakened.length > 0) {
      const weight = name === CSP ? Math.min(60, d.weakened.reduce((s, w) => s + w.weight, 0)) : 3;
      return { ...base, direction: 'weakened', weight, reasons: [...new Set(d.weakened.map((w) => w.reason))], summary: `${name} weakened: ${d.weakened.map((w) => w.text).slice(0, 6).join('; ')}${d.strengthened.length ? ` (also strengthened: ${d.strengthened.slice(0, 3).join('; ')})` : ''}` };
    }
    if (d.strengthened.length > 0) return { ...base, direction: 'strengthened', weight: 2, reasons: ['csp-strengthened'], summary: `${name} strengthened: ${d.strengthened.slice(0, 6).join('; ')}` };
    return { ...base, direction: 'changed', weight: 2, reasons: ['csp-changed'], summary: `${name} changed without a change of its restrictions` };
  }
  switch (name) {
    case 'strict-transport-security': {
      const b = hstsParts(before);
      const a = hstsParts(after);
      const problems: string[] = [];
      let weight = 0;
      if (a.maxAge === 0) {
        problems.push('max-age=0 disables HSTS');
        weight += 35;
      } else if (a.maxAge < b.maxAge) {
        problems.push(`max-age reduced from ${b.maxAge} to ${a.maxAge}`);
        weight += 20;
      }
      if (b.sub && !a.sub) {
        problems.push('includeSubDomains removed');
        weight += 12;
      }
      if (b.preload && !a.preload) {
        problems.push('preload removed');
        weight += 6;
      }
      if (problems.length > 0) return { ...base, direction: 'weakened', weight, reasons: ['hsts-weakened'], summary: `Strict-Transport-Security weakened: ${problems.join('; ')}` };
      const stronger = a.maxAge > b.maxAge || (!b.sub && a.sub) || (!b.preload && a.preload);
      return { ...base, direction: stronger ? 'strengthened' : 'changed', weight: 2, reasons: ['hsts-' + (stronger ? 'strengthened' : 'changed')], summary: `Strict-Transport-Security ${stronger ? 'strengthened' : 'changed'}: "${before}" to "${after}"` };
    }
    case 'x-frame-options':
      return ranked(name, before, after, (v) => XFO_RANK[v] ?? 1, REMOVED_WEIGHT[name] ?? 20, 'X-Frame-Options') as HeaderChange;
    case 'x-content-type-options': {
      const weaker = before === 'nosniff' && after !== 'nosniff';
      return { ...base, direction: weaker ? 'weakened' : 'changed', weight: weaker ? 20 : 2, reasons: [weaker ? 'xcto-weakened' : 'xcto-changed'], summary: `X-Content-Type-Options changed from "${before}" to "${after}"` };
    }
    case 'referrer-policy':
      return ranked(name, before, after, (v) => lastReferrerToken(v), 10, 'Referrer-Policy') as HeaderChange;
    case 'permissions-policy': {
      const b = permissionsMap(before);
      const a = permissionsMap(after);
      const problems: string[] = [];
      for (const [feature, list] of b) {
        const now = a.get(feature);
        if (!now) problems.push(`${feature} no longer restricted`);
        else for (const o of now) if (!list.has(o) && !list.has('*')) problems.push(`${feature}: now allowed for ${o}`);
      }
      if (problems.length > 0) return { ...base, direction: 'weakened', weight: Math.min(25, 8 + problems.length * 4), reasons: ['permissions-policy-weakened'], summary: `Permissions-Policy weakened: ${problems.slice(0, 5).join('; ')}` };
      return { ...base, direction: 'strengthened', weight: 2, reasons: ['permissions-policy-strengthened'], summary: 'Permissions-Policy strengthened or reordered' };
    }
    case 'cross-origin-opener-policy':
      return ranked(name, before, after, (v) => COOP_RANK[v], 8, 'Cross-Origin-Opener-Policy') as HeaderChange;
    case 'cross-origin-embedder-policy':
      return ranked(name, before, after, (v) => COEP_RANK[v], 8, 'Cross-Origin-Embedder-Policy') as HeaderChange;
    case 'cross-origin-resource-policy':
      return ranked(name, before, after, (v) => CORP_RANK[v], 8, 'Cross-Origin-Resource-Policy') as HeaderChange;
    default:
      return { ...base, direction: 'changed', weight: 2, reasons: [`${name}-changed`], summary: `${name} changed` };
  }
}

/** Compare approved and current (normalised) security headers of one page. */
export function diffSecurityHeaders(approved: Readonly<SecurityHeaders>, current: Readonly<SecurityHeaders>): HeaderChange[] {
  const out: HeaderChange[] = [];
  for (const name of SECURITY_HEADERS) {
    const b = approved[name];
    const c = current[name];
    if (b === c) continue;
    if (b !== undefined && c === undefined) {
      out.push({ header: name, kind: 'removed', direction: 'weakened', before: b, weight: REMOVED_WEIGHT[name] ?? 10, reasons: [`${name}-removed`], summary: `${name} was removed (approved value: ${b.slice(0, 200)})` });
    } else if (b === undefined && c !== undefined) {
      out.push({ header: name, kind: 'added', direction: 'strengthened', after: c, weight: 2, reasons: [`${name}-added`], summary: `${name} was added: ${c.slice(0, 200)}` });
    } else if (b !== undefined && c !== undefined) {
      out.push(modified(name, b, c));
    }
  }
  return out;
}
