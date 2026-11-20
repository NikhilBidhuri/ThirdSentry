import { canonicalUrl } from '../discovery/resource-identity.js';
import { hostInfo } from '../discovery/resource-classifier.js';
import { matchesGlob, matchesHostPattern } from '../utils/patterns.js';
import type { ScriptPolicy } from './schema.js';
import type { PolicyRef } from './types.js';

/**
 * Policy matching and precedence.
 *
 * Specificity of a match, most specific first (documented in docs/policies.md):
 *   1. exact URL / identity
 *   2. URL prefix (longer prefix wins)
 *   3. glob (more literal characters win)
 *   4. host
 *   5. registrable domain
 * then: a `pages` restriction beats none, a site policy beats a global one,
 * and finally the policy declared first wins.
 */

export interface CompiledPolicy {
  readonly policy: ScriptPolicy;
  readonly ref: PolicyRef;
  readonly scope: string;
  readonly order: number;
  /** Allowed content hashes (pin mode): lowercase SHA-256 hex and `sha384-<base64>` entries. */
  readonly allowed: ReadonlySet<string>;
  /** Expiry instant in ms, if any. */
  readonly expiresAt?: number;
}

export interface ScriptFacts {
  readonly identity: string;
  /** Canonical requested URL (identity without the `url:` prefix). */
  readonly url: string;
  readonly hostname: string;
  readonly registrableDomain: string;
  readonly pages: readonly string[];
}

export interface Specificity {
  readonly level: number;
  readonly length: number;
  readonly pages: number;
}

export interface PolicyMatchResult {
  readonly policy: CompiledPolicy;
  readonly specificity: Specificity;
}

export function policyIdentity(name: string): string {
  return `policy:${name}`;
}

export function isPolicyIdentity(identity: string): boolean {
  return identity.startsWith('policy:');
}

/** Hash entries normalised for comparison. */
export function normalizeHashEntry(h: string): string {
  if (/^[0-9a-f]{64}$/i.test(h)) return h.toLowerCase();
  const m = /^(sha256|sha384)-([A-Za-z0-9+/_-]+)={0,2}$/.exec(h) as RegExpExecArray;
  const b64 = (m[2] as string).replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (m[1] === 'sha256') return Buffer.from(b64, 'base64').toString('hex');
  return `sha384-${b64}`;
}

export function expiryInstant(expires: string): number {
  const t = Date.parse(expires);
  return /^\d{4}-\d{2}-\d{2}$/.test(expires.trim()) ? t + 24 * 3600_000 : t;
}

export function isExpired(p: { readonly expires?: string | undefined }, now: Date): boolean {
  return p.expires !== undefined && expiryInstant(p.expires) <= now.getTime();
}

export function compilePolicy(policy: ScriptPolicy, scope: string, order: number): CompiledPolicy {
  return {
    policy,
    scope,
    order,
    ref: { name: policy.name, mode: policy.mode, scope, reason: policy.reason, ...(policy.owner ? { owner: policy.owner } : {}) },
    allowed: new Set((policy.hashes ?? []).map(normalizeHashEntry)),
    ...(policy.expires ? { expiresAt: expiryInstant(policy.expires) } : {}),
  };
}

/** Facts for a URL-identified script, or undefined for inline/blob/data scripts and cross-domain redirects (never covered). */
export function factsFor(
  identity: string,
  pages: readonly string[],
  urls: { readonly originalUrl?: string | undefined; readonly finalUrl?: string | undefined },
): ScriptFacts | undefined {
  if (!identity.startsWith('url:')) return undefined;
  const url = identity.slice(4);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return undefined;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return undefined;
  const requested = hostInfo(url);
  if (!requested) return undefined;
  // A script that was redirected to another registrable domain is not covered: whoever controls the
  // target controls the code, and a policy for domain A must not vouch for domain B.
  const final = urls.finalUrl ? hostInfo(urls.finalUrl) : undefined;
  if (final && final.registrableDomain !== requested.registrableDomain) return undefined;
  return { identity, url, hostname: requested.hostname, registrableDomain: requested.registrableDomain, pages };
}

function samePageSet(pages: readonly string[], patterns: readonly string[]): boolean {
  return pages.length > 0 && pages.every((p) => patterns.some((pat) => pat === p || matchesGlob(p, pat)));
}

function literalLength(glob: string): number {
  return glob.replace(/[*?]/g, '').length;
}

function better(a: Specificity, b: Specificity): boolean {
  if (a.level !== b.level) return a.level > b.level;
  if (a.length !== b.length) return a.length > b.length;
  return a.pages > b.pages;
}

/** Specificity of the best matcher of `policy` for the script, or undefined when it does not match. */
export function matchPolicy(policy: CompiledPolicy, facts: ScriptFacts, ignoreQueryParams: readonly string[]): Specificity | undefined {
  const m = policy.policy.match;
  if (m.pages && !samePageSet(facts.pages, m.pages)) return undefined;
  const pages = m.pages ? 1 : 0;
  let best: Specificity | undefined;
  const offer = (level: number, length: number): void => {
    const s = { level, length, pages };
    if (!best || better(s, best)) best = s;
  };
  let target: URL;
  try {
    target = new URL(facts.url);
  } catch {
    return undefined;
  }
  for (const id of m.identity ?? []) if (id === facts.identity) offer(6, id.length);
  for (const u of m.url ?? []) if (canonicalUrl(u, ignoreQueryParams) === facts.url) offer(6, u.length);
  for (const prefix of m.urlPrefix ?? []) {
    let p: URL;
    try {
      p = new URL(prefix);
    } catch {
      continue;
    }
    if (p.origin !== target.origin) continue;
    const want = `${p.pathname}${p.search}`;
    if (`${target.pathname}${target.search}`.startsWith(want)) offer(5, want.length);
  }
  for (const glob of m.glob ?? []) {
    const g = /^(https?):\/\/([^/]+)(\/.*)?$/.exec(glob);
    if (!g) continue;
    if (`${g[1]}:` !== target.protocol) continue;
    const hostPattern = (g[2] as string).toLowerCase();
    if (hostPattern.startsWith('*.') ? !matchesHostPattern(target.hostname, hostPattern) : target.host !== hostPattern && target.hostname !== hostPattern) continue;
    const pathGlob = g[3] ?? '/';
    if (matchesGlob(`${target.pathname}${target.search}`, pathGlob)) offer(4, literalLength(pathGlob));
  }
  for (const h of m.host ?? []) if (matchesHostPattern(facts.hostname, h)) offer(3, h.length);
  for (const d of m.domain ?? []) if (facts.registrableDomain === d.toLowerCase()) offer(2, d.length);
  return best;
}

/** All policies matching a script, ordered from most to least specific. */
export function matchAll(policies: readonly CompiledPolicy[], facts: ScriptFacts, ignoreQueryParams: readonly string[]): PolicyMatchResult[] {
  const out: PolicyMatchResult[] = [];
  for (const policy of policies) {
    const specificity = matchPolicy(policy, facts, ignoreQueryParams);
    if (specificity) out.push({ policy, specificity });
  }
  return out.sort((x, y) => {
    if (x.specificity.level !== y.specificity.level) return y.specificity.level - x.specificity.level;
    if (x.specificity.length !== y.specificity.length) return y.specificity.length - x.specificity.length;
    if (x.specificity.pages !== y.specificity.pages) return y.specificity.pages - x.specificity.pages;
    const xs = x.policy.scope === 'global' ? 0 : 1;
    const ys = y.policy.scope === 'global' ? 0 : 1;
    if (xs !== ys) return ys - xs;
    return x.policy.order - y.policy.order;
  });
}
