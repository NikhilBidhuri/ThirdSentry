/**
 * Content-Security-Policy parser (CSP Level 3 "parse a serialized CSP").
 *
 *  - A header value may contain several policies separated by commas, and a
 *    response may carry several CSP headers; every policy is enforced
 *    independently (a resource must satisfy all of them).
 *  - Directive names are case-insensitive; the first occurrence of a
 *    directive wins and later duplicates are ignored (and reported).
 *  - Source expressions are classified so that the analyser can reason about
 *    keywords, nonces, hashes, schemes, hosts and wildcards.
 */

export type SourceKind = 'keyword' | 'nonce' | 'hash' | 'scheme' | 'host' | 'wildcard' | 'invalid';

export interface SourceExpression {
  readonly raw: string;
  readonly kind: SourceKind;
  /** Normalised value: keyword name, nonce/hash value, scheme (with colon), host pattern. */
  readonly value: string;
  /** For host sources: the hostname part (may start with "*."). */
  readonly host?: string;
  /** For host sources: explicit scheme, if any. */
  readonly scheme?: string;
}

export interface Directive {
  readonly name: string;
  readonly values: readonly string[];
  readonly sources: readonly SourceExpression[];
}

export interface Policy {
  readonly index: number;
  readonly raw: string;
  readonly disposition: 'enforce' | 'report';
  readonly directives: ReadonlyMap<string, Directive>;
  readonly duplicateDirectives: readonly string[];
  readonly unknownDirectives: readonly string[];
}

export const KNOWN_KEYWORDS = new Set([
  'self',
  'none',
  'unsafe-inline',
  'unsafe-eval',
  'strict-dynamic',
  'unsafe-hashes',
  'report-sample',
  'wasm-unsafe-eval',
  'unsafe-allow-redirects',
  'inline-speculation-rules',
  'trusted-types-eval',
]);

export const FETCH_DIRECTIVES = new Set([
  'default-src',
  'script-src',
  'script-src-elem',
  'script-src-attr',
  'style-src',
  'style-src-elem',
  'style-src-attr',
  'img-src',
  'font-src',
  'connect-src',
  'media-src',
  'object-src',
  'frame-src',
  'child-src',
  'worker-src',
  'manifest-src',
  'fenced-frame-src',
  'prefetch-src',
]);

const OTHER_DIRECTIVES = new Set([
  'base-uri',
  'form-action',
  'frame-ancestors',
  'sandbox',
  'report-uri',
  'report-to',
  'upgrade-insecure-requests',
  'block-all-mixed-content',
  'require-trusted-types-for',
  'trusted-types',
  'require-sri-for',
  'plugin-types',
  'navigate-to',
  'webrtc',
]);

export function isKnownDirective(name: string): boolean {
  return FETCH_DIRECTIVES.has(name) || OTHER_DIRECTIVES.has(name);
}

const HASH_RE = /^'(sha256|sha384|sha512)-([A-Za-z0-9+/_-]+={0,2})'$/i;
const NONCE_RE = /^'nonce-([A-Za-z0-9+/_-]+={0,2})'$/i;
const SCHEME_RE = /^[a-z][a-z0-9+.-]*:$/i;
const HOST_RE = /^(?:([a-z][a-z0-9+.-]*):\/\/)?(\*|\*\.[a-z0-9.-]+|[a-z0-9.-]+|\[[0-9a-f:.]+\])(?::(\d{1,5}|\*))?(\/[^\s;,]*)?$/i;

export function parseSource(raw: string): SourceExpression {
  const lower = raw.toLowerCase();
  if (raw === '*') return { raw, kind: 'wildcard', value: '*' };
  const quoted = /^'([a-z-]+)'$/i.exec(raw);
  if (quoted && KNOWN_KEYWORDS.has(lower.slice(1, -1))) return { raw, kind: 'keyword', value: lower.slice(1, -1) };
  const nonce = NONCE_RE.exec(raw);
  if (nonce) return { raw, kind: 'nonce', value: nonce[1] as string };
  const hash = HASH_RE.exec(raw);
  if (hash) return { raw, kind: 'hash', value: `${(hash[1] as string).toLowerCase()}-${hash[2] as string}` };
  if (SCHEME_RE.test(raw)) return { raw, kind: 'scheme', value: lower };
  const host = HOST_RE.exec(raw);
  if (host && !raw.startsWith("'")) {
    return { raw, kind: 'host', value: lower, host: (host[2] as string).toLowerCase(), ...(host[1] ? { scheme: `${host[1].toLowerCase()}:` } : {}) };
  }
  return { raw, kind: 'invalid', value: raw };
}

/** Parse one serialized policy. */
export function parsePolicy(raw: string, disposition: 'enforce' | 'report', index: number): Policy {
  const directives = new Map<string, Directive>();
  const duplicates: string[] = [];
  const unknown: string[] = [];
  for (const token of raw.split(';')) {
    const trimmed = token.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/[\t\n\f\r ]+/);
    const name = (parts[0] ?? '').toLowerCase();
    if (!/^[a-z0-9-]+$/.test(name)) continue;
    if (directives.has(name)) {
      duplicates.push(name);
      continue;
    }
    if (!isKnownDirective(name)) unknown.push(name);
    const values = parts.slice(1);
    const isSourceList = FETCH_DIRECTIVES.has(name) || name === 'base-uri' || name === 'form-action' || name === 'frame-ancestors';
    directives.set(name, { name, values, sources: isSourceList ? values.map(parseSource) : [] });
  }
  return { index, raw: raw.trim(), disposition, directives, duplicateDirectives: duplicates, unknownDirectives: unknown };
}

/** Parse every Content-Security-Policy / -Report-Only header value into policies. */
export function parsePolicies(enforceHeaders: readonly string[], reportOnlyHeaders: readonly string[] = []): Policy[] {
  const policies: Policy[] = [];
  const add = (headers: readonly string[], disposition: 'enforce' | 'report'): void => {
    for (const header of headers) {
      for (const serialized of header.split(',')) {
        if (serialized.trim()) policies.push(parsePolicy(serialized, disposition, policies.length));
      }
    }
  };
  add(enforceHeaders, 'enforce');
  add(reportOnlyHeaders, 'report');
  return policies;
}

/**
 * Fallback order for fetch directives (CSP3 §6.8.3 "Get the effective
 * directive for request" / fallback list). Navigation and document
 * directives (base-uri, form-action, frame-ancestors, ...) never fall back.
 */
const FALLBACKS: Record<string, readonly string[]> = {
  'script-src-elem': ['script-src-elem', 'script-src', 'default-src'],
  'script-src-attr': ['script-src-attr', 'script-src', 'default-src'],
  'script-src': ['script-src', 'default-src'],
  'style-src-elem': ['style-src-elem', 'style-src', 'default-src'],
  'style-src-attr': ['style-src-attr', 'style-src', 'default-src'],
  'style-src': ['style-src', 'default-src'],
  'worker-src': ['worker-src', 'child-src', 'script-src', 'default-src'],
  'frame-src': ['frame-src', 'child-src', 'default-src'],
  'child-src': ['child-src', 'default-src'],
  'img-src': ['img-src', 'default-src'],
  'connect-src': ['connect-src', 'default-src'],
  'font-src': ['font-src', 'default-src'],
  'media-src': ['media-src', 'default-src'],
  'object-src': ['object-src', 'default-src'],
  'manifest-src': ['manifest-src', 'default-src'],
};

/** The directive that actually governs `name` in a policy (after fallback), if any. */
export function effectiveDirective(policy: Policy, name: string): Directive | undefined {
  const chain = FALLBACKS[name] ?? [name];
  for (const candidate of chain) {
    const d = policy.directives.get(candidate);
    if (d) return d;
  }
  return undefined;
}
