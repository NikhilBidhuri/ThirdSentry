/**
 * Small, dependency-free pattern helpers used by configuration (allowlists,
 * denylists, suppressions). Patterns are intentionally simple and predictable:
 *
 *  - Host patterns: `example.com` matches exactly; `*.example.com` matches any
 *    subdomain (but not `example.com` itself); `*` matches everything.
 *  - Glob patterns (URLs, paths): `*` matches any run of characters except
 *    nothing special; `**` is treated like `*`; `?` matches one character.
 *    Matching is case-sensitive except for the URL scheme/host which callers
 *    are expected to lowercase.
 */

export function normalizeHost(host: string): string {
  let h = host.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h.endsWith('.')) h = h.slice(0, -1);
  return h;
}

export function matchesHostPattern(host: string, pattern: string): boolean {
  const h = normalizeHost(host);
  const p = normalizeHost(pattern);
  if (p === '*') return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.com"
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  return h === p;
}

export function matchesAnyHost(host: string, patterns: readonly string[]): boolean {
  return patterns.some((p) => matchesHostPattern(host, p));
}

const globCache = new Map<string, RegExp>();

export function globToRegExp(glob: string): RegExp {
  const cached = globCache.get(glob);
  if (cached) return cached;
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i] as string;
    if (ch === '*') {
      while (glob[i + 1] === '*') i++;
      re += '.*';
    } else if (ch === '?') {
      re += '.';
    } else {
      re += ch.replace(/[\\^$.|+()[\]{}]/g, '\\$&');
    }
  }
  const compiled = new RegExp(`^${re}$`);
  globCache.set(glob, compiled);
  return compiled;
}

export function matchesGlob(value: string, glob: string): boolean {
  return globToRegExp(glob).test(value);
}

export function matchesAnyGlob(value: string, globs: readonly string[]): boolean {
  return globs.some((g) => matchesGlob(value, g));
}
