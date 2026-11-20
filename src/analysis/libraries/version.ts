/**
 * Semver-ish version parsing and comparison for library versions.
 *
 * JavaScript libraries use many schemes (1.12.4, 3.0.0-beta1, 1.9.0b1,
 * 2.0.0rc.2, 1.4). A version is parsed as up to four numeric components
 * (missing ones are 0) plus an optional pre-release tag. A release sorts
 * after every pre-release of the same numbers ("1.9.0b1" < "1.9.0").
 * Pre-release tags are compared chunk by chunk (numeric chunks numerically,
 * alphabetic ones lexically, numeric before alphabetic, shorter prefix first).
 */

export interface ParsedVersion {
  readonly raw: string;
  readonly nums: readonly [number, number, number, number];
  readonly pre: readonly (string | number)[];
}

const VERSION_RE = /^v?(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:[-.+_]?([A-Za-z][0-9A-Za-z.\-_]{0,30}))?$/;

export function parseVersion(input: string): ParsedVersion | undefined {
  const raw = input.trim();
  if (raw.length === 0 || raw.length > 40) return undefined;
  const m = VERSION_RE.exec(raw);
  if (!m) return undefined;
  const nums: [number, number, number, number] = [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0), Number(m[4] ?? 0)];
  const pre = m[5] ? (m[5].match(/\d+|[A-Za-z]+/g) ?? []).map((c) => (/^\d+$/.test(c) ? Number(c) : c.toLowerCase())) : [];
  return { raw, nums, pre };
}

function comparePre(a: readonly (string | number)[], b: readonly (string | number)[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1; // a is a release, b a pre-release
  if (b.length === 0) return -1;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const x = a[i] as string | number;
    const y = b[i] as string | number;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x < y ? -1 : 1;
    if (typeof x === 'number') return -1;
    if (typeof y === 'number') return 1;
    return x < y ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

export function compareParsed(a: ParsedVersion, b: ParsedVersion): number {
  for (let i = 0; i < 4; i++) {
    const x = a.nums[i] as number;
    const y = b.nums[i] as number;
    if (x !== y) return x < y ? -1 : 1;
  }
  return comparePre(a.pre, b.pre);
}

/** Compare two version strings; undefined when either is not parseable. */
export function compareVersions(a: string, b: string): number | undefined {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  return pa && pb ? compareParsed(pa, pb) : undefined;
}

/** `atOrAbove <= version < below` (either bound optional). Unparseable input never matches. */
export function inVulnerableRange(version: string, range: { atOrAbove?: string | undefined; below?: string | undefined }): boolean {
  const v = parseVersion(version);
  if (!v) return false;
  if (range.atOrAbove !== undefined) {
    const lo = parseVersion(range.atOrAbove);
    if (!lo || compareParsed(v, lo) < 0) return false;
  }
  if (range.below !== undefined) {
    const hi = parseVersion(range.below);
    if (!hi || compareParsed(v, hi) >= 0) return false;
  }
  return true;
}
