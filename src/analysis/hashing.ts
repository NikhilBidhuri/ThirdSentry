import { createHash } from 'node:crypto';

export function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sriHash(data: Uint8Array | string, algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha256'): string {
  return `${algorithm}-${createHash(algorithm).update(data).digest('base64')}`;
}

const SRI_ALGORITHMS = { sha256: 1, sha384: 2, sha512: 3 } as const;
type SriAlgorithm = keyof typeof SRI_ALGORITHMS;

/**
 * Verify a Subresource Integrity attribute against content, following the SRI
 * spec: only the strongest algorithm present is considered, and any matching
 * digest of that algorithm is accepted. Returns null when the attribute
 * contains no recognised hash.
 */
export function verifySri(integrity: string, data: Uint8Array): boolean | null {
  const entries = integrity
    .split(/\s+/)
    .map((token) => token.trim())
    .filter(Boolean)
    .map((token) => {
      const match = /^(sha256|sha384|sha512)-([A-Za-z0-9+/=_-]+)(\?.*)?$/.exec(token);
      return match ? { algorithm: match[1] as SriAlgorithm, digest: match[2] as string } : undefined;
    })
    .filter((e): e is { algorithm: SriAlgorithm; digest: string } => e !== undefined);
  if (entries.length === 0) return null;
  const strongest = Math.max(...entries.map((e) => SRI_ALGORITHMS[e.algorithm]));
  const candidates = entries.filter((e) => SRI_ALGORITHMS[e.algorithm] === strongest);
  const algorithm = candidates[0]?.algorithm as SriAlgorithm;
  const actual = createHash(algorithm).update(data).digest('base64');
  const normalise = (d: string): string => d.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  return candidates.some((c) => normalise(c.digest) === normalise(actual));
}

/** Short, human-friendly form of a hex hash for display. */
export function shortHash(hash: string | null | undefined, length = 12): string {
  return hash ? hash.slice(0, length) : 'unavailable';
}
