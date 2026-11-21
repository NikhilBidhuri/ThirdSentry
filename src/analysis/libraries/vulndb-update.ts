import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { safeFetch, type SafeFetchOptions } from '../../security/safe-http.js';
import type { NetworkPolicy } from '../../security/network-policy.js';
import { ThirdSentryError } from '../../utils/errors.js';
import { ExitCode } from '../../utils/exit-codes.js';
import { stableStringify, writeFileAtomic } from '../../utils/fs.js';
import { DB_FILE, DB_META_FILE, DEFAULT_VULNDB_URL, MAX_DB_BYTES, parseVulnDb, vulnDbDir, type DbMeta } from './vulndb.js';

/**
 * Download and install the vulnerability database. This is the ONLY place
 * the libraries feature touches the network. It runs in the tools/alerter
 * side, never in the analyzer (which has no network), and uses the SSRF-safe
 * client: every hop (including redirects) is validated and pinned.
 *
 * The response is treated as untrusted: size-capped (a truncated download is
 * an error, never installed), parsed as JSON, validated against the strict
 * schema, compiled with the regex safeguards, and only then written
 * atomically (temp file + fsync + rename) together with its metadata.
 * A failed update leaves the previous database untouched.
 */

export interface UpdateOptions {
  readonly url?: string;
  readonly now?: Date;
  readonly maxBytes?: number;
  readonly timeoutMs?: number;
  readonly fetchOptions?: Omit<SafeFetchOptions, 'maxBytes' | 'timeoutMs'>;
}

export interface UpdateResult {
  readonly meta: DbMeta;
  readonly path: string;
  readonly skippedPatterns: number;
  readonly skippedAdvisories: number;
}

function fail(message: string, hint?: string): never {
  throw new ThirdSentryError(message, { exitCode: ExitCode.ConfigError, ...(hint ? { hint } : {}) });
}

export async function updateVulnDb(cacheDir: string, policy: NetworkPolicy, options: UpdateOptions = {}): Promise<UpdateResult> {
  const url = options.url ?? DEFAULT_VULNDB_URL;
  const maxBytes = options.maxBytes ?? MAX_DB_BYTES;
  let res;
  try {
    res = await safeFetch(url, policy, { ...options.fetchOptions, maxBytes, timeoutMs: options.timeoutMs ?? 60_000, headers: { accept: 'application/json', ...(options.fetchOptions?.headers ?? {}) } });
  } catch (error) {
    if (error instanceof ThirdSentryError) throw error;
    fail(`Could not download the vulnerability database from ${url}: ${error instanceof Error ? error.message : String(error)}`, 'Check network access. Run this command where internet egress is allowed (see docs/libraries.md).');
  }
  if (res.status !== 200) fail(`Downloading ${url} failed: HTTP ${res.status}`);
  if (res.truncated) fail(`The vulnerability database at ${url} is larger than the ${maxBytes} byte limit; nothing was installed.`);
  if (res.body.length === 0) fail(`The vulnerability database at ${url} is empty; nothing was installed.`);
  let json: unknown;
  try {
    json = JSON.parse(res.body.toString('utf8'));
  } catch {
    fail(`The response from ${url} is not valid JSON; nothing was installed.`);
  }
  let parsed;
  try {
    parsed = parseVulnDb(json);
  } catch (error) {
    const detail = error instanceof Error ? error.message.replace(/\s+/g, ' ').slice(0, 300) : 'schema violation';
    fail(`The response from ${url} is not a valid retire.js repository (jsrepository.json): ${detail}`);
  }
  if (parsed.libraryCount === 0 || parsed.advisoryCount === 0) fail(`The database at ${url} contains no libraries or advisories; nothing was installed.`);
  const sha256 = createHash('sha256').update(res.body).digest('hex');
  const meta: DbMeta = {
    sourceUrl: url,
    fetchedAt: (options.now ?? new Date()).toISOString(),
    sha256,
    bytes: res.body.length,
    libraries: parsed.libraryCount,
    advisories: parsed.advisoryCount,
  };
  const dir = vulnDbDir(cacheDir);
  const path = join(dir, DB_FILE);
  // Database first, then metadata: a reader that sees new data with old metadata
  // fails the checksum and falls back to the seed instead of trusting a mismatch.
  await writeFileAtomic(path, res.body);
  await writeFileAtomic(join(dir, DB_META_FILE), stableStringify(meta));
  return { meta, path, skippedPatterns: parsed.skippedPatterns, skippedAdvisories: parsed.skippedAdvisories };
}
