import http, { type IncomingHttpHeaders } from 'node:http';
import https from 'node:https';
import type { LookupFunction } from 'node:net';
import { toolVersion } from '../utils/version.js';
import type { NetworkPolicy } from './network-policy.js';
import { effectivePort, validateTargetUrl } from './url-validator.js';

/**
 * Server-side HTTP client with the same SSRF protections as the browser's
 * egress proxy, used by commands that fetch URLs from Node.js (csp-lint).
 *
 *  - Every request (including each redirect hop) is validated.
 *  - DNS is resolved by the network policy, and the socket connects to the
 *    validated address via a custom `lookup`, so there is no second
 *    resolution an attacker could rebind. TLS still verifies the certificate
 *    for the original hostname (SNI is unchanged).
 *  - Redirects are followed manually, at most `maxRedirects` times.
 *  - Response bodies are capped.
 */

export interface SafeResponse {
  readonly url: string;
  readonly status: number;
  readonly headers: IncomingHttpHeaders;
  readonly rawHeaders: ReadonlyArray<[string, string]>;
  readonly body: Buffer;
  readonly truncated: boolean;
  readonly redirects: readonly string[];
}

export interface SafeFetchOptions {
  readonly timeoutMs?: number;
  readonly maxBytes?: number;
  readonly maxRedirects?: number;
  readonly headers?: Record<string, string>;
}

export class SafeFetchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SafeFetchError';
  }
}

function policyLookup(policy: NetworkPolicy, port: number): LookupFunction {
  return (hostname, options, callback) => {
    policy.resolveDestination(hostname, port).then(
      (decision) => {
        if (!decision.allowed) {
          callback(Object.assign(new Error(`Blocked by network policy: ${decision.reason}`), { code: 'ESCRIPTDRIFTBLOCKED' }), '', 0);
          return;
        }
        if ((options as { all?: boolean }).all) {
          (callback as unknown as (err: null, addresses: Array<{ address: string; family: number }>) => void)(null, [{ address: decision.address, family: decision.family }]);
        } else {
          callback(null, decision.address, decision.family);
        }
      },
      (error: unknown) => callback(error as NodeJS.ErrnoException, '', 0),
    );
  };
}

function requestOnce(url: URL, policy: NetworkPolicy, options: Required<Pick<SafeFetchOptions, 'timeoutMs' | 'maxBytes'>> & { headers: Record<string, string> }): Promise<Omit<SafeResponse, 'redirects'>> {
  return new Promise((resolve, reject) => {
    const port = effectivePort(url);
    const client = url.protocol === 'https:' ? https : http;
    const req = client.request(
      url,
      {
        method: 'GET',
        headers: { 'user-agent': `ScriptDrift/${toolVersion()} (csp-lint)`, accept: 'text/html,*/*;q=0.8', ...options.headers },
        lookup: policyLookup(policy, port),
        timeout: options.timeoutMs,
        agent: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        res.on('data', (chunk: Buffer) => {
          if (truncated) return;
          size += chunk.length;
          if (size > options.maxBytes) {
            truncated = true;
            chunks.push(chunk.subarray(0, Math.max(0, chunk.length - (size - options.maxBytes))));
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        const finish = (): void => {
          const raw: Array<[string, string]> = [];
          for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) raw.push([(res.rawHeaders[i] as string).toLowerCase(), res.rawHeaders[i + 1] as string]);
          resolve({ url: url.toString(), status: res.statusCode ?? 0, headers: res.headers, rawHeaders: raw, body: Buffer.concat(chunks), truncated });
        };
        res.on('end', finish);
        res.on('close', finish);
        res.on('error', (e) => (truncated ? finish() : reject(e)));
      },
    );
    req.on('timeout', () => req.destroy(new SafeFetchError(`Request timed out after ${options.timeoutMs}ms`)));
    req.on('error', (e: NodeJS.ErrnoException) => reject(e.code === 'ESCRIPTDRIFTBLOCKED' ? new SafeFetchError(e.message) : e));
    req.end();
  });
}

export async function safeFetch(rawUrl: string, policy: NetworkPolicy, options: SafeFetchOptions = {}): Promise<SafeResponse> {
  const maxRedirects = options.maxRedirects ?? 5;
  const opts = { timeoutMs: options.timeoutMs ?? 15_000, maxBytes: options.maxBytes ?? 2 * 1024 * 1024, headers: options.headers ?? {} };
  const redirects: string[] = [];
  let url = validateTargetUrl(rawUrl, policy);
  for (let hop = 0; ; hop++) {
    const res = await requestOnce(url, policy, opts);
    const location = res.headers.location;
    if (res.status >= 300 && res.status < 400 && location) {
      if (hop >= maxRedirects) throw new SafeFetchError(`Too many redirects (more than ${maxRedirects})`);
      redirects.push(url.toString());
      // Each redirect target is validated like a user-supplied URL (scheme, credentials, port, IP).
      url = validateTargetUrl(new URL(location, url).toString(), policy);
      continue;
    }
    return { ...res, redirects };
  }
}
