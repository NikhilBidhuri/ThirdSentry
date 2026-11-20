import { toolVersion } from '../utils/version.js';

export type FetchLike = typeof fetch;

/** Most response bytes kept from a successful response (GitHub issue listings can be large). */
export const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
/** Most response bytes read from an error response (only a short excerpt is reported). */
const MAX_ERROR_BYTES = 4 * 1024;

export class AlertDeliveryError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly retryable = true,
  ) {
    super(message);
    this.name = 'AlertDeliveryError';
  }
}

export interface HttpRequest {
  readonly method?: string;
  readonly url: string;
  readonly headers?: Record<string, string>;
  readonly body?: string;
  readonly timeoutMs: number;
}

/**
 * Read at most `maxBytes` of a response body while streaming, then cancel the
 * rest, so a hostile or broken endpoint cannot make us buffer an unbounded body.
 */
export async function readBounded(response: Response, maxBytes: number): Promise<{ text: string; truncated: boolean }> {
  if (!response.body) return { text: '', truncated: false };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const room = maxBytes - size;
      if (value.byteLength > room) {
        chunks.push(value.subarray(0, room));
        size += room;
        truncated = true;
        break;
      }
      chunks.push(value);
      size += value.byteLength;
    }
  } catch {
    // A body that fails mid-way is reported with what was read.
  } finally {
    if (truncated) await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  return { text: new TextDecoder().decode(Buffer.concat(chunks, size)), truncated };
}

/** Send an HTTP request to an alert endpoint. Errors never include the URL (it may contain a secret). */
export async function sendHttp(request: HttpRequest, fetchImpl: FetchLike = fetch): Promise<{ status: number; text: string; truncated: boolean }> {
  let response: Response;
  const signal = AbortSignal.timeout(request.timeoutMs);
  try {
    response = await fetchImpl(request.url, {
      method: request.method ?? 'POST',
      headers: { 'user-agent': `ThirdSentry/${toolVersion()}`, ...request.headers },
      ...(request.body !== undefined ? { body: request.body } : {}),
      redirect: 'error',
      signal,
    });
  } catch (error) {
    const reason = error instanceof Error ? (error.name === 'TimeoutError' ? `timed out after ${request.timeoutMs}ms` : error.message) : 'request failed';
    throw new AlertDeliveryError(`request failed: ${reason}`);
  }
  if (!response.ok) {
    const { text } = await readBounded(response, MAX_ERROR_BYTES);
    const retryable = response.status >= 500 || response.status === 429 || response.status === 408;
    throw new AlertDeliveryError(`HTTP ${response.status}${text ? `: ${text.slice(0, 200)}` : ''}`, response.status, retryable);
  }
  const { text, truncated } = await readBounded(response, MAX_RESPONSE_BYTES);
  return { status: response.status, text, truncated };
}

export function requireHttpsUrl(raw: string, setting: string, allowHttp = false): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new AlertDeliveryError(`${setting} is not a valid URL`, undefined, false);
  }
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) {
    throw new AlertDeliveryError(`${setting} must use https://`, undefined, false);
  }
  return url;
}
