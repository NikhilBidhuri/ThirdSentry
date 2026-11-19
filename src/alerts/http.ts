import { toolVersion } from '../utils/version.js';

export type FetchLike = typeof fetch;

const MAX_RESPONSE_CHARS = 10 * 1024 * 1024;

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

/** Send an HTTP request to an alert endpoint. Errors never include the URL (it may contain a secret). */
export async function sendHttp(request: HttpRequest, fetchImpl: FetchLike = fetch): Promise<{ status: number; text: string }> {
  let response: Response;
  try {
    response = await fetchImpl(request.url, {
      method: request.method ?? 'POST',
      headers: { 'user-agent': `ThirdSentry/${toolVersion()}`, ...request.headers },
      ...(request.body !== undefined ? { body: request.body } : {}),
      redirect: 'error',
      signal: AbortSignal.timeout(request.timeoutMs),
    });
  } catch (error) {
    const reason = error instanceof Error ? (error.name === 'TimeoutError' ? `timed out after ${request.timeoutMs}ms` : error.message) : 'request failed';
    throw new AlertDeliveryError(`request failed: ${reason}`);
  }
  // Successful bodies are kept (GitHub issue listings can be large) but bounded.
  const text = (await response.text().catch(() => '')).slice(0, MAX_RESPONSE_CHARS);
  if (!response.ok) {
    const retryable = response.status >= 500 || response.status === 429;
    throw new AlertDeliveryError(`HTTP ${response.status}${text ? `: ${text.slice(0, 200)}` : ''}`, response.status, retryable);
  }
  return { status: response.status, text };
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
