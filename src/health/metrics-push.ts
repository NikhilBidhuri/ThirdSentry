import { redactSecrets } from '../alerts/env.js';
import { requireHttpsUrl, sendHttp, type FetchLike } from '../alerts/http.js';
import { ThirdSentryError } from '../utils/errors.js';
import { ExitCode } from '../utils/exit-codes.js';

/**
 * Push the exposition text to a Prometheus Pushgateway. A batch job that ends
 * before it can be scraped is the Pushgateway's use case; the textfile
 * collector is still the recommended mode (see docs/monitoring.md). The URL
 * may contain credentials and is never logged or put in an error message.
 */

export function pushgatewayUrl(raw: string): URL {
  const url = requireHttpsUrl(raw, '--push', true);
  if (!/\/metrics\/job\//.test(url.pathname)) url.pathname = `${url.pathname.replace(/\/+$/, '')}/metrics/job/thirdsentry`;
  return url;
}

export async function pushMetrics(rawUrl: string, body: string, fetchImpl?: FetchLike): Promise<void> {
  let url: URL;
  try {
    url = pushgatewayUrl(rawUrl);
  } catch {
    throw new ThirdSentryError('--push is not a valid http(s) URL', { exitCode: ExitCode.ConfigError });
  }
  // fetch refuses URLs with credentials: send them as HTTP Basic authentication instead.
  const headers: Record<string, string> = { 'content-type': 'text/plain; version=0.0.4' };
  const clean = new URL(url.toString());
  if (url.username || url.password) {
    headers.authorization = `Basic ${Buffer.from(`${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`).toString('base64')}`;
    clean.username = '';
    clean.password = '';
  }
  try {
    // PUT replaces the whole group, so metrics of sites that were removed do not linger.
    await sendHttp({ method: 'PUT', url: clean.toString(), headers, body, timeoutMs: 10_000 }, fetchImpl);
  } catch (error) {
    const secrets = [rawUrl, url.toString(), url.password, url.username, url.pathname].filter((s) => s.length >= 6);
    throw new ThirdSentryError(`Pushgateway push failed: ${redactSecrets(error instanceof Error ? error.message : 'request failed', secrets)}`, { exitCode: ExitCode.InternalError });
  }
}
