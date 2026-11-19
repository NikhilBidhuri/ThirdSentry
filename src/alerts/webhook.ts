import { createHmac } from 'node:crypto';
import type { AlertPayload } from './alert-payload.js';
import { requireHttpsUrl, sendHttp, type FetchLike } from './http.js';

/**
 * Generic JSON webhook. The body is the AlertPayload. When a secret is
 * configured, the request is signed:
 *
 *   X-ThirdSentry-Timestamp: <unix seconds>
 *   X-ThirdSentry-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">
 *
 * Receivers should recompute the HMAC with the shared secret, compare in
 * constant time, and reject timestamps older than a few minutes.
 */

export function signPayload(body: string, secret: string, timestamp: number): string {
  return `sha256=${createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex')}`;
}

export async function sendWebhook(
  payload: AlertPayload,
  target: { url: string; secret?: string; allowInsecureHttp: boolean },
  options: { timeoutMs: number; fetchImpl?: FetchLike; now?: Date },
): Promise<void> {
  const url = requireHttpsUrl(target.url, 'alerts.webhook.url', target.allowInsecureHttp);
  const body = JSON.stringify(payload);
  const headers: Record<string, string> = { 'content-type': 'application/json', 'x-thirdsentry-event': 'findings' };
  if (target.secret) {
    const ts = Math.floor((options.now ?? new Date()).getTime() / 1000);
    headers['x-thirdsentry-timestamp'] = String(ts);
    headers['x-thirdsentry-signature'] = signPayload(body, target.secret, ts);
  }
  await sendHttp({ url: url.toString(), headers, body, timeoutMs: options.timeoutMs }, options.fetchImpl);
}
