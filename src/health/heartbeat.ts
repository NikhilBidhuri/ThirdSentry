import { redactSecrets, resolveEnv } from '../alerts/env.js';
import { requireHttpsUrl, sendHttp, type FetchLike } from '../alerts/http.js';
import type { HeartbeatConfig } from '../config/schema.js';
import type { AnalysisReport } from '../types/report.js';
import { getLogger } from '../utils/logger.js';

/**
 * Heartbeat (dead-man's switch) for push monitors such as healthchecks.io,
 * Cronitor or Uptime Kuma: a plain GET after each run, to the success URL
 * after a complete run and to the failure URL otherwise. If the run never
 * happens (cron stopped, host down, crash), no ping arrives and the monitor
 * raises the alarm itself.
 *
 * Runs only in components that have network access and credentials (the
 * `alert` command, and `scan` when alerts are enabled), never in the analyzer.
 * One attempt with a short timeout, no retries. The ping URL is a secret: it
 * is never logged or included in an error message.
 */

export type HeartbeatOutcome = 'success' | 'fail' | 'skip';

export interface HeartbeatResult {
  readonly outcome: HeartbeatOutcome;
  /** A request was made. */
  readonly sent: boolean;
  /** Nothing was sent, or the monitor accepted the ping. */
  readonly ok: boolean;
  /** Human-readable, secret-free. */
  readonly detail: string;
}

export interface HeartbeatOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly fetchImpl?: FetchLike;
}

/** What a finished run reports: success only after a complete scan whose alerts were delivered. */
export function heartbeatOutcome(report: Pick<AnalysisReport, 'scanStatus'>, config: Pick<HeartbeatConfig, 'onIncomplete'>, alertFailed = false): HeartbeatOutcome {
  if (report.scanStatus === 'failed' || alertFailed) return 'fail';
  if (report.scanStatus === 'partial') return config.onIncomplete;
  return 'success';
}

function failureUrl(base: URL, failPath: string): URL {
  const url = new URL(base.toString());
  const suffix = failPath.startsWith('/') ? failPath : `/${failPath}`;
  url.pathname = `${url.pathname.replace(/\/+$/, '')}${suffix}`;
  return url;
}

function secretsOf(...urls: ReadonlyArray<string | URL | undefined>): string[] {
  const out: string[] = [];
  for (const u of urls) {
    if (!u) continue;
    out.push(u.toString());
    try {
      const url = new URL(u.toString());
      out.push(url.pathname, url.search.replace(/^\?/, ''), url.password, url.username, ...url.pathname.split('/'));
    } catch {
      // not a URL: the raw value was added above
    }
  }
  return out.filter((s) => s.length >= 6);
}

/** Send one heartbeat. Never throws: a failing monitor must not fail the run. */
export async function sendHeartbeat(config: HeartbeatConfig, outcome: HeartbeatOutcome, options: HeartbeatOptions = {}): Promise<HeartbeatResult> {
  if (outcome === 'skip') return { outcome, sent: false, ok: true, detail: 'heartbeat skipped (onIncomplete: skip)' };
  const env = options.env ?? process.env;
  const secrets: string[] = [config.url, config.failUrl ?? ''];
  try {
    const base = requireHttpsUrl(resolveEnv(config.url, env, 'health.heartbeat.url'), 'health.heartbeat.url', true);
    secrets.push(...secretsOf(base));
    let target: URL = base;
    if (outcome === 'fail') {
      if (config.failUrl) {
        target = requireHttpsUrl(resolveEnv(config.failUrl, env, 'health.heartbeat.failUrl'), 'health.heartbeat.failUrl', true);
        secrets.push(...secretsOf(target));
      } else if (config.failPath === '') {
        return { outcome, sent: false, ok: true, detail: 'no failure ping configured (failPath is empty)' };
      } else {
        target = failureUrl(base, config.failPath);
        secrets.push(...secretsOf(target));
      }
    }
    await sendHttp({ method: 'GET', url: target.toString(), timeoutMs: config.timeoutMs }, options.fetchImpl);
    return { outcome, sent: true, ok: true, detail: `heartbeat (${outcome}) sent to ${target.host}` };
  } catch (error) {
    const message = redactSecrets(error instanceof Error ? error.message : 'request failed', secrets);
    return { outcome, sent: true, ok: false, detail: `heartbeat (${outcome}) failed: ${message}` };
  }
}

/**
 * Heartbeat for a finished run, if `health.heartbeat` is configured. Logs the
 * result (warn on failure) and returns it; undefined when not configured.
 */
export async function sendRunHeartbeat(
  heartbeat: HeartbeatConfig | undefined,
  report: Pick<AnalysisReport, 'scanStatus'>,
  options: HeartbeatOptions & { alertFailed?: boolean } = {},
): Promise<HeartbeatResult | undefined> {
  if (!heartbeat) return undefined;
  const result = await sendHeartbeat(heartbeat, heartbeatOutcome(report, heartbeat, options.alertFailed === true), options);
  const log = getLogger('heartbeat');
  if (result.ok) log.info(result.detail);
  else log.warn(result.detail);
  return result;
}
