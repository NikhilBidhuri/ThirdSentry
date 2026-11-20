import type { AlertFinding, AlertPayload } from './alert-payload.js';
import { AlertDeliveryError, requireHttpsUrl, sendHttp, type FetchLike } from './http.js';

/**
 * PagerDuty Events API v2 integration.
 *
 * One `trigger` event per finding. The `dedup_key` is derived from the
 * finding ID, which is a content fingerprint: re-sending the same unchanged
 * finding updates the same PagerDuty alert instead of opening another one.
 * With `autoResolve`, a `resolve` event with the same key closes it.
 *
 * Events are compact: metadata, hashes and the explanation; never script
 * bodies or code excerpts (evidence is not sent at all).
 */

export const PAGERDUTY_LIMITS = {
  /** `payload.summary` (Events API v2 limit). */
  summary: 1024,
  /** `dedup_key` (Events API v2 limit). */
  dedupKey: 255,
} as const;

/** Severity mapping onto the values PagerDuty accepts. */
export const PAGERDUTY_SEVERITY: Record<string, 'critical' | 'error' | 'warning' | 'info'> = {
  critical: 'critical',
  high: 'error',
  medium: 'warning',
  low: 'info',
  info: 'info',
};

export function pagerDutySeverity(severity: string): 'critical' | 'error' | 'warning' | 'info' {
  return PAGERDUTY_SEVERITY[severity] ?? 'info';
}

/** Stable per-finding key; PagerDuty de-duplicates on it. */
export function dedupKey(findingId: string): string {
  return `thirdsentry:${findingId}`.slice(0, PAGERDUTY_LIMITS.dedupKey);
}

function clip(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function oneLine(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

function hostOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).host || undefined;
  } catch {
    return undefined;
  }
}

function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

export interface PagerDutyTarget {
  readonly routingKey: string;
  readonly apiUrl: string;
  readonly allowInsecureHttp: boolean;
  readonly maxEventsPerRun: number;
}

export function triggerEvent(f: AlertFinding, routingKey: string, reportLocation: string, scanId: string, timestamp: string, test = false): Record<string, unknown> {
  const where = f.resourceUrl ? ` (${clip(f.resourceUrl, 200)})` : '';
  const summary = clip(oneLine(`${test ? 'TEST - ' : ''}${f.severity.toUpperCase()}: ${f.title}${where} on ${f.site || 'site'}: ${f.reason}`), PAGERDUTY_LIMITS.summary);
  const component = f.domain ?? hostOf(f.resourceUrl);
  const details: Record<string, unknown> = {
    finding_id: f.id,
    confidence: f.confidence,
    category: f.category,
    site: f.site,
    pages: f.pages.slice(0, 10),
    ...(f.resourceUrl ? { resource_url: clip(f.resourceUrl, 500) } : {}),
    ...(f.previousHash !== undefined ? { previous_hash: f.previousHash } : {}),
    ...(f.currentHash !== undefined ? { current_hash: f.currentHash } : {}),
    reason: clip(f.reason, 500),
    why: clip(f.why, 500),
    next_step: clip(f.recommendedAction, 300),
    scan_id: scanId,
    report: clip(reportLocation, 500),
  };
  return {
    routing_key: routingKey,
    event_action: 'trigger',
    dedup_key: dedupKey(f.id),
    payload: {
      summary,
      source: clip(f.site || 'thirdsentry', 255),
      severity: pagerDutySeverity(f.severity),
      timestamp,
      ...(component ? { component: clip(component, 255) } : {}),
      group: clip(f.site || 'thirdsentry', 255),
      class: clip(f.category || 'finding', 255),
      custom_details: details,
    },
    client: 'ThirdSentry',
    ...(isHttpUrl(reportLocation) ? { client_url: reportLocation, links: [{ href: reportLocation, text: 'ThirdSentry report' }] } : {}),
  };
}

export function resolveEvent(findingId: string, routingKey: string): Record<string, unknown> {
  return { routing_key: routingKey, event_action: 'resolve', dedup_key: dedupKey(findingId) };
}

export interface PagerDutyOutcome {
  /** Findings whose trigger event was accepted. */
  readonly triggered: string[];
  /** Findings whose resolve event was accepted. */
  readonly resolved: string[];
  readonly error?: Error;
}

/**
 * Send trigger events for the payload's findings (at most `maxEventsPerRun`;
 * the caller builds the payload with that cap) and resolve events for
 * `resolveIds`. `send` wraps one HTTP call with the retry policy.
 *
 * A 400 means that one event is invalid, so the others are still sent; any
 * other failure (retries exhausted, 401/403, ...) stops the run, and every
 * finding not accepted stays pending.
 */
export async function sendPagerDuty(
  payload: AlertPayload,
  target: PagerDutyTarget,
  resolveIds: readonly string[],
  options: { timeoutMs: number; fetchImpl?: FetchLike },
  retry: <T>(fn: () => Promise<T>) => Promise<T>,
): Promise<PagerDutyOutcome> {
  const url = requireHttpsUrl(target.apiUrl, 'alerts.pagerduty.apiUrl', target.allowInsecureHttp).toString();
  const post = (event: Record<string, unknown>): Promise<unknown> =>
    retry(() => sendHttp({ url, headers: { 'content-type': 'application/json' }, body: JSON.stringify(event), timeoutMs: options.timeoutMs }, options.fetchImpl));
  const triggered: string[] = [];
  const resolved: string[] = [];
  const failure: { error?: Error } = {};
  const run = async (events: ReadonlyArray<{ id: string; event: Record<string, unknown> }>, done: string[]): Promise<void> => {
    for (const { id, event } of events.slice(0, target.maxEventsPerRun)) {
      try {
        await post(event);
        done.push(id);
      } catch (e) {
        failure.error ??= e instanceof Error ? e : new Error(String(e));
        if (!(e instanceof AlertDeliveryError && e.status === 400)) return;
      }
    }
  };
  await run(
    payload.findings.map((f) => ({ id: f.id, event: triggerEvent(f, target.routingKey, payload.reportLocation, payload.scanId, payload.generatedAt, payload.test === true) })),
    triggered,
  );
  if (!failure.error) await run(resolveIds.map((id) => ({ id, event: resolveEvent(id, target.routingKey) })), resolved);
  // A test alert must not leave an open incident behind.
  if (!failure.error && payload.test) {
    await run(payload.findings.map((f) => ({ id: f.id, event: resolveEvent(f.id, target.routingKey) })), []);
  }
  return { triggered, resolved, ...(failure.error ? { error: failure.error } : {}) };
}
