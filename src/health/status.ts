import type { Severity } from '../types/findings.js';
import type { AnalysisReport } from '../types/report.js';
import type { HealthPolicy, HealthState } from './health-state.js';

/**
 * Health summary behind `thirdsentry status`.
 *
 * Exit codes (also in docs/monitoring.md):
 *   0  every selected site is healthy or merely degraded, alert channels work
 *   1  at least one site is unhealthy (failure streak at the threshold, or the
 *      last scan is older than --max-age) or an alert channel keeps failing
 *   3  no scan has been recorded yet for a selected site (nothing to judge)
 * (2 is the usual configuration/usage error.)
 */

export type SiteState = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';

export interface SiteStatus {
  readonly name: string;
  readonly state: SiteState;
  readonly reasons: readonly string[];
  readonly lastScanAt?: string;
  readonly lastCompleteAt?: string;
  readonly lastStatus?: 'complete' | 'partial' | 'failed';
  readonly consecutiveFailures: number;
  readonly streakStart?: string;
  readonly lastError?: string;
  readonly openFindings: Readonly<Record<Severity, number>>;
  readonly baselinePresent: boolean;
}

export interface ChannelStatus {
  readonly channel: string;
  readonly state: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  readonly lastAttemptAt?: string;
  readonly lastSuccessAt?: string;
  readonly consecutiveFailures: number;
  readonly lastError?: string;
}

export interface StatusSummary {
  readonly overall: 'healthy' | 'unhealthy' | 'unknown';
  readonly exitCode: 0 | 1 | 3;
  readonly generatedAt: string;
  readonly sites: readonly SiteStatus[];
  readonly channels: readonly ChannelStatus[];
}

export interface StatusInput {
  readonly now: Date;
  readonly sites: readonly string[];
  readonly health: HealthState;
  readonly report?: AnalysisReport;
  readonly baselinePresent: Readonly<Record<string, boolean>>;
  readonly enabledChannels: readonly string[];
  readonly policy: HealthPolicy;
  /** Treat a site whose last scan ended longer ago than this as unhealthy. */
  readonly maxAgeHours?: number;
}

function emptyCounts(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

export function computeStatus(input: StatusInput): StatusSummary {
  const sites: SiteStatus[] = input.sites.map((name) => {
    const h = input.health.sites[name];
    const openFindings = emptyCounts();
    for (const f of input.report?.findings ?? []) if (f.site === name && !f.suppressed) openFindings[f.severity]++;
    const baselinePresent = input.baselinePresent[name] === true;
    const base = { name, openFindings, baselinePresent };
    if (!h) return { ...base, state: 'unknown' as const, reasons: ['no scan recorded yet'], consecutiveFailures: 0 };
    const reasons: string[] = [];
    let state: SiteState = 'healthy';
    if (h.consecutiveFailures >= input.policy.failureThreshold) {
      state = 'unhealthy';
      reasons.push(`${h.consecutiveFailures} consecutive failed scans (threshold ${input.policy.failureThreshold})`);
    } else if (h.consecutiveFailures > 0) {
      state = 'degraded';
      reasons.push(`${h.consecutiveFailures} consecutive failed scan(s)`);
    } else if (h.lastStatus !== 'complete') {
      state = 'degraded';
      reasons.push(`last scan was ${h.lastStatus}`);
    }
    if (input.maxAgeHours !== undefined) {
      const ageHours = (input.now.getTime() - Date.parse(h.lastScanAt)) / 3_600_000;
      if (ageHours > input.maxAgeHours) {
        state = 'unhealthy';
        reasons.push(`last scan finished ${Math.floor(ageHours)}h ago (max ${input.maxAgeHours}h)`);
      }
    }
    if (!baselinePresent && state === 'healthy') {
      state = 'degraded';
      reasons.push('no approved baseline');
    }
    return {
      ...base,
      state,
      reasons,
      lastScanAt: h.lastScanAt,
      ...(h.lastCompleteAt ? { lastCompleteAt: h.lastCompleteAt } : {}),
      lastStatus: h.lastStatus,
      consecutiveFailures: h.consecutiveFailures,
      ...(h.streakStart ? { streakStart: h.streakStart } : {}),
      ...(h.lastError ? { lastError: h.lastError } : {}),
    };
  });
  const channels: ChannelStatus[] = input.enabledChannels.map((channel) => {
    const h = input.health.alerts[channel];
    if (!h) return { channel, state: 'unknown' as const, consecutiveFailures: 0 };
    const state = h.consecutiveFailures >= input.policy.failureThreshold ? 'unhealthy' : h.consecutiveFailures > 0 ? 'degraded' : 'healthy';
    return {
      channel,
      state,
      lastAttemptAt: h.lastAttemptAt,
      ...(h.lastSuccessAt ? { lastSuccessAt: h.lastSuccessAt } : {}),
      consecutiveFailures: h.consecutiveFailures,
      ...(h.lastError ? { lastError: h.lastError } : {}),
    };
  });
  const unhealthy = sites.some((s) => s.state === 'unhealthy') || channels.some((c) => c.state === 'unhealthy');
  const unknown = sites.some((s) => s.state === 'unknown');
  const overall = unhealthy ? 'unhealthy' : unknown ? 'unknown' : 'healthy';
  return { overall, exitCode: unhealthy ? 1 : unknown ? 3 : 0, generatedAt: input.now.toISOString(), sites, channels };
}
