import { customSignal } from '../analysis/risk-scoring.js';
import { fingerprint } from '../monitoring/finding-engine.js';
import type { Finding, Severity } from '../types/findings.js';
import type { HealthPolicy, HealthState } from './health-state.js';

/**
 * The site-level `scan-unhealthy` finding.
 *
 * It differs from the per-page `page-failed` / `coverage-degraded` findings:
 * those say "this page was not scanned completely in this scan" and appear
 * (and disappear) with every scan; `scan-unhealthy` says "scanning this site
 * has been broken for N scans in a row" and is raised only once the streak
 * reaches `health.failureThreshold`.
 *
 * ID: site + start of the streak. The same outage keeps the same ID, so each
 * channel alerts once; a later outage has a new streak start and a new ID.
 * Severity is `high` at the threshold and `critical` at three times the
 * threshold; the increase re-alerts (the alert state re-sends on escalation).
 */

export const ESCALATION_FACTOR = 3;

export function unhealthySeverity(failures: number, policy: HealthPolicy): Severity {
  return failures >= policy.failureThreshold * ESCALATION_FACTOR ? 'critical' : 'high';
}

export function scanUnhealthyId(site: string, streakStart: string): string {
  return fingerprint([site, 'scan-unhealthy', streakStart]);
}

export function buildHealthFindings(state: HealthState, siteNames: readonly string[], policy: HealthPolicy, now: Date): Finding[] {
  const findings: Finding[] = [];
  for (const name of siteNames) {
    const h = state.sites[name];
    if (!h || !h.streakStart || h.consecutiveFailures < policy.failureThreshold) continue;
    const severity = unhealthySeverity(h.consecutiveFailures, policy);
    const weight = severity === 'critical' ? 80 : 60;
    findings.push({
      id: scanUnhealthyId(name, h.streakStart),
      kind: 'scan-unhealthy',
      title: `Scanning of ${name} has failed ${h.consecutiveFailures} times in a row`,
      site: name,
      pages: [],
      detectedAt: now.toISOString(),
      severity,
      confidence: 'high',
      category: 'high-priority',
      score: weight,
      signals: [
        customSignal(
          'scan-unhealthy',
          `The last ${h.consecutiveFailures} scans of this site were ${policy.countIncomplete ? 'failed or incomplete' : 'failed'} (threshold ${policy.failureThreshold}); script changes cannot be detected while this lasts`,
          weight,
        ),
      ],
      reason: `The last ${h.consecutiveFailures} scans of ${name} did not complete (since ${h.streakStart}), so changes to its third-party scripts are not being checked. An attacker can also cause this on purpose by serving scanners an error page.`,
      evidence: [
        { label: 'Failure streak started', value: h.streakStart },
        { label: 'Consecutive failed scans', value: String(h.consecutiveFailures) },
        ...(h.lastError ? [{ label: 'Last error', value: h.lastError }] : []),
        { label: 'Last complete scan', value: h.lastCompleteAt ?? 'never' },
      ],
      recommendedAction:
        'Check that the site is reachable from the scanner, the scan limits (limits.*) and the scanner host (browser, memory, egress proxy). Run "thirdsentry status" for details. The alert is sent once per outage and again if the outage lasts three times the threshold.',
    });
  }
  return findings;
}
