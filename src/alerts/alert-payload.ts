import { explainScore } from '../analysis/risk-scoring.js';
import type { AlertsConfig } from '../config/schema.js';
import { lastAlert, type FindingState } from '../monitoring/dedup-state.js';
import { SEVERITY_ORDER, type Evidence, type Finding, type Severity } from '../types/findings.js';
import type { AnalysisReport } from '../types/report.js';
import type { ChannelName } from './channels.js';

/**
 * What an alert contains. Deliberately compact: metadata, hashes and short
 * evidence — never script bodies or code excerpts — so that alert channels
 * (chat, e-mail, issue trackers) do not receive copies of third-party code.
 */

export interface AlertFinding {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence: string;
  readonly category: string;
  readonly site: string;
  readonly pages: readonly string[];
  readonly resourceUrl?: string;
  readonly domain?: string;
  readonly previousHash?: string | null;
  readonly currentHash?: string | null;
  readonly reason: string;
  readonly why: string;
  readonly evidence: readonly Evidence[];
  readonly recommendedAction: string;
  readonly status?: string;
}

export interface AlertPayload {
  readonly schemaVersion: 1;
  readonly kind: 'thirdsentry-alert';
  readonly generatedAt: string;
  readonly scanId: string;
  readonly scanStatus: string;
  readonly headline: string;
  readonly sites: readonly string[];
  readonly highestSeverity: Severity;
  readonly counts: Readonly<Record<Severity, number>>;
  readonly reportLocation: string;
  readonly findings: readonly AlertFinding[];
  /** Number of selected findings not listed because of maxFindingsPerAlert. */
  readonly omitted: number;
  /** Operational notice shown above the findings (e.g. alert history was reset). */
  readonly notice?: string;
  /** True for `thirdsentry alert --test` messages, which contain no real finding. */
  readonly test?: boolean;
}

/** Evidence safe to send externally: drop code excerpts from behaviour matches. */
function alertEvidence(evidence: readonly Evidence[]): Evidence[] {
  return evidence
    .filter((e) => !/^TS-[A-Z-]+ at line \d+$/.test(e.label))
    .map((e) => ({ label: e.label, value: e.value.length > 300 ? `${e.value.slice(0, 300)}…` : e.value }))
    .slice(0, 12);
}

/**
 * Convert a finding to its alert form. Tolerates findings of kinds this
 * version does not know about (and therefore possibly missing optional
 * details): every field falls back to a generic value.
 */
export function toAlertFinding(f: Finding): AlertFinding {
  const evidence = (f.evidence ?? []);
  const behaviour = evidence.filter((e) => /^TS-[A-Z-]+ at line \d+$/.test(e.label)).map((e) => e.label);
  return {
    id: f.id,
    title: f.title || f.kind || 'ThirdSentry finding',
    severity: f.severity,
    confidence: f.confidence ?? 'unknown',
    category: f.category ?? 'review',
    site: f.site ?? '',
    pages: f.pages ?? [],
    ...(f.resourceUrl ? { resourceUrl: f.resourceUrl } : {}),
    ...(f.domain ? { domain: f.domain } : {}),
    ...(f.previousHash !== undefined ? { previousHash: f.previousHash } : {}),
    ...(f.currentHash !== undefined ? { currentHash: f.currentHash } : {}),
    reason: f.reason ?? '',
    why: explainScore(f.signals ?? []),
    evidence: [...alertEvidence(evidence), ...(behaviour.length ? [{ label: 'Behaviour matches', value: behaviour.join(', ') }] : [])],
    recommendedAction: (f.recommendedAction ?? 'Review the finding in the report.').replace('<finding-id>', f.id),
    ...(f.status ? { status: f.status } : {}),
  };
}

/**
 * Choose which findings to alert on through one channel: unsuppressed, at or
 * above the threshold, and not already delivered through *this* channel
 * (unless the severity increased since that delivery or the repeat interval
 * elapsed). Delivery is tracked per channel, so a channel that failed or
 * skipped findings gets them on the next run even if another channel
 * succeeded.
 */
export function selectFindingsForAlert(
  report: AnalysisReport,
  state: FindingState,
  config: Pick<AlertsConfig, 'minSeverity' | 'repeatAfterHours'>,
  now: Date,
  channel: ChannelName,
): Finding[] {
  return report.findings.filter((f) => {
    if (f.suppressed) return false;
    if (rank(f.severity) < rank(config.minSeverity)) return false;
    const mark = lastAlert(state.findings[f.id], channel);
    if (!mark) return true;
    if (rank(f.severity) > rank(mark.severity)) return true;
    if (config.repeatAfterHours > 0) {
      return now.getTime() - Date.parse(mark.at) >= config.repeatAfterHours * 3_600_000;
    }
    return false;
  });
}

/** Severity rank; unknown values (from newer/older tools) rank as info. */
export function rank(severity: string): number {
  return SEVERITY_ORDER[severity as Severity] ?? 0;
}

export function buildAlertPayload(
  report: AnalysisReport,
  findings: readonly Finding[],
  options: { maxFindings: number; reportLocation: string; now?: Date; notice?: string; test?: boolean },
): AlertPayload {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) if (f.severity in counts) counts[f.severity]++;
  // Most severe first, so that truncation (maxFindingsPerAlert, channel limits) drops the least severe.
  const ordered = [...findings].sort((a, b) => rank(b.severity) - rank(a.severity));
  const highest = ordered[0] && rank(ordered[0].severity) > 0 ? ordered[0].severity : 'info';
  const listed = ordered.slice(0, options.maxFindings);
  return {
    schemaVersion: 1,
    kind: 'thirdsentry-alert',
    generatedAt: (options.now ?? new Date()).toISOString(),
    scanId: report.scanId,
    scanStatus: report.scanStatus,
    headline: report.headline,
    sites: [...new Set(findings.map((f) => f.site))].sort(),
    highestSeverity: highest,
    counts,
    reportLocation: options.reportLocation,
    findings: listed.map(toAlertFinding),
    omitted: findings.length - listed.length,
    ...(options.notice ? { notice: options.notice } : {}),
    ...(options.test ? { test: true } : {}),
  };
}

/** Restrict a rendered payload to the first `n` findings, counting the rest as omitted. */
export function truncatePayload(payload: AlertPayload, n: number): AlertPayload {
  if (payload.findings.length <= n) return payload;
  return { ...payload, findings: payload.findings.slice(0, n), omitted: payload.omitted + payload.findings.length - n };
}

export function subjectLine(payload: AlertPayload): string {
  if (payload.test) return '[ThirdSentry] TEST alert: delivery check (no real finding)';
  const n = payload.findings.length + payload.omitted;
  return `[ThirdSentry] ${n} finding${n === 1 ? '' : 's'} (highest: ${payload.highestSeverity}) on ${payload.sites.join(', ')}`;
}
