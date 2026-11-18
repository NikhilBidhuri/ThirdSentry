import { explainScore } from '../analysis/risk-scoring.js';
import type { AlertsConfig } from '../config/schema.js';
import type { FindingState } from '../monitoring/dedup-state.js';
import { SEVERITY_ORDER, type Evidence, type Finding, type Severity } from '../types/findings.js';
import type { AnalysisReport } from '../types/report.js';

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
  readonly kind: 'scriptdrift-alert';
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
}

/** Evidence safe to send externally: drop code excerpts from behaviour matches. */
function alertEvidence(evidence: readonly Evidence[]): Evidence[] {
  return evidence
    .filter((e) => !/^SD-[A-Z-]+ at line \d+$/.test(e.label))
    .map((e) => ({ label: e.label, value: e.value.length > 300 ? `${e.value.slice(0, 300)}…` : e.value }))
    .slice(0, 12);
}

export function toAlertFinding(f: Finding): AlertFinding {
  const behaviour = f.evidence.filter((e) => /^SD-[A-Z-]+ at line \d+$/.test(e.label)).map((e) => e.label);
  return {
    id: f.id,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    category: f.category,
    site: f.site,
    pages: f.pages,
    ...(f.resourceUrl ? { resourceUrl: f.resourceUrl } : {}),
    ...(f.domain ? { domain: f.domain } : {}),
    ...(f.previousHash !== undefined ? { previousHash: f.previousHash } : {}),
    ...(f.currentHash !== undefined ? { currentHash: f.currentHash } : {}),
    reason: f.reason,
    why: explainScore(f.signals),
    evidence: [...alertEvidence(f.evidence), ...(behaviour.length ? [{ label: 'Behaviour matches', value: behaviour.join(', ') }] : [])],
    recommendedAction: f.recommendedAction.replace('<finding-id>', f.id),
    ...(f.status ? { status: f.status } : {}),
  };
}

/**
 * Choose which findings to alert on: unsuppressed, at or above the severity
 * threshold, and not already alerted (unless the severity increased or the
 * repeat interval elapsed).
 */
export function selectFindingsForAlert(
  report: AnalysisReport,
  state: FindingState,
  config: Pick<AlertsConfig, 'minSeverity' | 'repeatAfterHours'>,
  now: Date = new Date(),
): Finding[] {
  return report.findings.filter((f) => {
    if (f.suppressed) return false;
    if (SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[config.minSeverity]) return false;
    const entry = state.findings[f.id];
    if (!entry?.lastAlertedAt) return true;
    const previous = entry.lastAlertedSeverity as Severity | undefined;
    if (previous && SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[previous]) return true;
    if (config.repeatAfterHours > 0) {
      return now.getTime() - Date.parse(entry.lastAlertedAt) >= config.repeatAfterHours * 3_600_000;
    }
    return false;
  });
}

export function buildAlertPayload(report: AnalysisReport, findings: readonly Finding[], options: { maxFindings: number; reportLocation: string; now?: Date }): AlertPayload {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) counts[f.severity]++;
  const highest = findings.reduce<Severity>((h, f) => (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[h] ? f.severity : h), 'info');
  const listed = findings.slice(0, options.maxFindings);
  return {
    schemaVersion: 1,
    kind: 'scriptdrift-alert',
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
  };
}

/** Restrict a payload to findings at or above a channel-specific threshold. */
export function filterPayload(payload: AlertPayload, minSeverity: Severity | undefined): AlertPayload | undefined {
  if (!minSeverity) return payload;
  const findings = payload.findings.filter((f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[minSeverity]);
  if (findings.length === 0) return undefined;
  return { ...payload, findings };
}

export function subjectLine(payload: AlertPayload): string {
  const n = payload.findings.length + payload.omitted;
  return `[ScriptDrift] ${n} finding${n === 1 ? '' : 's'} (highest: ${payload.highestSeverity}) on ${payload.sites.join(', ')}`;
}
