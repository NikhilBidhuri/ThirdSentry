import type { Finding, Severity } from './findings.js';
import type { PolicyReport } from '../policies/types.js';
import type { Issue, PageStatus, ScanSummary } from './index.js';

export interface SiteComparisonSummary {
  readonly name: string;
  readonly url: string;
  readonly status: PageStatus;
  readonly baseline: {
    readonly exists: boolean;
    readonly path: string;
    readonly approvedAt?: string;
    readonly sourceScanId?: string;
    readonly resources?: number;
  };
  readonly unchangedResources: number;
  readonly newResources: number;
  readonly modifiedResources: number;
  readonly removedResources: number;
  readonly newDomains: readonly string[];
  readonly pagesNotCompared: readonly string[];
  readonly findings: number;
}

export interface SiteHealthSummary {
  readonly name: string;
  readonly consecutiveFailures: number;
  readonly streakStart?: string;
  readonly lastCompleteAt?: string;
}

export interface HealthRecovery {
  readonly site: string;
  readonly failures: number;
  readonly since: string;
  readonly recoveredAt: string;
}

/** Scan health at the time of the report (see docs/monitoring.md). */
export interface ReportHealth {
  readonly sites: readonly SiteHealthSummary[];
  /** Sites that scanned completely again with this scan after an unhealthy streak. */
  readonly recoveries: readonly HealthRecovery[];
}

/** The analysis report: scan facts + comparison with baselines + findings. */
export interface AnalysisReport {
  readonly schemaVersion: 1;
  readonly kind: 'thirdsentry-report';
  readonly generatedAt: string;
  readonly toolVersion: string;
  readonly scanId: string;
  readonly scanPath: string;
  readonly scanStatus: PageStatus;
  readonly scanStartedAt: string;
  readonly scanFinishedAt: string;
  readonly scanSummary: ScanSummary;
  readonly scanIssues: readonly Issue[];
  readonly sites: readonly SiteComparisonSummary[];
  readonly findings: readonly Finding[];
  readonly findingCounts: Readonly<Record<Severity, number>>;
  readonly highestSeverity: Severity | 'none';
  readonly coverageLimitations: readonly string[];
  readonly health?: ReportHealth;
  /** Script policies (scriptPolicies): active, unused and expired, and which policy governs which script. Absent when none are configured. */
  readonly policies?: PolicyReport;
  /** Plain-language summary for non-specialists. */
  readonly headline: string;
}
