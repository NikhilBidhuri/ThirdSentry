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

export interface LibraryDbSummary {
  readonly source: 'bundled-seed' | 'cache';
  readonly sourceUrl?: string;
  readonly fetchedAt?: string;
  readonly sha256?: string;
  readonly ageDays?: number;
  readonly libraries: number;
  readonly advisories: number;
  readonly stale: boolean;
  readonly warnings: readonly string[];
}

export interface LibraryInventoryItem {
  readonly site: string;
  readonly name: string;
  readonly version: string;
  readonly method: 'banner' | 'code' | 'url' | 'content-hash';
  readonly confidence: 'low' | 'medium' | 'high';
  /** Resource URLs (or identities) where it was recognised. */
  readonly resources: readonly string[];
  /** Advisory ids (CVE-... or ADV-...) that affect this version. */
  readonly advisories: readonly string[];
}

export interface LibraryReport {
  readonly db: LibraryDbSummary;
  readonly inventory: readonly LibraryInventoryItem[];
}

/** PCI DSS 6.4.3 script inventory summary of one site (sensitive pages only). */
export interface PciReportSection {
  readonly requireJustification: boolean;
  readonly sites: ReadonlyArray<{
    readonly site: string;
    /** Path of the inventory file, or null when the site has none. */
    readonly inventoryFile: string | null;
    readonly sensitiveScripts: number;
    readonly authorized: number;
    readonly missingJustification: number;
    readonly reviewOverdue: number;
    readonly notApproved: number;
    readonly unmatchedEntries: number;
    readonly gaps: ReadonlyArray<{ readonly url: string; readonly status: string; readonly issues: readonly string[] }>;
  }>;
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
  /** Recognised JavaScript libraries and vulnerability database status (absent when libraries.detect is off). */
  readonly libraries?: LibraryReport;
  /** Script inventory section (present when an inventory exists or pci.requireJustification is on). */
  readonly pci?: PciReportSection;
  /** Plain-language summary for non-specialists. */
  readonly headline: string;
}
