import type { Finding, Severity } from './findings.js';
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
  /** Script inventory section (present when an inventory exists or pci.requireJustification is on). */
  readonly pci?: PciReportSection;
  /** Plain-language summary for non-specialists. */
  readonly headline: string;
}
