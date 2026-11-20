import type { PolicyMode } from './schema.js';

/** Reference to a policy, carried by changes, findings and report entries (explainability). */
export interface PolicyRef {
  readonly name: string;
  readonly mode: PolicyMode;
  /** `global` or the site name that declares the policy. */
  readonly scope: string;
  readonly reason: string;
  readonly owner?: string;
}

export interface PolicyMatchRecord {
  readonly site: string;
  readonly policy: string;
  readonly mode: PolicyMode;
  /** Requested URL (or identity) of the matched script. */
  readonly resource: string;
  /** Identity the script is tracked under (`policy:<name>` for path-versions and domain-only). */
  readonly identity: string;
  readonly sha256: string | null;
}

export interface PolicyReportEntry extends PolicyRef {
  readonly expires?: string;
  readonly status: 'active' | 'unused' | 'expired';
  /** Scripts seen in the scan that this policy governed. */
  readonly matchedResources: number;
  /** Content changes accepted by the policy (path-versions / domain-only) or pinned hashes that matched. */
  readonly acceptedUpdates: number;
  /** Findings that name this policy (including pin mismatches and behaviour alerts). */
  readonly findings: number;
  readonly sites: readonly string[];
}

export interface PolicyReport {
  readonly active: readonly PolicyReportEntry[];
  readonly unused: readonly PolicyReportEntry[];
  readonly expired: readonly PolicyReportEntry[];
  /** Which policy governs which script (capped). */
  readonly matches: readonly PolicyMatchRecord[];
}
