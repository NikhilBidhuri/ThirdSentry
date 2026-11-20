import type { Severity } from '../config/schema.js';
import type { PolicyRef } from '../policies/types.js';
import type { Party, ResourceType } from './index.js';

export type { Severity } from '../config/schema.js';

export type Confidence = 'low' | 'medium' | 'high';

/**
 * How the finding should be treated by a human:
 *  - informational:  no action required, recorded for visibility
 *  - review:         an expected-looking change that still needs a human to approve it
 *  - suspicious:     behaviour indicators make this change worth investigating
 *  - high-priority:  investigate now
 */
export type FindingCategory = 'informational' | 'review' | 'suspicious' | 'high-priority';

export type ChangeKind =
  | 'resource-added'
  | 'resource-removed'
  | 'resource-modified'
  | 'resource-formatting-changed'
  | 'resource-moved'
  | 'resource-type-changed'
  | 'redirect-changed'
  | 'content-unavailable'
  | 'sri-mismatch'
  | 'new-script-domain'
  | 'new-outbound-domain'
  | 'new-outbound-host'
  | 'denylisted-domain'
  | 'iframe-origin-added'
  | 'iframe-origin-removed'
  | 'page-failed'
  | 'coverage-degraded'
  | 'policy-accepted-update'
  | 'pinned-hash-mismatch';

/** A single contribution to a finding's risk score, shown to users verbatim. */
export interface Signal {
  readonly id: string;
  readonly description: string;
  readonly weight: number;
}

export interface Evidence {
  readonly label: string;
  readonly value: string;
}

export interface Finding {
  /** Stable fingerprint: identical for the same change of the same resource across scans. */
  readonly id: string;
  readonly kind: ChangeKind;
  readonly title: string;
  readonly site: string;
  readonly page?: string;
  readonly pages: readonly string[];
  readonly resourceIdentity?: string;
  readonly resourceUrl?: string;
  readonly resourceType?: ResourceType;
  readonly party?: Party;
  readonly domain?: string;
  readonly previousHash?: string | null;
  readonly currentHash?: string | null;
  readonly detectedAt: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly category: FindingCategory;
  readonly score: number;
  readonly signals: readonly Signal[];
  readonly reason: string;
  readonly evidence: readonly Evidence[];
  readonly recommendedAction: string;
  /** The script policy (scriptPolicies) that governs the affected resource, if any. */
  readonly policy?: PolicyRef;
  /** Rule metadata for behaviour-indicator findings. */
  readonly ruleId?: string;
  /** Set when a configured suppression matched. Suppressed findings are reported but do not alert or fail builds. */
  suppressed?: { readonly reason: string; readonly expires?: string };
  /** `new` the first time this fingerprint is seen, `recurring` afterwards. */
  status?: 'new' | 'recurring';
}

export const SEVERITY_ORDER: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function severityAtLeast(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}
