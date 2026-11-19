import type { Severity } from '../config/schema.js';
import type { Confidence, FindingCategory, Signal } from '../types/findings.js';

/**
 * Explainable risk scoring.
 *
 * Every finding carries the list of signals that contributed to its score,
 * with their weights, so users can see exactly *why* something was rated the
 * way it was. Scores are a prioritisation aid, not a verdict: no combination
 * of signals labels anything as confirmed malware.
 *
 * Severity (how bad would it be if this is malicious) and confidence (how
 * sure are we about the underlying facts) are computed separately.
 */

export interface SignalDefinition {
  readonly weight: number;
  readonly description: string;
  /** Signals that indicate behaviour rather than mere change; they move findings into "suspicious". */
  readonly suspicious?: boolean;
}

export const SIGNALS = {
  'hash-changed-third-party': { weight: 25, description: 'Content of an approved third-party script changed' },
  'hash-changed-first-party': { weight: 15, description: 'Content of an approved first-party script changed' },
  'inline-changed': { weight: 18, description: 'An approved inline script changed' },
  'formatting-only': { weight: 3, description: 'Only formatting/comments changed; the parsed code is identical' },
  'new-third-party-script': { weight: 25, description: 'A third-party script that is not in the baseline started loading' },
  'new-first-party-script': { weight: 10, description: 'A first-party script that is not in the baseline started loading' },
  'new-inline-script': { weight: 12, description: 'A new inline script appeared' },
  'new-script-domain': { weight: 25, description: 'Scripts are now loaded from a domain never approved for this site' },
  'runtime-injection': { weight: 10, description: 'The script was injected at runtime by another script' },
  'sensitive-page': { weight: 15, description: 'Observed on a page marked as sensitive (payments, login or personal data)' },
  'unexpected-resource-type': { weight: 15, description: 'A resource type that is rarely needed (WebAssembly, blob/data script, service or shared worker)' },
  'type-changed': { weight: 15, description: 'The resource is now loaded as a different type' },
  'redirect-changed': { weight: 12, description: 'The script URL now redirects to a different destination' },
  'redirect-cross-host': { weight: 15, description: 'The new redirect destination is on a different host' },
  'moved-cross-domain': { weight: 20, description: 'Approved code is now served from a different domain' },
  'moved-same-domain': { weight: 3, description: 'Approved code is now served from a different URL on the same domain' },
  'sri-mismatch': { weight: 45, description: 'The Subresource Integrity attribute does not match the served content', suspicious: true },
  'content-unavailable': { weight: 10, description: 'The script content could not be captured, so changes cannot be ruled out' },
  'resource-removed': { weight: 4, description: 'An approved resource no longer loads' },
  'new-outbound-domain-third-party': { weight: 25, description: 'The page now sends requests to a third-party domain never approved for this site' },
  'new-outbound-domain-first-party': { weight: 8, description: 'The page now sends requests to a new first-party domain' },
  'new-outbound-host': { weight: 6, description: 'A new hostname under an already approved domain is contacted' },
  'data-sending-request': { weight: 10, description: 'Requests to the new destination send data (POST, beacon or similar)' },
  'blocked-destination': { weight: 15, description: 'The page tried to reach a blocked (internal or disallowed) address', suspicious: true },
  'iframe-origin-added': { weight: 18, description: 'A new iframe origin is embedded in the page' },
  'iframe-origin-removed': { weight: 3, description: 'An approved iframe origin is no longer embedded' },
  'correlated-new-destination': { weight: 20, description: 'On the same page, a new outbound destination appeared in the same scan', suspicious: true },
  'denylisted-domain': { weight: 80, description: 'The domain is on the configured denylist', suspicious: true },
  'suspicious-domain': { weight: 30, description: 'The domain matches a configured reputation warning (domains.suspicious)', suspicious: true },
  'ip-address-destination': { weight: 15, description: 'The destination is a raw IP address rather than a domain name', suspicious: true },
  'script-references-new-destination': { weight: 25, description: 'The changed script itself references the new outbound destination', suspicious: true },
} as const satisfies Record<string, SignalDefinition>;

export type SignalId = keyof typeof SIGNALS | `rule:${string}` | `new-rule:${string}` | (string & {});

export interface RiskConfig {
  readonly thresholds: { readonly low: number; readonly medium: number; readonly high: number; readonly critical: number };
  readonly weights: Readonly<Record<string, number>>;
}

export const DEFAULT_RISK_CONFIG: RiskConfig = { thresholds: { low: 15, medium: 30, high: 50, critical: 75 }, weights: {} };

/** Create a signal from the catalogue, applying configured weight overrides. */
export function signal(id: keyof typeof SIGNALS, config: RiskConfig = DEFAULT_RISK_CONFIG): Signal {
  const def = SIGNALS[id];
  return { id, description: def.description, weight: config.weights[id] ?? def.weight };
}

/** Create a custom signal (e.g. from a static-analysis rule). */
export function customSignal(id: string, description: string, weight: number, config: RiskConfig = DEFAULT_RISK_CONFIG): Signal {
  return { id, description, weight: config.weights[id] ?? weight };
}

export function isSuspiciousSignal(s: Signal): boolean {
  // Only rules of medium severity or above (weight >= 10) make a finding "suspicious";
  // low-severity indicators such as storage access are common in legitimate code.
  if (s.id.startsWith('rule:') || s.id.startsWith('new-rule:')) return s.weight >= 10;
  const def = (SIGNALS as Record<string, SignalDefinition>)[s.id];
  return def?.suspicious === true;
}

export function scoreSignals(signals: readonly Signal[]): number {
  const total = signals.reduce((sum, s) => sum + s.weight, 0);
  return Math.max(0, Math.min(100, Math.round(total)));
}

export function severityForScore(score: number, config: RiskConfig = DEFAULT_RISK_CONFIG): Severity {
  const t = config.thresholds;
  if (score >= t.critical) return 'critical';
  if (score >= t.high) return 'high';
  if (score >= t.medium) return 'medium';
  if (score >= t.low) return 'low';
  return 'info';
}

export function categoryFor(severity: Severity, signals: readonly Signal[]): FindingCategory {
  if (severity === 'high' || severity === 'critical') return 'high-priority';
  if (signals.some(isSuspiciousSignal)) return 'suspicious';
  if (severity === 'info') return 'informational';
  return 'review';
}

export interface Assessment {
  readonly score: number;
  readonly severity: Severity;
  readonly category: FindingCategory;
  readonly confidence: Confidence;
}

export function assess(signals: readonly Signal[], confidence: Confidence, config: RiskConfig = DEFAULT_RISK_CONFIG): Assessment {
  const score = scoreSignals(signals);
  const severity = severityForScore(score, config);
  return { score, severity, category: categoryFor(severity, signals), confidence };
}

/** Human-readable explanation of a score ("25 content changed + 15 sensitive page = 40"). */
export function explainScore(signals: readonly Signal[]): string {
  if (signals.length === 0) return 'no risk signals';
  const parts = signals.map((s) => `${s.weight >= 0 ? '+' : ''}${s.weight} ${s.description.charAt(0).toLowerCase()}${s.description.slice(1)}`);
  return `${parts.join('; ')} (score ${scoreSignals(signals)})`;
}
