import { signal, DEFAULT_RISK_CONFIG, type RiskConfig } from '../analysis/risk-scoring.js';
import type { Change } from '../monitoring/comparison-engine.js';
import type { Confidence, Evidence, Finding, Signal } from '../types/findings.js';
import type { PolicyRef } from './types.js';

/**
 * Finding wording and scoring for script policies. Called from the finding engine so that all
 * policy-specific behaviour stays in src/policies.
 */

export interface PolicyTemplate {
  title: string;
  reason: string;
  action: string;
  signals: Signal[];
  confidence: Confidence;
}

/** Template for a content change that a path-versions / domain-only policy accepts. */
export function policyUpdateTemplate(c: Change, label: string, risk: RiskConfig = DEFAULT_RISK_CONFIG): PolicyTemplate {
  const name = c.policy?.name ?? c.details.policy ?? 'unknown';
  return {
    title: `Script updated under policy "${name}"`,
    reason: `${label} has new content. Script policy "${name}" (${c.details.mode ?? c.policy?.mode ?? 'path-versions'}) accepts new versions of this script, so the update itself is not a finding. The new code was compared with the approved version and introduces no new security-relevant behaviour.`,
    action: 'No action needed. Approve the current version to refresh the behaviour reference: thirdsentry baseline --approve <finding-id>.',
    signals: [signal('policy-accepted-update', risk)],
    confidence: 'high',
  };
}

/**
 * Behaviour signals that matter for a policy-accepted update: behaviour that is new (not merely
 * more occurrences of low-risk behaviour that every release changes), behaviour of medium
 * severity or above, and "could not be analysed". Everything else is the routine noise a policy exists to remove.
 */
export function significantPolicyBehaviour(behaviour: { signals: Signal[]; evidence: Evidence[] }): { signals: Signal[]; evidence: Evidence[] } {
  const signals = behaviour.signals.filter((s) => {
    if (s.id === 'analysis-regression' || s.id === 'analysis-unavailable') return true;
    if (s.id.startsWith('rule:')) return true;
    if (s.id.startsWith('new-rule:')) return s.description.startsWith('New behaviour') || s.weight >= 10;
    return false;
  });
  const kept = new Set(signals.map((s) => s.id.replace(/^(new-)?rule:/, '')));
  const evidence = behaviour.evidence.filter((e) => e.label === 'Analysis unavailable' || [...kept].some((id) => e.label.startsWith(`${id} `)));
  return { signals, evidence };
}

/**
 * A policy-accepted update that carries security-relevant signals is scored like the ordinary
 * modified-script finding it would be without the policy (same hash-change weight), so a policy
 * reduces noise but never lowers the severity of suspicious new behaviour.
 */
export function escalatePolicyUpdate(t: PolicyTemplate, c: Change, sensitive: boolean, risk: RiskConfig = DEFAULT_RISK_CONFIG): void {
  if (!t.signals.some((s) => s.id !== 'policy-accepted-update')) return;
  const name = c.policy?.name ?? 'unknown';
  const third = (c.current?.party ?? c.baseline?.party) === 'third-party';
  const head: Signal[] = [t.signals[0] as Signal, third ? signal('hash-changed-third-party', risk) : signal('hash-changed-first-party', risk)];
  if (sensitive) head.push(signal('sensitive-page', risk));
  t.signals = [...head, ...t.signals.slice(1)];
  t.title = `Script updated under policy "${name}" with new behaviour`;
  t.reason = `${t.reason.split(' The new code was compared')[0] ?? ''} The policy accepts new versions, but the new code does something the approved version did not (see the signals and evidence). Policies never hide new security-relevant behaviour.`;
  t.action = 'Compare the new version with the approved one (thirdsentry diff), confirm the change with the vendor, and approve it with "thirdsentry baseline --approve <finding-id>" only if it is expected.';
}

export function pinMismatchTemplate(c: Change, label: string, sensitiveSignals: Signal[], risk: RiskConfig = DEFAULT_RISK_CONFIG): PolicyTemplate {
  const names = c.details.policy ?? c.policy?.name ?? 'unknown';
  const unverifiable = c.details.verdict === 'unverifiable';
  return {
    title: unverifiable ? 'Pinned script could not be verified against its allowed hashes' : 'Pinned script does not match its allowed hashes',
    reason: unverifiable
      ? `${label} is pinned by policy "${names}", but its content could not be captured completely (or hashed in the form the pin uses), so ThirdSentry cannot show that it is one of the ${c.details.allowedHashes ?? 'allowed'} pinned version(s).`
      : `${label} is pinned by policy "${names}" to ${c.details.allowedHashes ?? 'a fixed list of'} hash(es), but the content served has SHA-256 ${c.details.observedSha256 ?? 'unknown'}. Pins are enforced regardless of baseline approval.`,
    action:
      'Treat this as an unreviewed change to a script that must not change silently: check the vendor\'s release notes and compare the code (thirdsentry diff). If the new version is legitimate, add its hash to the policy\'s "hashes" in thirdsentry.yml after review; approving it in the baseline does not clear this finding.',
    signals: [signal('pinned-hash-mismatch', risk), ...sensitiveSignals],
    confidence: unverifiable ? 'medium' : 'high',
  };
}

/** Evidence line naming the policy. */
export function policyEvidence(policy: PolicyRef | undefined): Evidence[] {
  if (!policy) return [];
  return [{ label: 'Policy', value: `${policy.name} (${policy.mode}, ${policy.scope}${policy.owner ? `, owner ${policy.owner}` : ''}): ${policy.reason}`.slice(0, 600) }];
}

export function policyReasonSuffix(policy: PolicyRef | undefined, reason: string): string {
  if (!policy || reason.includes(`"${policy.name}"`)) return reason;
  return `${reason} [Script policy "${policy.name}" (${policy.mode}) governs this script.]`;
}

/**
 * domain-only policies track only where scripts load from: a content change without new
 * behaviour (score 0) is not reported at all.
 */
export function isSilentPolicyFinding(f: Pick<Finding, 'kind' | 'score' | 'policy'>): boolean {
  return f.kind === 'policy-accepted-update' && f.policy?.mode === 'domain-only' && f.score === 0;
}
