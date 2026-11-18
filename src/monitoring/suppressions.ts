import type { Suppression } from '../config/schema.js';
import { assess, DEFAULT_RISK_CONFIG, type RiskConfig } from '../analysis/risk-scoring.js';
import type { Finding } from '../types/findings.js';
import { matchesAnyHost, matchesGlob } from '../utils/patterns.js';

/**
 * Documented false-positive suppression. Every suppression must state a
 * reason and may expire.
 *
 *  - A suppression with `rule` removes that rule's contribution (its risk
 *    signal) from matching findings and re-scores them. The underlying change
 *    is still reported if other signals remain, so suppressing a noisy rule
 *    for one vendor cannot hide an unrelated problem in the same finding.
 *  - Any other suppression (by `id`, `kind`, `resource`, `domain`, `site`)
 *    marks the whole finding as suppressed. Suppressed findings remain in
 *    reports (marked as such) but do not trigger alerts or fail builds.
 */

export interface SuppressionOutcome {
  readonly findings: Finding[];
  readonly applied: number;
  readonly expired: ReadonlyArray<{ readonly index: number; readonly reason: string; readonly expires: string }>;
}

function safeHost(url: string): string | undefined {
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
}

function isRuleSignal(signalId: string, rule: string): boolean {
  return signalId === `rule:${rule}` || signalId === `new-rule:${rule}`;
}

/** Whether the non-rule matchers of a suppression match a finding. */
export function scopeMatches(s: Suppression, f: Finding): boolean {
  if (s.id && s.id !== f.id) return false;
  if (s.kind && s.kind !== f.kind) return false;
  if (s.site && s.site !== f.site) return false;
  if (s.resource) {
    const candidates = [f.resourceUrl, f.resourceIdentity].filter((v): v is string => v !== undefined);
    if (!candidates.some((c) => matchesGlob(c, s.resource as string))) return false;
  }
  if (s.domain) {
    const hosts = [f.domain, f.resourceUrl ? safeHost(f.resourceUrl) : undefined].filter((v): v is string => typeof v === 'string' && v.length > 0);
    if (!hosts.some((h) => matchesAnyHost(h, [s.domain as string]))) return false;
  }
  return true;
}

export function applySuppressions(
  input: readonly Finding[],
  suppressions: readonly Suppression[],
  options: { now?: Date; risk?: RiskConfig } = {},
): SuppressionOutcome {
  const now = options.now ?? new Date();
  const risk = options.risk ?? DEFAULT_RISK_CONFIG;
  const expired: Array<{ index: number; reason: string; expires: string }> = [];
  const active = suppressions.filter((s, index) => {
    if (s.expires && Date.parse(s.expires) < now.getTime()) {
      expired.push({ index, reason: s.reason, expires: s.expires });
      return false;
    }
    return true;
  });

  let applied = 0;
  const findings = input.map((original) => {
    let f: Finding = original;
    for (const s of active) {
      if (!scopeMatches(s, f)) continue;
      if (s.rule) {
        const rule = s.rule;
        if (!f.signals.some((sig) => isRuleSignal(sig.id, rule))) continue;
        const signals = f.signals.filter((sig) => !isRuleSignal(sig.id, rule));
        const a = assess(signals, f.confidence, risk);
        f = {
          ...f,
          signals,
          score: a.score,
          severity: a.severity,
          category: a.category,
          evidence: [...f.evidence, { label: 'Suppressed rule', value: `${rule}: ${s.reason}` }],
        };
        applied++;
        continue;
      }
      f = { ...f, suppressed: { reason: s.reason, ...(s.expires ? { expires: s.expires } : {}) } };
      applied++;
      break;
    }
    return f;
  });
  return { findings, applied, expired };
}
