import type { ThirdSentryConfig } from '../config/schema.js';
import type { Finding } from '../types/findings.js';
import type { PolicySiteUsage } from './apply.js';
import { isExpired } from './matching.js';
import type { PolicyMatchRecord, PolicyReport, PolicyReportEntry } from './types.js';

const MAX_MATCHES = 200;

/**
 * Policy section of the analysis report: every configured policy is either active (it governed at
 * least one script in this scan), unused (it matched nothing: a candidate for removal, or a
 * mistyped matcher) or expired (no longer applied). Returns undefined when no policy is configured.
 */
export function buildPolicyReport(
  config: Pick<ThirdSentryConfig, 'scriptPolicies' | 'sites'>,
  usages: readonly PolicySiteUsage[],
  findings: readonly Finding[],
  now: Date,
): PolicyReport | undefined {
  const scanned = new Set(usages.map((u) => u.site));
  const declared: Array<{ policy: ThirdSentryConfig['scriptPolicies'][number]; scope: string }> = [
    ...config.scriptPolicies.map((policy) => ({ policy, scope: 'global' })),
    ...config.sites.filter((s) => scanned.has(s.name)).flatMap((s) => s.scriptPolicies.map((policy) => ({ policy, scope: s.name }))),
  ];
  if (declared.length === 0 || usages.length === 0) return undefined;

  const entries: PolicyReportEntry[] = [];
  const matches: PolicyMatchRecord[] = [];
  for (const { policy, scope } of declared) {
    const forPolicy = usages.filter((u) => scope === 'global' || u.site === scope);
    const used = forPolicy.flatMap((u) => u.entries.filter((e) => e.ref.name === policy.name && e.ref.scope === scope));
    const matched = used.reduce((n, e) => n + e.matches.length, 0);
    const accepted = used.reduce((n, e) => n + e.accepted, 0);
    const count = findings.filter((f) => f.policy?.name === policy.name && f.policy.scope === scope).length;
    const expired = isExpired(policy, now);
    for (const e of used) matches.push(...e.matches);
    entries.push({
      name: policy.name,
      mode: policy.mode,
      scope,
      reason: policy.reason,
      ...(policy.owner ? { owner: policy.owner } : {}),
      ...(policy.expires ? { expires: policy.expires } : {}),
      status: expired ? 'expired' : matched > 0 ? 'active' : 'unused',
      matchedResources: matched,
      acceptedUpdates: accepted,
      findings: count,
      sites: [...new Set(used.filter((e) => e.matches.length > 0).flatMap((e) => e.matches.map((m) => m.site)))].sort(),
    });
  }
  return {
    active: entries.filter((e) => e.status === 'active'),
    unused: entries.filter((e) => e.status === 'unused'),
    expired: entries.filter((e) => e.status === 'expired'),
    matches: matches.slice(0, MAX_MATCHES),
  };
}

/** Plain-text lines for terminal output (`thirdsentry diff`). */
export function formatPolicyReport(report: PolicyReport): string[] {
  const lines: string[] = [];
  const line = (e: PolicyReportEntry): string =>
    `  ${e.name} [${e.mode}, ${e.scope}] ${e.matchedResources} script(s), ${e.acceptedUpdates} accepted update(s), ${e.findings} finding(s)${e.owner ? `, owner ${e.owner}` : ''}${e.expires ? `, expires ${e.expires}` : ''}`;
  if (report.active.length > 0) lines.push(`Active script policies (${report.active.length}):`, ...report.active.map(line));
  if (report.unused.length > 0) lines.push(`Unused script policies, matched no script in this scan (${report.unused.length}):`, ...report.unused.map(line));
  if (report.expired.length > 0) lines.push(`Expired script policies, no longer applied (${report.expired.length}):`, ...report.expired.map(line));
  if (report.matches.length > 0) {
    lines.push('Policy matches:');
    for (const m of report.matches.slice(0, 50)) lines.push(`  ${m.resource}  ->  policy ${m.policy} (${m.mode})${m.identity.startsWith('policy:') ? `, tracked as ${m.identity}` : ''}`);
    if (report.matches.length > 50) lines.push(`  ... and ${report.matches.length - 50} more (see the JSON report)`);
  }
  return lines;
}
