import type { Baseline, BaselineResource } from '../baseline/baseline-schema.js';
import type { DomainPolicy, ThirdSentryConfig } from '../config/schema.js';
import { EMPTY_DOMAIN_POLICY } from '../analysis/domain-analyzer.js';
import { resourceKey } from '../discovery/resource-identity.js';
import { compareSite, type Change, type ComparisonResult } from '../monitoring/comparison-engine.js';
import type { ScriptResource, SiteResult } from '../types/index.js';
import { compilePolicy, factsFor, isExpired, matchAll, normalizeHashEntry, policyIdentity, type CompiledPolicy } from './matching.js';
import type { PolicyMatchRecord, PolicyRef } from './types.js';

/**
 * Applies `scriptPolicies` around the comparison engine, without changing it:
 *
 *  1. Scripts governed by a `path-versions` or `domain-only` policy are re-keyed to the stable
 *     identity `policy:<name>`; baseline resources that match the same policy are merged into
 *     that identity, so adopting a policy needs no re-baselining and a rotating, hash-named
 *     bundle is never a new + removed pair.
 *  2. The normal comparison runs on the re-keyed scan and baseline. Domain checks, outbound
 *     destinations, SRI, type changes and removals are untouched.
 *  3. Content changes of policy-governed scripts become `policy-accepted-update`; the finding
 *     engine still analyses behaviour against the approved version and raises findings for new
 *     security-relevant behaviour. Pinned scripts are checked against their allowed hashes.
 */

export interface PolicySiteUsage {
  readonly site: string;
  readonly entries: ReadonlyArray<{ readonly ref: PolicyRef; readonly matches: PolicyMatchRecord[]; accepted: number }>;
  readonly expired: ReadonlyArray<{ readonly ref: PolicyRef; readonly expires: string }>;
}

export interface PolicyComparison {
  /** The scan with policy identities applied (use this for baselines and findings). */
  readonly site: SiteResult;
  /** The baseline with policy identities applied. */
  readonly baseline: Baseline;
  readonly comparison: ComparisonResult;
  readonly usage: PolicySiteUsage;
}

interface PolicySet {
  readonly active: CompiledPolicy[];
  readonly expired: CompiledPolicy[];
}

/** Global and site policies in effect for a site; expired ones are separated out and never apply. */
export function policiesForSite(config: Pick<ThirdSentryConfig, 'scriptPolicies' | 'sites'>, siteName: string, now: Date): PolicySet {
  const siteCfg = config.sites.find((s) => s.name === siteName);
  const all = [
    ...(siteCfg?.scriptPolicies ?? []).map((p, i) => compilePolicy(p, siteName, i)),
    ...config.scriptPolicies.map((p, i) => compilePolicy(p, 'global', 1000 + i)),
  ];
  return { active: all.filter((p) => !isExpired(p.policy, now)), expired: all.filter((p) => isExpired(p.policy, now)) };
}

function ignoreParamsOf(config: Pick<ThirdSentryConfig, 'sites'>, siteName: string): readonly string[] {
  return config.sites.find((s) => s.name === siteName)?.ignoreQueryParams ?? [];
}

type PinVerdict = 'ok' | 'mismatch' | 'unverifiable';

function pinVerdict(r: ScriptResource, allowed: ReadonlySet<string>): PinVerdict {
  const sha = r.hashes.sha256;
  if (!sha || r.content.status !== 'captured') return 'unverifiable';
  if (allowed.has(sha)) return 'ok';
  const sri384 = r.hashes.sri384;
  if (sri384 && allowed.has(normalizeHashEntry(sri384))) return 'ok';
  if (!sri384 && [...allowed].some((h) => h.startsWith('sha384-'))) return 'unverifiable';
  return 'mismatch';
}

function mergeCounts(a: Readonly<Record<string, number>> | undefined, b: Readonly<Record<string, number>> | undefined): Record<string, number> | undefined {
  if (!a && !b) return undefined;
  const out: Record<string, number> = { ...(a ?? {}) };
  for (const [k, v] of Object.entries(b ?? {})) out[k] = Math.max(out[k] ?? 0, v);
  return out;
}

const MAX_HASHES = 100;

function remapBaseline(
  baseline: Baseline,
  set: readonly CompiledPolicy[],
  ignore: readonly string[],
  refs?: { identityRefs: Map<string, PolicyRef>; pinRefsByIdentity: Map<string, PolicyRef[]> },
): Baseline {
  const groups = new Map<string, BaselineResource>();
  const kept: BaselineResource[] = [];
  const merge = (identity: string, b: BaselineResource): void => {
    const existing = groups.get(identity);
    if (!existing) {
      groups.set(identity, { ...b, identity, approvedHashes: b.approvedHashes.slice(-MAX_HASHES) });
      return;
    }
    const hashes = [...existing.approvedHashes];
    for (const h of b.approvedHashes) {
      if (!hashes.some((x) => (x.sha256 !== null ? x.sha256 === h.sha256 : x.normalizedSha256 === h.normalizedSha256))) hashes.push(h);
    }
    const indicators = mergeCounts(existing.indicators, b.indicators);
    groups.set(identity, {
      ...existing,
      pages: [...new Set([...existing.pages, ...b.pages])].sort(),
      dynamic: existing.dynamic || b.dynamic,
      approvedHashes: hashes.slice(-MAX_HASHES),
      ...(indicators ? { indicators } : {}),
    });
  };
  for (const b of baseline.resources) {
    const facts = factsFor(b.identity, b.pages, b);
    const matches = facts ? matchAll(set, facts, ignore) : [];
    const winner = matches[0]?.policy;
    const pins = matches.filter((m) => m.policy.policy.mode === 'pin').map((m) => m.policy.ref);
    if (refs && pins.length > 0) refs.pinRefsByIdentity.set(b.identity, pins);
    if (winner && winner.policy.mode !== 'pin') {
      refs?.identityRefs.set(policyIdentity(winner.policy.name), winner.ref);
      merge(policyIdentity(winner.policy.name), b);
    } else if (b.identity.startsWith('policy:')) {
      merge(b.identity, b);
    } else {
      kept.push(b);
    }
  }
  if (groups.size === 0) return baseline;
  return { ...baseline, resources: [...kept, ...groups.values()].sort((a, b) => a.identity.localeCompare(b.identity)) };
}

/**
 * Compare a site scan with its baseline under the configured script policies.
 * Without any active policy this is exactly `compareSite`.
 */
export function compareSiteWithPolicies(
  site: SiteResult,
  baseline: Baseline,
  config: Pick<ThirdSentryConfig, 'scriptPolicies' | 'sites'>,
  options: { domains?: DomainPolicy; now?: Date } = {},
): PolicyComparison {
  const now = options.now ?? new Date();
  const set = policiesForSite(config, site.name, now);
  const domains = options.domains ?? EMPTY_DOMAIN_POLICY;
  const usage = emptyUsage(site.name, set);
  if (set.active.length === 0) return { site, baseline, comparison: compareSite(site, baseline, domains), usage };

  const prepared = prepareSite(site, set.active, ignoreParamsOf(config, site.name), usage);
  const mappedBaseline = remapBaseline(baseline, set.active, ignoreParamsOf(config, site.name), prepared);
  const comparison = compareSite(prepared.site, mappedBaseline, domains);

  const entry = (ref: PolicyRef): PolicySiteUsage['entries'][number] | undefined => usage.entries.find((e) => e.ref.name === ref.name);
  const changes: Change[] = [];
  const isContent = (c: Change): boolean => c.kind === 'resource-modified' || c.kind === 'resource-formatting-changed';
  for (const c of comparison.changes) {
    const pinnedBy = c.current ? prepared.pinned.get(c.current.key) : undefined;
    if (pinnedBy && isContent(c)) {
      // The pinned hash list decides about content: allowed hashes are accepted, anything else
      // is reported as pinned-hash-mismatch below, regardless of what the baseline approves.
      for (const ref of pinnedBy) {
        const e = entry(ref);
        if (e) e.accepted++;
      }
      continue;
    }
    const ref = c.identity ? prepared.identityRefs.get(c.identity) : undefined;
    if (ref && isContent(c)) {
      const e = entry(ref);
      if (e) e.accepted++;
      changes.push({ ...c, kind: 'policy-accepted-update', policy: ref, details: { ...c.details, policy: ref.name, mode: ref.mode } });
      continue;
    }
    const anyRef = ref ?? (c.identity ? prepared.pinRefsByIdentity.get(c.identity)?.[0] : undefined);
    changes.push(anyRef ? { ...c, policy: anyRef } : c);
  }

  for (const miss of prepared.pinFailures) {
    const b = mappedBaseline.resources.find((x) => x.identity === miss.mapped.identity);
    changes.push({
      kind: 'pinned-hash-mismatch',
      identity: miss.original.identity,
      current: miss.original,
      ...(b ? { baseline: b } : {}),
      pages: miss.original.pages,
      policy: miss.refs[0] as PolicyRef,
      details: {
        policy: miss.refs.map((r) => r.name).join(', '),
        verdict: miss.verdict,
        observedSha256: miss.original.hashes.sha256 ?? 'unavailable',
        allowedHashes: String(miss.allowedCount),
      },
    });
  }

  // Policy-governed resources keep their re-keyed identity so baselines approve the policy identity.
  return { site: prepared.site, baseline: mappedBaseline, comparison: { ...comparison, changes }, usage };
}

function emptyUsage(siteName: string, set: PolicySet): PolicySiteUsage {
  return {
    site: siteName,
    entries: set.active.map((p) => ({ ref: p.ref, matches: [] as PolicyMatchRecord[], accepted: 0 })),
    expired: set.expired.map((p) => ({ ref: p.ref, expires: p.policy.expires ?? '' })),
  };
}

interface PinFailure {
  readonly original: ScriptResource;
  readonly mapped: ScriptResource;
  readonly refs: readonly PolicyRef[];
  readonly verdict: PinVerdict;
  readonly allowedCount: number;
}

interface Prepared {
  readonly site: SiteResult;
  /** `policy:<name>` identity to policy, for re-keyed resources. */
  readonly identityRefs: Map<string, PolicyRef>;
  /** URL identity to the pin policies that cover it. */
  readonly pinRefsByIdentity: Map<string, PolicyRef[]>;
  /** Re-keyed resource key to the pin policies covering it (their hash list decides about its content). */
  readonly pinned: Map<string, PolicyRef[]>;
  readonly pinFailures: PinFailure[];
}

function prepareSite(site: SiteResult, active: readonly CompiledPolicy[], ignore: readonly string[], usage: PolicySiteUsage): Prepared {
  const identityRefs = new Map<string, PolicyRef>();
  const pinRefsByIdentity = new Map<string, PolicyRef[]>();
  const pinned = new Map<string, PolicyRef[]>();
  const pinFailures: PinFailure[] = [];
  const mappedByKey = new Map<string, ScriptResource>();
  const record = (ref: PolicyRef, r: ScriptResource, identity: string): void => {
    const e = usage.entries.find((x) => x.ref.name === ref.name);
    e?.matches.push({ site: site.name, policy: ref.name, mode: ref.mode, resource: r.originalUrl ?? r.identity, identity, sha256: r.hashes.sha256 });
  };

  for (const r of site.resources) {
    const facts = factsFor(r.identity, r.pages, r);
    const matches = facts ? matchAll(active, facts, ignore) : [];
    const winner = matches[0]?.policy;
    const remap = winner && winner.policy.mode !== 'pin' ? winner : undefined;
    const identity = remap ? policyIdentity(remap.policy.name) : r.identity;
    if (remap) identityRefs.set(identity, remap.ref);
    let mapped: ScriptResource = r;
    if (remap) {
      const key = resourceKey(identity, r.hashes.sha256);
      const existing = mappedByKey.get(key);
      if (existing) {
        mapped = { ...existing, pages: [...new Set([...existing.pages, ...r.pages])].sort(), occurrences: existing.occurrences + r.occurrences };
      } else mapped = { ...r, identity, key };
      mappedByKey.set(key, mapped);
    } else mappedByKey.set(r.key, r);
    if (remap) record(remap.ref, r, identity);

    const pins = matches.filter((m) => m.policy.policy.mode === 'pin').map((m) => m.policy);
    if (pins.length > 0) {
      pinRefsByIdentity.set(r.identity, pins.map((p) => p.ref));
      pinned.set(mapped.key, pins.map((p) => p.ref));
      const failing = pins.filter((p) => pinVerdict(r, p.allowed) !== 'ok');
      for (const p of pins) if (p !== remap) record(p.ref, r, identity);
      if (failing.length > 0) {
        const verdicts = failing.map((p) => pinVerdict(r, p.allowed));
        pinFailures.push({
          original: r,
          mapped,
          refs: failing.map((p) => p.ref),
          verdict: verdicts.includes('mismatch') ? 'mismatch' : 'unverifiable',
          allowedCount: Math.max(...failing.map((p) => p.allowed.size)),
        });
      }
    }
  }
  const resources = [...mappedByKey.values()];
  return { site: { ...site, resources }, identityRefs, pinRefsByIdentity, pinned, pinFailures };
}

/**
 * Record which policies govern a site's scripts without comparing (sites without a baseline), so
 * the report can still list active and unused policies.
 */
export function usageWithoutBaseline(site: SiteResult, config: Pick<ThirdSentryConfig, 'scriptPolicies' | 'sites'>, now: Date): PolicySiteUsage {
  const set = policiesForSite(config, site.name, now);
  const usage = emptyUsage(site.name, set);
  if (set.active.length > 0) prepareSite(site, set.active, ignoreParamsOf(config, site.name), usage);
  return usage;
}

/** The scan with policy identities applied (for creating a first baseline). */
export function applyPoliciesToSite(site: SiteResult, config: Pick<ThirdSentryConfig, 'scriptPolicies' | 'sites'>, now: Date): SiteResult {
  const set = policiesForSite(config, site.name, now);
  if (set.active.length === 0) return site;
  return prepareSite(site, set.active, ignoreParamsOf(config, site.name), emptyUsage(site.name, set)).site;
}
/** The baseline with policy identities applied (resources governed by one policy merged into `policy:<name>`). */
export function applyPoliciesToBaseline(baseline: Baseline, config: Pick<ThirdSentryConfig, 'scriptPolicies' | 'sites'>, now: Date): Baseline {
  const set = policiesForSite(config, baseline.site, now);
  return set.active.length === 0 ? baseline : remapBaseline(baseline, set.active, ignoreParamsOf(config, baseline.site));
}