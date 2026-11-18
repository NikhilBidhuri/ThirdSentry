import { NORMALIZER_VERSION } from '../analysis/normalizer.js';
import { baselinePath, type StoragePaths } from '../storage/paths.js';
import type { ScriptResource, SiteResult } from '../types/index.js';
import { pathExists, readJsonFile, writeJsonAtomic } from '../utils/fs.js';
import { BASELINE_SCHEMA_VERSION, type ApprovedHash, type Approval, type Baseline, type BaselineResource } from './baseline-schema.js';
import { validateBaseline } from './baseline-validator.js';

/**
 * Baseline management. Baselines are only ever written by the explicit
 * `scriptdrift baseline` command (never by scans), and every write records an
 * approval entry for auditability.
 */

const MAX_APPROVAL_HISTORY = 100;

export async function loadBaseline(paths: StoragePaths, site: string): Promise<Baseline | undefined> {
  const path = baselinePath(paths, site);
  if (!(await pathExists(path))) return undefined;
  return validateBaseline(await readJsonFile(path, 256 * 1024 * 1024), site, path);
}

export async function saveBaseline(paths: StoragePaths, baseline: Baseline): Promise<string> {
  const path = baselinePath(paths, baseline.site);
  validateBaseline(baseline, baseline.site, path);
  await writeJsonAtomic(path, baseline);
  return path;
}

function approvedHashFor(r: ScriptResource, at: string): ApprovedHash {
  return {
    sha256: r.hashes.sha256,
    normalizedSha256: r.hashes.normalizedSha256,
    normalizerVersion: r.hashes.normalizedSha256 ? (r.hashes.normalizerVersion ?? NORMALIZER_VERSION) : null,
    ...(r.size !== undefined ? { size: r.size } : {}),
    approvedAt: at,
  };
}

function sameHash(a: ApprovedHash, b: ApprovedHash): boolean {
  return a.sha256 === b.sha256 && (a.sha256 !== null || a.normalizedSha256 === b.normalizedSha256);
}

function addHash(list: ApprovedHash[], hash: ApprovedHash): ApprovedHash[] {
  return list.some((h) => sameHash(h, hash)) ? list : [...list, hash];
}

/** Collapse scan resources (one per identity+hash) into baseline resources (one per identity). */
export function baselineResourcesFrom(resources: readonly ScriptResource[], at: string): BaselineResource[] {
  const byIdentity = new Map<string, BaselineResource>();
  for (const r of resources) {
    const existing = byIdentity.get(r.identity);
    if (existing) {
      byIdentity.set(r.identity, {
        ...existing,
        pages: [...new Set([...existing.pages, ...r.pages])].sort(),
        dynamic: existing.dynamic || r.dynamic,
        approvedHashes: addHash(existing.approvedHashes, approvedHashFor(r, at)),
        ...(r.indicators?.analyzed ? { indicators: mergeIndicators(existing.indicators, r.indicators.counts) } : {}),
      });
      continue;
    }
    byIdentity.set(r.identity, {
      identity: r.identity,
      type: r.type,
      party: r.party,
      pages: [...r.pages].sort(),
      ...(r.originalUrl ? { originalUrl: r.originalUrl } : {}),
      ...(r.finalUrl ? { finalUrl: r.finalUrl } : {}),
      ...(r.hostname ? { hostname: r.hostname } : {}),
      ...(r.registrableDomain ? { registrableDomain: r.registrableDomain } : {}),
      frameContext: r.frameContext,
      dynamic: r.dynamic,
      approvedHashes: [approvedHashFor(r, at)],
      ...(r.indicators?.analyzed ? { indicators: { ...r.indicators.counts } } : {}),
    });
  }
  return [...byIdentity.values()].sort((a, b) => a.identity.localeCompare(b.identity));
}

function mergeIndicators(a: Readonly<Record<string, number>> | undefined, b: Readonly<Record<string, number>>): Record<string, number> {
  const out: Record<string, number> = { ...(a ?? {}) };
  for (const [k, v] of Object.entries(b)) out[k] = Math.max(out[k] ?? 0, v);
  return out;
}

function siteDomains(site: SiteResult): Baseline['domains'] {
  return {
    scripts: [...site.domains.scripts].sort(),
    outbound: [...site.domains.outbound].sort(),
    outboundHosts: [...new Set(site.destinations.map((d) => d.hostname))].sort(),
    iframes: [...site.domains.iframes].sort(),
  };
}

export interface ApprovalOptions {
  readonly scanId: string;
  readonly reason?: string;
  readonly approvedBy?: string;
  readonly now?: Date;
  /** Keep previously approved hashes/domains in addition to the new ones (vendor variants). */
  readonly keepVariants?: boolean;
}

function approval(scope: Approval['scope'], options: ApprovalOptions, at: string, items?: string[]): Approval {
  return {
    at,
    scanId: options.scanId,
    scope,
    ...(options.reason ? { reason: options.reason } : {}),
    ...(options.approvedBy ? { approvedBy: options.approvedBy } : {}),
    ...(items ? { items } : {}),
  };
}

/** Pages scanned completely; only these are trusted for approving removals. */
export function completePages(site: SiteResult): Set<string> {
  return new Set(site.pages.filter((p) => p.status === 'complete').map((p) => p.key));
}

/** Resources observed on complete pages only (partial pages may be missing scripts). */
function resourcesFromCompletePages(site: SiteResult, complete: ReadonlySet<string>, includePartial: boolean): ScriptResource[] {
  if (includePartial) return [...site.resources];
  return site.resources.filter((r) => r.pages.some((p) => complete.has(p)));
}

/** Create the first baseline for a site from a scan. */
export function createBaseline(site: SiteResult, options: ApprovalOptions & { includePartial?: boolean }): Baseline {
  const at = (options.now ?? new Date()).toISOString();
  const complete = completePages(site);
  const resources = baselineResourcesFrom(resourcesFromCompletePages(site, complete, options.includePartial === true), at);
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    kind: 'scriptdrift-baseline',
    site: site.name,
    siteUrl: site.url,
    createdAt: at,
    updatedAt: at,
    approvals: [approval('initial', options, at)],
    resources,
    domains: siteDomains(site),
    pages: site.pages.filter((p) => options.includePartial === true || p.status === 'complete').map((p) => p.key).sort(),
  };
}

/**
 * Re-approve the whole current state of a site. Resources of pages that were
 * not scanned completely are kept from the previous baseline, so a partial
 * scan can never silently drop approvals.
 */
export function approveFullScan(existing: Baseline, site: SiteResult, options: ApprovalOptions & { includePartial?: boolean }): Baseline {
  const at = (options.now ?? new Date()).toISOString();
  const complete = completePages(site);
  const fresh = baselineResourcesFrom(resourcesFromCompletePages(site, complete, options.includePartial === true), at);
  const freshIds = new Set(fresh.map((r) => r.identity));
  const merged: BaselineResource[] = fresh.map((r) => {
    const old = existing.resources.find((o) => o.identity === r.identity);
    if (!old || !options.keepVariants) return r;
    return { ...r, approvedHashes: r.approvedHashes.reduce((acc, h) => addHash(acc, h), [...old.approvedHashes]) };
  });
  // Keep resources that belong only to pages not (completely) scanned now.
  for (const old of existing.resources) {
    if (freshIds.has(old.identity)) continue;
    const touched = old.pages.some((p) => complete.has(p));
    if (!touched || options.keepVariants) merged.push(old);
  }
  const domains = siteDomains(site);
  const union = (a: readonly string[], b: readonly string[]): string[] => [...new Set([...a, ...b])].sort();
  const allComplete = site.pages.every((p) => p.status === 'complete');
  const keepOld = options.keepVariants === true || !allComplete;
  return {
    ...existing,
    siteUrl: site.url,
    updatedAt: at,
    approvals: [...existing.approvals, approval('full', options, at)].slice(-MAX_APPROVAL_HISTORY),
    resources: merged.sort((a, b) => a.identity.localeCompare(b.identity)),
    domains: keepOld
      ? {
          scripts: union(existing.domains.scripts, domains.scripts),
          outbound: union(existing.domains.outbound, domains.outbound),
          outboundHosts: union(existing.domains.outboundHosts, domains.outboundHosts),
          iframes: union(existing.domains.iframes, domains.iframes),
        }
      : domains,
    pages: union(existing.pages, [...complete]),
  };
}

/** Items that can be approved selectively, derived from findings. */
export interface ApprovalItem {
  readonly kind: 'resource' | 'remove-resource' | 'script-domain' | 'outbound-domain' | 'outbound-host' | 'iframe-origin' | 'remove-iframe-origin';
  readonly value: string;
}

/** Approve only selected items (resources by identity, domains, iframe origins). */
export function approveSelected(existing: Baseline, site: SiteResult, items: readonly ApprovalItem[], options: ApprovalOptions): Baseline {
  const at = (options.now ?? new Date()).toISOString();
  let resources = [...existing.resources];
  const domains = {
    scripts: new Set(existing.domains.scripts),
    outbound: new Set(existing.domains.outbound),
    outboundHosts: new Set(existing.domains.outboundHosts),
    iframes: new Set(existing.domains.iframes),
  };
  for (const item of items) {
    switch (item.kind) {
      case 'resource': {
        const current = baselineResourcesFrom(site.resources.filter((r) => r.identity === item.value), at)[0];
        if (!current) break;
        const old = resources.find((r) => r.identity === item.value);
        const approvedHashes = old && options.keepVariants ? current.approvedHashes.reduce((acc, h) => addHash(acc, h), [...old.approvedHashes]) : current.approvedHashes;
        resources = resources.filter((r) => r.identity !== item.value);
        resources.push({ ...current, approvedHashes, pages: [...new Set([...(old?.pages ?? []), ...current.pages])].sort() });
        if (current.registrableDomain && current.hostname) domains.scripts.add(current.registrableDomain);
        break;
      }
      case 'remove-resource':
        resources = resources.filter((r) => r.identity !== item.value);
        break;
      case 'script-domain':
        domains.scripts.add(item.value);
        break;
      case 'outbound-domain':
        domains.outbound.add(item.value);
        break;
      case 'outbound-host':
        domains.outboundHosts.add(item.value);
        break;
      case 'iframe-origin':
        domains.iframes.add(item.value);
        break;
      case 'remove-iframe-origin':
        domains.iframes.delete(item.value);
        break;
    }
  }
  const sorted = (s: Set<string>): string[] => [...s].sort();
  return {
    ...existing,
    updatedAt: at,
    approvals: [...existing.approvals, approval('selected', options, at, items.map((i) => `${i.kind}:${i.value}`))].slice(-MAX_APPROVAL_HISTORY),
    resources: resources.sort((a, b) => a.identity.localeCompare(b.identity)),
    domains: { scripts: sorted(domains.scripts), outbound: sorted(domains.outbound), outboundHosts: sorted(domains.outboundHosts), iframes: sorted(domains.iframes) },
  };
}

export interface BaselineChangeSummary {
  readonly addedResources: readonly string[];
  readonly removedResources: readonly string[];
  readonly changedResources: readonly string[];
  readonly addedDomains: readonly string[];
  readonly removedDomains: readonly string[];
  readonly totalResources: number;
}

/** Describe what a baseline update would change, for the confirmation prompt. */
export function summarizeBaselineChange(previous: Baseline | undefined, next: Baseline): BaselineChangeSummary {
  const prev = new Map((previous?.resources ?? []).map((r) => [r.identity, r]));
  const nextMap = new Map(next.resources.map((r) => [r.identity, r]));
  const key = (r: BaselineResource): string => r.approvedHashes.map((h) => h.sha256 ?? h.normalizedSha256 ?? 'none').sort().join(',');
  const added = [...nextMap.keys()].filter((id) => !prev.has(id));
  const removed = [...prev.keys()].filter((id) => !nextMap.has(id));
  const changed = [...nextMap.entries()].filter(([id, r]) => prev.has(id) && key(prev.get(id) as BaselineResource) !== key(r)).map(([id]) => id);
  const allPrev = new Set([...(previous?.domains.scripts ?? []), ...(previous?.domains.outbound ?? [])]);
  const allNext = new Set([...next.domains.scripts, ...next.domains.outbound]);
  return {
    addedResources: added.sort(),
    removedResources: removed.sort(),
    changedResources: changed.sort(),
    addedDomains: [...allNext].filter((d) => !allPrev.has(d)).sort(),
    removedDomains: [...allPrev].filter((d) => !allNext.has(d)).sort(),
    totalResources: next.resources.length,
  };
}
