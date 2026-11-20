import { NORMALIZER_VERSION } from '../analysis/normalizer.js';
import { baselinePath, type StoragePaths } from '../storage/paths.js';
import { observedPageSecurity, type PageSecurity, type PageSecurityPart } from '../pci/page-security.js';
import type { PageResult, ScriptResource, SiteResult } from '../types/index.js';
import { pathExists, readJsonFile, writeJsonAtomic } from '../utils/fs.js';
import { BASELINE_SCHEMA_VERSION, type ApprovedHash, type Approval, type Baseline, type BaselineResource } from './baseline-schema.js';
import { validateBaseline } from './baseline-validator.js';
import { BaselineError } from '../utils/errors.js';

/**
 * Baseline management. Baselines are only ever written by the explicit
 * `thirdsentry baseline` command (never by scans), and every write records an
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

/** Approved security state (headers, form fingerprints) of the given pages of a scan. */
export function pageSecurityFrom(pages: readonly PageResult[], at: string): Record<string, PageSecurity> {
  const out: Record<string, PageSecurity> = {};
  for (const p of pages) {
    const observed = observedPageSecurity(p, at);
    if (observed) out[p.key] = observed;
  }
  return out;
}

/** Create the first baseline for a site from a scan. */
export function createBaseline(site: SiteResult, options: ApprovalOptions & { includePartial?: boolean }): Baseline {
  const at = (options.now ?? new Date()).toISOString();
  const complete = completePages(site);
  const resources = baselineResourcesFrom(resourcesFromCompletePages(site, complete, options.includePartial === true), at);
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    kind: 'thirdsentry-baseline',
    site: site.name,
    siteUrl: site.url,
    createdAt: at,
    updatedAt: at,
    approvals: [approval('initial', options, at)],
    resources,
    domains: siteDomains(site),
    pages: site.pages.filter((p) => options.includePartial === true || p.status === 'complete').map((p) => p.key).sort(),
    pageSecurity: pageSecurityFrom(site.pages.filter((p) => options.includePartial === true || p.status === 'complete'), at),
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
    // Security state of pages scanned completely is re-approved; other pages keep what was approved before.
    pageSecurity: { ...(existing.pageSecurity ?? {}), ...pageSecurityFrom(site.pages.filter((p) => complete.has(p.key)), at) },
  };
}

/**
 * Items that can be approved selectively, derived from findings.
 *
 * Finding IDs include the content hash, so approvals are bound to the exact
 * version that was reviewed: a `resource` item approves only the scan
 * resource with that identity AND that hash (the same URL can serve a benign
 * variant on one page and a malicious one on another), and a
 * `remove-resource` item removes only the approved hashes that were reviewed.
 */
export type ApprovalItem =
  | {
      readonly kind: 'resource';
      readonly value: string;
      /** Raw SHA-256 of the reviewed version (null when its content could not be captured). */
      readonly sha256: string | null;
    }
  | {
      readonly kind: 'remove-resource';
      readonly value: string;
      /** Approved hashes (sha256, or normalised hash when sha256 is null) that were reviewed as removed. */
      readonly hashes: readonly string[];
    }
  | {
      /** Approve the observed security headers and/or form fingerprint of one page (PCI DSS 11.6.1). */
      readonly kind: 'page-security';
      readonly value: string;
      readonly part: PageSecurityPart;
    }
  | {
      readonly kind: 'script-domain' | 'outbound-domain' | 'outbound-host' | 'iframe-origin' | 'remove-iframe-origin';
      readonly value: string;
    };

function hashKey(h: Pick<ApprovedHash, 'sha256' | 'normalizedSha256'>): string {
  return h.sha256 ?? h.normalizedSha256 ?? 'none';
}

export function describeApprovalItem(item: ApprovalItem): string {
  switch (item.kind) {
    case 'resource':
      return `resource:${item.value}@${item.sha256 ?? 'no-content'}`;
    case 'page-security':
      return `page-security:${item.value}#${item.part}`;
    case 'remove-resource':
      return `remove-resource:${item.value}@${[...item.hashes].sort().join(',')}`;
    default:
      return `${item.kind}:${item.value}`;
  }
}

/** Approve only selected items (resource versions, removals, domains, iframe origins). */
export function approveSelected(existing: Baseline, site: SiteResult, items: readonly ApprovalItem[], options: ApprovalOptions): Baseline {
  const at = (options.now ?? new Date()).toISOString();
  let resources = [...existing.resources];
  const domains = {
    scripts: new Set(existing.domains.scripts),
    outbound: new Set(existing.domains.outbound),
    outboundHosts: new Set(existing.domains.outboundHosts),
    iframes: new Set(existing.domains.iframes),
  };
  // Identities that already received an approved version in this run: further
  // variants of the same identity are added, not substituted.
  const approvedThisRun = new Set<string>();
  const pageSecurity: Record<string, PageSecurity> = { ...(existing.pageSecurity ?? {}) };
  for (const item of items) {
    switch (item.kind) {
      case 'resource': {
        if (!('sha256' in item) || (item.sha256 !== null && typeof item.sha256 !== 'string')) {
          throw new BaselineError(`Approval of ${item.value} does not name the reviewed version`);
        }
        const matching = site.resources.filter((r) => r.identity === item.value && r.hashes.sha256 === item.sha256);
        const current = baselineResourcesFrom(matching, at)[0];
        if (!current) {
          throw new BaselineError(`The scan does not contain version ${item.sha256 ?? '(no content)'} of ${item.value}`, 'Run "thirdsentry diff" again and approve the current findings.');
        }
        const old = resources.find((r) => r.identity === item.value);
        const keepOld = approvedThisRun.has(item.value) || options.keepVariants === true;
        const approvedHashes = old && keepOld ? current.approvedHashes.reduce((acc, h) => addHash(acc, h), [...old.approvedHashes]) : current.approvedHashes;
        const indicators = old && approvedThisRun.has(item.value) && current.indicators ? mergeIndicators(old.indicators, current.indicators) : current.indicators;
        resources = resources.filter((r) => r.identity !== item.value);
        resources.push({
          ...current,
          approvedHashes,
          pages: [...new Set([...(old?.pages ?? []), ...current.pages])].sort(),
          dynamic: current.dynamic || (approvedThisRun.has(item.value) && old?.dynamic === true),
          ...(indicators ? { indicators } : {}),
        });
        approvedThisRun.add(item.value);
        if (current.registrableDomain && current.hostname) domains.scripts.add(current.registrableDomain);
        break;
      }
      case 'remove-resource': {
        const reviewed = new Set(item.hashes);
        resources = resources.flatMap((r) => {
          if (r.identity !== item.value) return [r];
          const remaining = r.approvedHashes.filter((h) => !reviewed.has(hashKey(h)));
          // Versions approved after the review are kept: they were not reviewed as removed.
          return remaining.length > 0 ? [{ ...r, approvedHashes: remaining }] : [];
        });
        break;
      }
      case 'page-security': {
        const page = site.pages.find((p) => p.key === item.value);
        const observed = page ? observedPageSecurity(page, at) : undefined;
        const part = observed?.[item.part];
        if (!observed || part === undefined) {
          throw new BaselineError(`The scan has no ${item.part === 'headers' ? 'security headers' : 'form snapshot'} for page ${item.value}`, 'Run "thirdsentry diff" again and approve the current findings.');
        }
        pageSecurity[item.value] = { ...(pageSecurity[item.value] ?? { approvedAt: at }), [item.part]: part, approvedAt: at };
        break;
      }
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
    approvals: [...existing.approvals, approval('selected', options, at, items.map(describeApprovalItem))].slice(-MAX_APPROVAL_HISTORY),
    resources: resources.sort((a, b) => a.identity.localeCompare(b.identity)),
    domains: { scripts: sorted(domains.scripts), outbound: sorted(domains.outbound), outboundHosts: sorted(domains.outboundHosts), iframes: sorted(domains.iframes) },
    ...(Object.keys(pageSecurity).length > 0 ? { pageSecurity } : {}),
  };
}

export interface BaselineChangeSummary {
  readonly addedResources: readonly string[];
  readonly removedResources: readonly string[];
  readonly changedResources: readonly string[];
  readonly addedDomains: readonly string[];
  readonly removedDomains: readonly string[];
  readonly totalResources: number;
  /** Pages whose approved security headers or form fingerprint are new or different (PCI DSS 11.6.1). */
  readonly securityChangedPages: readonly string[];
}

function securityKey(s: PageSecurity | undefined): string {
  return s ? JSON.stringify({ h: s.headers ?? null, f: s.forms?.hash ?? null }) : '';
}

/** Describe what a baseline update would change, for the confirmation prompt. */
export function summarizeBaselineChange(previous: Baseline | undefined, next: Baseline): BaselineChangeSummary {
  const prev = new Map((previous?.resources ?? []).map((r) => [r.identity, r]));
  const nextMap = new Map(next.resources.map((r) => [r.identity, r]));
  const key = (r: BaselineResource): string => r.approvedHashes.map(hashKey).sort().join(',');
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
    securityChangedPages: Object.keys(next.pageSecurity ?? {})
      .filter((p) => securityKey(previous?.pageSecurity?.[p]) !== securityKey(next.pageSecurity?.[p]))
      .sort(),
  };
}
