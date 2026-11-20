import type { Baseline, BaselineResource } from '../baseline/baseline-schema.js';
import type { DomainPolicy } from '../config/schema.js';
import { EMPTY_DOMAIN_POLICY, evaluateDomain } from '../analysis/domain-analyzer.js';
import type { ChangeKind } from '../types/findings.js';
import type { PolicyRef } from '../policies/types.js';
import type { ScriptResource, SiteResult } from '../types/index.js';

/**
 * Compares a site's scan result with its approved baseline and produces raw
 * changes. Changes carry facts only; severity, confidence and explanations are
 * assigned by the finding engine.
 *
 * Matching rules:
 *  - Resources are matched by identity (see discovery/resource-identity.ts).
 *  - A resource is unchanged if its raw SHA-256 matches any approved hash for
 *    that identity. If only the normalised hash matches, the change is
 *    formatting-only.
 *  - A new identity whose content hash equals a baseline resource that has
 *    disappeared is reported as "moved" rather than added + removed.
 *  - Inline scripts whose position changed but whose content is approved for
 *    the same page and frame are treated as unchanged.
 *  - Removals are only reported for pages that were scanned completely in
 *    this scan; otherwise a missing resource may simply not have loaded.
 */

export interface Change {
  readonly kind: ChangeKind;
  readonly identity?: string;
  readonly current?: ScriptResource;
  readonly baseline?: BaselineResource;
  readonly domain?: string;
  readonly host?: string;
  readonly origin?: string;
  readonly pages: readonly string[];
  readonly details: Readonly<Record<string, string>>;
  /** Script policy governing the resource (set by src/policies). */
  readonly policy?: PolicyRef;
}

export interface ComparisonResult {
  readonly site: string;
  readonly changes: readonly Change[];
  readonly unchanged: number;
  /** Pages whose removals could not be evaluated because they were not scanned completely. */
  readonly pagesNotCompared: readonly string[];
}

const UNEXPECTED_TYPES = new Set(['wasm', 'blob-script', 'data-script', 'service-worker', 'shared-worker']);

function hostOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
}

/** Where a URL resource was redirected to, or undefined when it was served from the requested URL. */
function redirectTarget(r: { readonly originalUrl?: string | undefined; readonly finalUrl?: string | undefined }): string | undefined {
  if (!r.finalUrl || !r.originalUrl || r.finalUrl === r.originalUrl) return undefined;
  return r.finalUrl;
}

function hashApproved(r: ScriptResource, b: BaselineResource): 'raw' | 'normalized' | false {
  if (r.hashes.sha256 !== null && b.approvedHashes.some((h) => h.sha256 === r.hashes.sha256)) return 'raw';
  if (
    r.hashes.normalizedSha256 !== null &&
    b.approvedHashes.some((h) => h.normalizedSha256 === r.hashes.normalizedSha256 && h.normalizerVersion === r.hashes.normalizerVersion)
  ) {
    return 'normalized';
  }
  return false;
}

/** `inline:<page>|<frame>|<pos>` or `blob:...|<pos>` → the page+frame group; undefined for URL-identified resources. */
function groupKeyOf(identity: string): string | undefined {
  if (!identity.startsWith('inline:') && !identity.startsWith('blob:')) return undefined;
  const lastBar = identity.lastIndexOf('|');
  return lastBar > 0 ? identity.slice(0, lastBar) : undefined;
}

/** Numeric DOM position components of an inline identity (`...script:nth-of-type(2)` gives [.., 2]). */
function positionOf(identity: string): number[] {
  const tail = identity.slice(identity.lastIndexOf('|') + 1);
  return [...tail.matchAll(/:nth-of-type\((\d+)\)/g)].map((m) => Number(m[1]));
}

function positionDistance(a: string, b: string): number {
  if (a === b) return 0;
  const pa = positionOf(a);
  const pb = positionOf(b);
  if (pa.length === 0 || pa.length !== pb.length) return 50;
  return pa.reduce((sum, v, i) => sum + Math.abs(v - (pb[i] as number)), 0);
}

function baselineSize(b: BaselineResource): number | undefined {
  return b.approvedHashes.at(-1)?.size;
}

/** The body of a truncated resource is only a prefix: it can never prove that the script is unchanged. */
function verifiable(r: ScriptResource): boolean {
  return r.content.status !== 'truncated';
}

const COVERAGE_WARNING_CODES = new Set(['script-limit', 'request-limit', 'bodies-pending', 'frame-snapshot-failed', 'service-worker-probe-failed', 'scan-time-limit']);

/**
 * Pages that could not be observed completely. Without these changes a page that fails
 * (or is skipped because a budget ran out) would silently hide every script change on it.
 * `details.reason` is a stable, sorted list of issue codes, so the finding ID is stable
 * per site+page+reason; a change of reason or of failed/partial status is an escalation
 * and produces a new ID.
 */
function coverageChanges(site: SiteResult, baseline: Baseline): Change[] {
  const out: Change[] = [];
  for (const p of site.pages) {
    const codes = [...new Set(p.issues.filter((i) => i.level === 'error' || COVERAGE_WARNING_CODES.has(i.code)).map((i) => i.code))].sort();
    const messages = p.issues.filter((i) => i.level === 'error' || COVERAGE_WARNING_CODES.has(i.code)).map((i) => i.message).slice(0, 5).join(' | ');
    if (p.status === 'failed') {
      out.push({ kind: 'page-failed', pages: [p.key], details: { reason: codes.length ? codes.join(',') : 'unknown', issues: messages } });
    } else if (p.status === 'partial' || codes.length > 0) {
      out.push({ kind: 'coverage-degraded', pages: [p.key], details: { reason: codes.length ? codes.join(',') : 'partial', issues: messages } });
    }
  }
  const scanned = new Set(site.pages.map((p) => p.key));
  for (const key of baseline.pages) {
    if (scanned.has(key)) continue;
    out.push({ kind: 'coverage-degraded', pages: [key], details: { reason: 'page-not-scanned', issues: 'The page is in the baseline but was not scanned (scan budget, page limit or unreachable site).' } });
  }
  return out;
}

export function compareSite(site: SiteResult, baseline: Baseline, policy: DomainPolicy = EMPTY_DOMAIN_POLICY): ComparisonResult {
  const changes: Change[] = [];
  let unchanged = 0;
  const baselineById = new Map(baseline.resources.map((r) => [r.identity, r]));
  const complete = new Set(site.pages.filter((p) => p.status === 'complete').map((p) => p.key));
  const scannedPages = new Set(site.pages.map((p) => p.key));
  const seenIdentities = new Set(site.resources.map((r) => r.identity));

  // Content hashes of baseline resources that are absent now (candidates for "moved").
  const missingBaselineByHash = new Map<string, BaselineResource>();
  for (const b of baseline.resources) {
    if (seenIdentities.has(b.identity)) continue;
    for (const h of b.approvedHashes) if (h.sha256) missingBaselineByHash.set(h.sha256, b);
  }
  const movedBaseline = new Set<string>();
  /** Baseline inline/blob resources accounted for by a current resource (possibly at another position). */
  const claimedBaseline = new Set<string>();

  /** A current resource that corresponds to a baseline resource. */
  const emitMatched = (r: ScriptResource, b: BaselineResource, match: 'raw' | 'normalized' | false): void => {
    if (r.type !== b.type) {
      changes.push({ kind: 'resource-type-changed', identity: r.identity, current: r, baseline: b, pages: r.pages, details: { previousType: b.type, currentType: r.type } });
    }
    // A resource "redirects" only when the response URL differs from the requested URL.
    // Comparing final URLs alone would report every request whose URL varies per load
    // (e.g. an ignored cache-buster such as ?cb=<timestamp>) as a changed redirect.
    const prevTarget = redirectTarget(b);
    const currTarget = redirectTarget(r);
    // Only URL-identified resources have meaningful redirects (blob: URLs are random per load).
    if (r.identity.startsWith('url:') && prevTarget && currTarget && prevTarget !== currTarget) {
      changes.push({
        kind: 'redirect-changed',
        identity: r.identity,
        current: r,
        baseline: b,
        pages: r.pages,
        details: { previousFinalUrl: prevTarget, currentFinalUrl: currTarget, crossHost: String(hostOf(prevTarget) !== hostOf(currTarget)) },
      });
    }
    if (match === 'raw' && verifiable(r)) {
      unchanged++;
    } else if (match === 'normalized' && verifiable(r)) {
      changes.push({ kind: 'resource-formatting-changed', identity: r.identity, current: r, baseline: b, pages: r.pages, details: {} });
    } else if (r.hashes.sha256 === null || !verifiable(r)) {
      if (b.approvedHashes.some((h) => h.sha256 !== null)) {
        changes.push({ kind: 'content-unavailable', identity: r.identity, current: r, baseline: b, pages: r.pages, details: { contentStatus: r.content.status } });
      } else unchanged++;
    } else {
      changes.push({ kind: 'resource-modified', identity: r.identity, current: r, baseline: b, pages: r.pages, details: {} });
    }
  };

  /** A current resource without a counterpart in the baseline. */
  const emitNew = (r: ScriptResource): void => {
    if (verifiable(r) && r.hashes.sha256 && missingBaselineByHash.has(r.hashes.sha256)) {
      const old = missingBaselineByHash.get(r.hashes.sha256) as BaselineResource;
      movedBaseline.add(old.identity);
      changes.push({
        kind: 'resource-moved',
        identity: r.identity,
        current: r,
        baseline: old,
        pages: r.pages,
        details: { previousIdentity: old.identity, previousDomain: old.registrableDomain ?? '', currentDomain: r.registrableDomain ?? '' },
      });
    } else {
      changes.push({
        kind: 'resource-added',
        identity: r.identity,
        current: r,
        pages: r.pages,
        details: UNEXPECTED_TYPES.has(r.type) ? { unexpectedType: r.type } : {},
      });
    }
  };

  // URL-identified resources are matched by identity.
  const groupsCurrent = new Map<string, ScriptResource[]>();
  const groupsBaseline = new Map<string, BaselineResource[]>();
  for (const r of site.resources) {
    const g = groupKeyOf(r.identity);
    if (g) {
      groupsCurrent.set(g, [...(groupsCurrent.get(g) ?? []), r]);
      continue;
    }
    const b = baselineById.get(r.identity);
    if (b) emitMatched(r, b, hashApproved(r, b));
    else emitNew(r);
  }
  for (const b of baseline.resources) {
    const g = groupKeyOf(b.identity);
    if (g) groupsBaseline.set(g, [...(groupsBaseline.get(g) ?? []), b]);
  }

  // Inline/blob scripts are paired per page+frame without relying on DOM position (a
  // runtime-injected script shifts nth-of-type indexes): exact hash first, then normalised
  // hash, then leftovers by nearest position and size.
  for (const [g, current] of groupsCurrent) {
    const base = groupsBaseline.get(g) ?? [];
    const taken = new Set<string>(); // baseline identities used by a normalised or paired match
    let pending: ScriptResource[] = [];
    for (const r of current) {
      const raw = verifiable(r) && r.hashes.sha256 !== null ? base.find((b) => b.approvedHashes.some((h) => h.sha256 === r.hashes.sha256)) : undefined;
      if (raw) {
        claimedBaseline.add(raw.identity);
        emitMatched(r, raw, 'raw');
      } else pending.push(r);
    }
    const afterNormalized: ScriptResource[] = [];
    for (const r of pending) {
      const norm =
        verifiable(r) && r.hashes.normalizedSha256 !== null
          ? base.find(
              (b) =>
                !taken.has(b.identity) &&
                b.approvedHashes.some((h) => h.normalizedSha256 === r.hashes.normalizedSha256 && h.normalizerVersion === r.hashes.normalizerVersion),
            )
          : undefined;
      if (norm) {
        taken.add(norm.identity);
        claimedBaseline.add(norm.identity);
        emitMatched(r, norm, 'normalized');
      } else afterNormalized.push(r);
    }
    pending = afterNormalized;
    const candidates = base.filter((b) => !claimedBaseline.has(b.identity) && !taken.has(b.identity));
    const pairs: Array<{ r: ScriptResource; b: BaselineResource; score: number }> = [];
    for (const r of pending) {
      for (const b of candidates) {
        const sameId = b.identity === r.identity;
        const bs = baselineSize(b);
        const ratio = bs && r.size ? Math.max(bs, r.size) / Math.max(1, Math.min(bs, r.size)) : 1;
        if (!sameId && ratio > 3) continue;
        pairs.push({ r, b, score: (sameId ? 0 : 1 + positionDistance(r.identity, b.identity)) + Math.log2(ratio) });
      }
    }
    pairs.sort((x, y) => x.score - y.score);
    const paired = new Set<string>();
    for (const { r, b } of pairs) {
      if (paired.has(r.key) || taken.has(b.identity)) continue;
      paired.add(r.key);
      taken.add(b.identity);
      claimedBaseline.add(b.identity);
      emitMatched(r, b, false);
    }
    for (const r of pending) if (!paired.has(r.key)) emitNew(r);
  }
  for (const r of site.resources) {
    if (r.sri && r.sri.valid === false) {
      const b = baselineById.get(r.identity);
      changes.push({ kind: 'sri-mismatch', identity: r.identity, current: r, ...(b ? { baseline: b } : {}), pages: r.pages, details: { integrity: r.sri.attribute } });
    }
  }

  // Removed resources (only where every page they appeared on was scanned completely now).
  const pagesNotCompared = [...new Set(baseline.pages.filter((p) => !complete.has(p)))].sort();
  for (const b of baseline.resources) {
    if (seenIdentities.has(b.identity) || movedBaseline.has(b.identity) || claimedBaseline.has(b.identity)) continue;
    const relevant = b.pages.filter((p) => scannedPages.has(p));
    if (relevant.length === 0 || !relevant.every((p) => complete.has(p))) continue;
    const group = groupKeyOf(b.identity);
    if (group) {
      // Approved inline content that is still present at another position is not "removed".
      const stillPresent = site.resources.some((r) => groupKeyOf(r.identity) === group && verifiable(r) && b.approvedHashes.some((h) => h.sha256 === r.hashes.sha256));
      if (stillPresent) continue;
    }
    changes.push({ kind: 'resource-removed', identity: b.identity, baseline: b, pages: relevant, details: {} });
  }

  changes.push(...coverageChanges(site, baseline));

  // Domains serving scripts.
  const approvedScriptDomains = new Set(baseline.domains.scripts);
  const newScriptDomains = new Map<string, ScriptResource[]>();
  for (const r of site.resources) {
    if (!r.hostname || !r.registrableDomain || approvedScriptDomains.has(r.registrableDomain)) continue;
    if (evaluateDomain(r.hostname, r.registrableDomain, policy).allowed) continue;
    const list = newScriptDomains.get(r.registrableDomain) ?? [];
    list.push(r);
    newScriptDomains.set(r.registrableDomain, list);
  }
  for (const [domain, resources] of newScriptDomains) {
    changes.push({
      kind: 'new-script-domain',
      domain,
      pages: [...new Set(resources.flatMap((r) => r.pages))].sort(),
      details: { resources: resources.map((r) => r.finalUrl ?? r.originalUrl ?? r.identity).slice(0, 5).join(' '), party: resources[0]?.party ?? 'third-party' },
    });
  }

  // Outbound destinations.
  const approvedOutbound = new Set(baseline.domains.outbound);
  const approvedHosts = new Set(baseline.domains.outboundHosts);
  for (const dest of site.destinations) {
    if (evaluateDomain(dest.hostname, dest.registrableDomain, policy).allowed) continue;
    if (!approvedOutbound.has(dest.registrableDomain)) {
      if (changes.some((c) => c.kind === 'new-outbound-domain' && c.domain === dest.registrableDomain)) continue;
      const sameDomain = site.destinations.filter((d) => d.registrableDomain === dest.registrableDomain);
      changes.push({
        kind: 'new-outbound-domain',
        domain: dest.registrableDomain,
        host: dest.hostname,
        pages: [...new Set(sameDomain.flatMap((d) => d.pages))].sort(),
        details: {
          hosts: sameDomain.map((d) => d.hostname).join(' '),
          methods: [...new Set(sameDomain.flatMap((d) => d.methods))].join(','),
          resourceTypes: [...new Set(sameDomain.flatMap((d) => d.resourceTypes))].join(','),
          requestCount: String(sameDomain.reduce((n, d) => n + d.requestCount, 0)),
          party: dest.party,
          blocked: String(sameDomain.some((d) => d.blocked)),
        },
      });
    } else if (!approvedHosts.has(dest.hostname)) {
      changes.push({
        kind: 'new-outbound-host',
        domain: dest.registrableDomain,
        host: dest.hostname,
        pages: dest.pages,
        details: { methods: dest.methods.join(','), resourceTypes: dest.resourceTypes.join(','), requestCount: String(dest.requestCount), party: dest.party },
      });
    }
  }

  // Iframe origins.
  const approvedIframes = new Set(baseline.domains.iframes);
  const currentIframes = new Set(site.domains.iframes);
  for (const origin of currentIframes) {
    if (approvedIframes.has(origin)) continue;
    const originHost = hostOf(origin);
    if (originHost && evaluateDomain(originHost, undefined, policy).allowed) continue;
    changes.push({
      kind: 'iframe-origin-added',
      origin,
      pages: site.pages.filter((p) => p.iframeOrigins.includes(origin)).map((p) => p.key),
      details: {},
    });
  }
  const allComplete = site.pages.length > 0 && site.pages.every((p) => p.status === 'complete') && baseline.pages.every((p) => scannedPages.has(p));
  if (allComplete) {
    for (const origin of approvedIframes) {
      if (!currentIframes.has(origin)) changes.push({ kind: 'iframe-origin-removed', origin, pages: [], details: {} });
    }
  }

  // Denylisted domains are reported on every scan, whether or not they were approved.
  const denied = new Map<string, { domain: string; pages: Set<string>; uses: Set<string> }>();
  const noteDenied = (host: string, domain: string | undefined, pages: readonly string[], use: string): void => {
    if (!evaluateDomain(host, domain, policy).denied) return;
    const entry = denied.get(host) ?? { domain: domain ?? host, pages: new Set<string>(), uses: new Set<string>() };
    pages.forEach((p) => entry.pages.add(p));
    entry.uses.add(use);
    denied.set(host, entry);
  };
  for (const r of site.resources) if (r.hostname) noteDenied(r.hostname, r.registrableDomain, r.pages, 'serves scripts');
  for (const d of site.destinations) noteDenied(d.hostname, d.registrableDomain, d.pages, 'receives requests');
  for (const origin of currentIframes) {
    const h = hostOf(origin);
    if (h) noteDenied(h, undefined, [], 'is embedded as an iframe');
  }
  for (const [host, entry] of denied) {
    changes.push({ kind: 'denylisted-domain', domain: entry.domain, host, pages: [...entry.pages].sort(), details: { uses: [...entry.uses].join(', ') } });
  }

  return { site: site.name, changes, unchanged, pagesNotCompared };
}
