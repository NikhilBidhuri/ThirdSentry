import type { Baseline, BaselineResource } from '../baseline/baseline-schema.js';
import type { DomainPolicy } from '../config/schema.js';
import { EMPTY_DOMAIN_POLICY, evaluateDomain } from '../analysis/domain-analyzer.js';
import type { ChangeKind } from '../types/findings.js';
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
}

export interface ComparisonResult {
  readonly site: string;
  readonly changes: readonly Change[];
  readonly unchanged: number;
  /** Pages whose removals could not be evaluated because they were not scanned completely. */
  readonly pagesNotCompared: readonly string[];
}

const UNEXPECTED_TYPES = new Set(['wasm', 'blob-script', 'data-script', 'service-worker', 'shared-worker']);

function inlinePrefix(identity: string): string | undefined {
  if (!identity.startsWith('inline:')) return undefined;
  const lastBar = identity.lastIndexOf('|');
  return lastBar > 0 ? identity.slice(0, lastBar) : undefined;
}

function hostOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
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
  // Approved inline/blob content per page+frame, for position-independent matching.
  const approvedByPrefix = new Map<string, Set<string>>();
  for (const b of baseline.resources) {
    const prefix = inlinePrefix(b.identity) ?? (b.identity.startsWith('blob:') ? b.identity.slice(0, b.identity.lastIndexOf('|')) : undefined);
    if (!prefix) continue;
    const set = approvedByPrefix.get(prefix) ?? new Set<string>();
    b.approvedHashes.forEach((h) => h.sha256 && set.add(h.sha256));
    approvedByPrefix.set(prefix, set);
  }
  const movedBaseline = new Set<string>();

  for (const r of site.resources) {
    const b = baselineById.get(r.identity);
    if (b) {
      const match = hashApproved(r, b);
      if (r.type !== b.type) {
        changes.push({ kind: 'resource-type-changed', identity: r.identity, current: r, baseline: b, pages: r.pages, details: { previousType: b.type, currentType: r.type } });
      }
      const prevFinalHost = hostOf(b.finalUrl);
      const currFinalHost = hostOf(r.finalUrl);
      // Only URL-identified resources have meaningful redirects (blob: URLs are random per load).
      if (r.identity.startsWith('url:') && b.finalUrl && r.finalUrl && b.finalUrl !== r.finalUrl) {
        changes.push({
          kind: 'redirect-changed',
          identity: r.identity,
          current: r,
          baseline: b,
          pages: r.pages,
          details: { previousFinalUrl: b.finalUrl, currentFinalUrl: r.finalUrl, crossHost: String(prevFinalHost !== currFinalHost) },
        });
      }
      if (match === 'raw') {
        unchanged++;
      } else if (match === 'normalized') {
        changes.push({ kind: 'resource-formatting-changed', identity: r.identity, current: r, baseline: b, pages: r.pages, details: {} });
      } else if (r.hashes.sha256 === null) {
        if (b.approvedHashes.some((h) => h.sha256 !== null)) {
          changes.push({ kind: 'content-unavailable', identity: r.identity, current: r, baseline: b, pages: r.pages, details: { contentStatus: r.content.status } });
        } else unchanged++;
      } else {
        changes.push({ kind: 'resource-modified', identity: r.identity, current: r, baseline: b, pages: r.pages, details: {} });
      }
    } else {
      const prefix = inlinePrefix(r.identity) ?? (r.identity.startsWith('blob:') ? r.identity.slice(0, r.identity.lastIndexOf('|')) : undefined);
      if (prefix && r.hashes.sha256 && approvedByPrefix.get(prefix)?.has(r.hashes.sha256)) {
        unchanged++; // same approved content, different DOM position
      } else if (r.hashes.sha256 && missingBaselineByHash.has(r.hashes.sha256)) {
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
    }
    if (r.sri && r.sri.valid === false) {
      changes.push({ kind: 'sri-mismatch', identity: r.identity, current: r, ...(b ? { baseline: b } : {}), pages: r.pages, details: { integrity: r.sri.attribute } });
    }
  }

  // Removed resources (only where every page they appeared on was scanned completely now).
  const pagesNotCompared = [...new Set(baseline.pages.filter((p) => !complete.has(p)))].sort();
  for (const b of baseline.resources) {
    if (seenIdentities.has(b.identity) || movedBaseline.has(b.identity)) continue;
    const relevant = b.pages.filter((p) => scannedPages.has(p));
    if (relevant.length === 0 || !relevant.every((p) => complete.has(p))) continue;
    const prefix = inlinePrefix(b.identity);
    if (prefix) {
      // Approved inline content that is still present at another position is not "removed".
      const stillPresent = site.resources.some((r) => inlinePrefix(r.identity) === prefix && b.approvedHashes.some((h) => h.sha256 === r.hashes.sha256));
      if (stillPresent) continue;
    }
    if (b.identity.startsWith('blob:')) {
      const blobPrefix = b.identity.slice(0, b.identity.lastIndexOf('|'));
      if (site.resources.some((r) => r.identity.startsWith(blobPrefix) && b.approvedHashes.some((h) => h.sha256 === r.hashes.sha256))) continue;
    }
    changes.push({ kind: 'resource-removed', identity: b.identity, baseline: b, pages: relevant, details: {} });
  }

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
