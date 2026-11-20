import { findVulnerabilities, type LibraryVulnerability } from '../analysis/libraries/matcher.js';
import type { LibraryDb } from '../analysis/libraries/vulndb.js';
import { libraryDisplayName, libraryLabel } from '../analysis/libraries/describe.js';
import { compareVersions } from '../analysis/libraries/version.js';
import { categoryFor, scoreSignals, signal, DEFAULT_RISK_CONFIG, type RiskConfig } from '../analysis/risk-scoring.js';
import type { ThirdSentryConfig } from '../config/schema.js';
import type { Confidence, Finding, Severity, Signal } from '../types/findings.js';
import { SEVERITY_ORDER } from '../types/findings.js';
import type { DetectedLibrary, ScriptResource, SiteResult } from '../types/index.js';
import type { LibraryDbSummary, LibraryInventoryItem, LibraryReport } from '../types/report.js';
import { fingerprint } from './finding-engine.js';

/**
 * Findings and inventory for recognised JavaScript libraries.
 *
 * A `vulnerable-library` finding is not a change against the baseline: the
 * library is vulnerable whether or not it was approved. It is raised from
 * the current scan for every site (with or without a baseline). Its ID is
 * derived from site + resource identity + library + version + the set of
 * matching advisory IDs, so it alerts once and again only when the library
 * version, the resource or the set of advisories changes (new advisories
 * appear in a database update).
 */

const NEXT_LEVEL: Record<Exclude<Severity, 'info'>, Exclude<Severity, 'info' | 'low'>> = { low: 'medium', medium: 'high', high: 'critical', critical: 'critical' };
const SEVERITY_SIGNAL = { low: 'vulnerable-library-low', medium: 'vulnerable-library-medium', high: 'vulnerable-library-high', critical: 'vulnerable-library-critical' } as const;
const SCORE_FOR: Record<Severity, number> = { info: 0, low: 20, medium: 40, high: 60, critical: 80 };

function confidenceOf(l: DetectedLibrary): Confidence {
  return l.confidence;
}

export function summarizeDb(db: LibraryDb): LibraryDbSummary {
  const i = db.info;
  return {
    source: i.source,
    ...(i.sourceUrl ? { sourceUrl: i.sourceUrl } : {}),
    ...(i.fetchedAt ? { fetchedAt: i.fetchedAt } : {}),
    ...(i.sha256 ? { sha256: i.sha256 } : {}),
    ...(i.ageDays !== undefined ? { ageDays: i.ageDays } : {}),
    libraries: i.libraries,
    advisories: i.advisories,
    stale: i.stale,
    warnings: [...i.warnings],
  };
}

function resourceLabel(r: ScriptResource): string {
  return r.finalUrl ?? r.originalUrl ?? r.identity;
}

export interface LibraryContext {
  readonly db: LibraryDb;
  readonly libraries: ThirdSentryConfig['libraries'];
  readonly risk?: RiskConfig;
  readonly now?: Date;
}

function buildOne(site: SiteResult, r: ScriptResource, v: LibraryVulnerability, sensitive: boolean, ctx: LibraryContext): Finding {
  const risk = ctx.risk ?? DEFAULT_RISK_CONFIG;
  const label = libraryLabel(v.library);
  const base = v.highestSeverity;
  const severity: Exclude<Severity, 'info'> = sensitive ? NEXT_LEVEL[base] : base;
  const signals: Signal[] = [signal(SEVERITY_SIGNAL[base], risk)];
  if (severity !== base) {
    signals.push({ id: 'sensitive-page', description: `Observed on a page marked as sensitive: severity raised from ${base} to ${severity}`, weight: SCORE_FOR[severity] - scoreSignals(signals) });
  }
  const advisoryIds = [...new Set(v.advisories.map((a) => a.id))].sort();
  const id = fingerprint([site.name, 'vulnerable-library', r.identity, v.library.name, v.library.version, advisoryIds.join(',')]);
  const n = v.advisories.length;
  const top = v.advisories.slice(0, 3).map((a) => `${a.id}${a.summary ? ` (${a.summary.slice(0, 90)})` : ''}`);
  const links = [...new Set(v.advisories.flatMap((a) => a.links))].slice(0, 8);
  const upgrade = v.fixedIn
    ? `Upgrade ${libraryDisplayName(v.library.name)} to ${v.fixedIn} or later (fixes ${n === 1 ? 'this advisory' : `all ${n} advisories found`}). Check the release notes for breaking changes and test the pages that use it.`
    : `Check whether a fixed ${libraryDisplayName(v.library.name)} release exists and upgrade or replace it.`;
  const db = ctx.db.info;
  const pages = r.pages;
  const evidence = [
    { label: 'Library', value: label },
    { label: 'Detected by', value: `${v.library.method} (confidence ${v.library.confidence})` },
    ...v.advisories.map((a) => ({
      label: `${a.id} (${a.severity})`,
      value: [a.summary, a.atOrAbove || a.below ? `affects ${a.atOrAbove ? `>= ${a.atOrAbove} ` : ''}${a.below ? `< ${a.below}` : ''}`.trim() : ''].filter(Boolean).join(' | ').slice(0, 400),
    })),
    ...(v.fixedIn ? [{ label: 'Fixed in', value: v.fixedIn }] : []),
    ...(links.length ? [{ label: 'References', value: links.join(' ') }] : []),
    { label: 'Resource identity', value: r.identity },
    ...(r.hashes.sha256 ? [{ label: 'Current SHA-256', value: r.hashes.sha256 }] : []),
    { label: 'Vulnerability database', value: `${db.source === 'cache' ? `cached${db.fetchedAt ? `, fetched ${db.fetchedAt}` : ''}` : 'bundled seed'}${db.ageDays !== undefined ? ` (${db.ageDays} days old)` : ''}` },
    ...(pages.length ? [{ label: 'Pages', value: pages.join(', ') }] : []),
  ];
  const reasonLead = `${label} is loaded from ${resourceLabel(r)} and has ${n} known ${n === 1 ? 'vulnerability' : 'vulnerabilities'}: ${top.join('; ')}${n > 3 ? `; and ${n - 3} more` : ''}.`;
  const caveat =
    v.library.method === 'url'
      ? ' The version was taken from the URL, so the file may differ from what its name says.'
      : ' Whether the vulnerable code path is reachable on your pages is not assessed.';
  return {
    id,
    kind: 'vulnerable-library',
    title: `Vulnerable library: ${label}${sensitive ? ' on a sensitive page' : ''}`,
    site: site.name,
    pages,
    ...(pages[0] ? { page: pages[0] } : {}),
    resourceIdentity: r.identity,
    resourceUrl: resourceLabel(r),
    resourceType: r.type,
    party: r.party,
    ...(r.registrableDomain ? { domain: r.registrableDomain } : {}),
    currentHash: r.hashes.sha256,
    detectedAt: (ctx.now ?? new Date()).toISOString(),
    severity,
    confidence: confidenceOf(v.library),
    category: categoryFor(severity, signals),
    score: Math.max(scoreSignals(signals), 0),
    signals,
    reason: reasonLead + caveat,
    evidence,
    recommendedAction: `${upgrade}${links.length ? ` Details: ${links.slice(0, 2).join(' ')}` : ''} If the library is intentionally pinned or the risk is accepted, suppress this finding with a reason in thirdsentry.yml.`,
  };
}

/** `vulnerable-library` findings for one site's current resources (one per resource and library version). */
export function buildLibraryFindings(site: SiteResult, ctx: LibraryContext): Finding[] {
  if (!ctx.libraries.detect || !ctx.libraries.vulnerabilities) return [];
  const sensitivePages = new Set(site.pages.filter((p) => p.sensitive).map((p) => p.key));
  const out = new Map<string, Finding>();
  for (const r of site.resources) {
    if (!r.libraries?.length) continue;
    const sensitive = r.pages.some((p) => sensitivePages.has(p));
    for (const v of findVulnerabilities(r.libraries, ctx.db, ctx.libraries.minSeverity)) {
      const f = buildOne(site, r, v, sensitive, ctx);
      const existing = out.get(f.id);
      // The same code served twice (two hashes can share an ID only if everything else matches): merge pages.
      if (existing) out.set(f.id, { ...existing, pages: [...new Set([...existing.pages, ...f.pages])] });
      else out.set(f.id, f);
    }
  }
  return [...out.values()].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.id.localeCompare(b.id));
}

/** Libraries recognised on the site, with matching advisory IDs. */
export function buildLibraryInventory(sites: readonly SiteResult[], db: LibraryDb | undefined, minSeverity: ThirdSentryConfig['libraries']['minSeverity'], withVulns: boolean): LibraryInventoryItem[] {
  const items = new Map<string, { item: Omit<LibraryInventoryItem, 'resources' | 'advisories'>; resources: Set<string>; advisories: Set<string> }>();
  for (const site of sites) {
    for (const r of site.resources) {
      for (const l of r.libraries ?? []) {
        const key = `${site.name}\u0000${l.name}\u0000${l.version}`;
        let e = items.get(key);
        if (!e) {
          const adv = db && withVulns ? findVulnerabilities([l], db, minSeverity)[0]?.advisories.map((a) => a.id) ?? [] : [];
          e = { item: { site: site.name, name: l.name, version: l.version, method: l.method, confidence: l.confidence }, resources: new Set(), advisories: new Set(adv) };
          items.set(key, e);
        }
        e.resources.add(resourceLabel(r));
      }
    }
  }
  return [...items.values()]
    .map((e) => ({ ...e.item, resources: [...e.resources].sort().slice(0, 20), advisories: [...e.advisories].sort() }))
    .sort((a, b) => a.site.localeCompare(b.site) || a.name.localeCompare(b.name) || (compareVersions(a.version, b.version) ?? 0));
}

export function buildLibraryReport(sites: readonly SiteResult[], db: LibraryDb | undefined, config: ThirdSentryConfig['libraries']): LibraryReport | undefined {
  if (!config.detect || !db) return undefined;
  return { db: summarizeDb(db), inventory: buildLibraryInventory(sites, db, config.minSeverity, config.vulnerabilities) };
}
