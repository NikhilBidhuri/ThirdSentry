import { basename, isAbsolute, join, relative, resolve } from 'node:path';
import { loadBaseline } from '../baseline/baseline-manager.js';
import type { Baseline } from '../baseline/baseline-schema.js';
import { buildInventory, loadInventory } from '../pci/inventory.js';
import { inventoryFindings, pciSectionFor } from '../pci/inventory-findings.js';
import type { ResolvedConfig } from '../config/loader.js';
import { loadLibraryDb } from '../analysis/libraries/vulndb.js';
import { writeReports, type ReportFormat, type WrittenReports } from '../reporting/index.js';
import { ensureScanReportDir } from '../storage/filesystem-store.js';
import { assertSiteName, baselinePath } from '../storage/paths.js';
import { SEVERITY_ORDER, type Finding, type Severity } from '../types/findings.js';
import type { ScanResult } from '../types/index.js';
import type { AnalysisReport, PciReportSection, ReportHealth, SiteComparisonSummary } from '../types/report.js';
import { buildHealthFindings } from '../health/health-finding.js';
import { loadHealthState, recordScanHealth, saveHealthState } from '../health/health-state.js';
import { ConfigError } from '../utils/errors.js';
import { ExitCode, type ExitCodeValue } from '../utils/exit-codes.js';
import { copyFileAtomic, writeJsonAtomic } from '../utils/fs.js';
import { toolVersion } from '../utils/version.js';
import type { ComparisonResult } from './comparison-engine.js';
import { compareSiteWithPolicies, usageWithoutBaseline, type PolicySiteUsage } from '../policies/apply.js';
import { isSilentPolicyFinding } from '../policies/finding-hooks.js';
import { buildPolicyReport } from '../policies/report.js';
import { buildFindings } from './finding-engine.js';
import { buildLibraryFindings, buildLibraryReport } from './library-findings.js';
import { applySuppressions } from './suppressions.js';
import { annotateFindings, loadFindingState, saveFindingState, trackFindings } from './dedup-state.js';
import { getLogger } from '../utils/logger.js';

/**
 * Trusted analysis step: compare a stored scan with the approved baselines
 * and produce the analysis report. Never modifies baselines.
 */

export interface AnalysisOptions {
  readonly scanPath: string;
  readonly now?: Date;
  /** Update the finding state (new/recurring tracking). Read-only commands pass false. */
  readonly updateState?: boolean;
}

export interface AnalysisOutcome {
  readonly report: AnalysisReport;
  readonly comparisons: ReadonlyMap<string, ComparisonResult>;
}

function countBy(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) if (!f.suppressed) counts[f.severity]++;
  return counts;
}

export function highestSeverity(findings: readonly Finding[]): Severity | 'none' {
  let best: Severity | 'none' = 'none';
  for (const f of findings) {
    if (f.suppressed) continue;
    if (best === 'none' || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[best]) best = f.severity;
  }
  return best;
}

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || b.score - a.score || a.id.localeCompare(b.id));
}

function headline(report: Omit<AnalysisReport, 'headline'>): string {
  const active = report.findings.filter((f) => !f.suppressed);
  const noBaseline = report.sites.filter((s) => !s.baseline.exists).map((s) => s.name);
  const parts: string[] = [];
  if (report.scanStatus !== 'complete') parts.push('The scan was incomplete, so some changes may have been missed.');
  if (noBaseline.length > 0) parts.push(`No approved baseline yet for ${noBaseline.join(', ')}: review the scan and run "thirdsentry baseline".`);
  const important = active.filter((f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.medium);
  if (active.length === 0 && noBaseline.length < report.sites.length) parts.unshift('No changes compared with the approved baseline.');
  else if (important.length === 0 && active.length > 0) parts.unshift(`${active.length} low-risk change(s) to review; nothing looks urgent.`);
  else if (important.length > 0) {
    const worst = report.highestSeverity;
    parts.unshift(`${important.length} change(s) need attention (highest severity: ${worst}). Start with the findings at the top of the list.`);
  }
  return parts.join(' ');
}

/**
 * Every site in a scan result must be a site configured in thirdsentry.yml.
 * Site names select baseline paths, and scan results / evidence may be crafted
 * or stale (renamed site), so an unknown name fails loudly instead of being
 * compared against nothing or mapped to an unexpected path.
 */
export function assertScanSitesConfigured(resolved: ResolvedConfig, siteNames: readonly string[], source: string): void {
  const configured = new Set(resolved.config.sites.map((s) => s.name));
  for (const name of siteNames) {
    assertSiteName(name);
    if (!configured.has(name)) {
      throw new ConfigError(
        `${source} contains site "${name}", which is not configured in ${resolved.configPath}`,
        `Configured sites: ${[...configured].join(', ')}. If the site was renamed, scan again.`,
      );
    }
  }
}

export async function analyzeScan(resolved: ResolvedConfig, scan: ScanResult, options: AnalysisOptions): Promise<AnalysisOutcome> {
  assertScanSitesConfigured(resolved, scan.sites.map((s) => s.name), `Scan ${scan.scanId}`);
  const now = options.now ?? new Date();
  const comparisons = new Map<string, ComparisonResult>();
  const findings: Finding[] = [];
  const sites: SiteComparisonSummary[] = [];
  const policyUsage: PolicySiteUsage[] = [];

  const libraryConfig = resolved.config.libraries;
  const libraryDb = libraryConfig.detect ? await loadLibraryDb(resolved.paths.cache, { now, maxAgeDays: libraryConfig.maxDbAgeDays }) : undefined;
  for (const w of libraryDb?.info.warnings ?? []) if (libraryDb?.info.source === 'cache' || libraryDb?.info.stale) getLogger('analysis').warn(w);
  const baselines = new Map<string, Baseline | undefined>();

  for (const site of scan.sites) {
    const libraryFindings = libraryDb ? buildLibraryFindings(site, { db: libraryDb, libraries: libraryConfig, risk: resolved.config.risk, now }) : [];
    findings.push(...libraryFindings);
    const baseline = await loadBaseline(resolved.paths, site.name);
    baselines.set(site.name, baseline);
    const path = relative(resolved.baseDir, baselinePath(resolved.paths, site.name)) || baselinePath(resolved.paths, site.name);
    if (!baseline) {
      policyUsage.push(usageWithoutBaseline(site, resolved.config, now));
      sites.push({
        name: site.name,
        url: site.url,
        status: site.status,
        baseline: { exists: false, path },
        unchangedResources: 0,
        newResources: 0,
        modifiedResources: 0,
        removedResources: 0,
        newDomains: [],
        pagesNotCompared: site.pages.map((p) => p.key),
        findings: libraryFindings.length,
      });
      continue;
    }
    const applied = compareSiteWithPolicies(site, baseline, resolved.config, { domains: resolved.config.domains, now });
    const comparison = applied.comparison;
    policyUsage.push(applied.usage);
    comparisons.set(site.name, comparison);
    const siteFindings = buildFindings(comparison.changes, {
      site: applied.site,
      risk: resolved.config.risk,
      rules: resolved.config.rules,
      domains: resolved.config.domains,
      now,
    }).filter((f) => !isSilentPolicyFinding(f));
    findings.push(...siteFindings);
    const kinds = comparison.changes.map((c) => c.kind);
    const lastApproval = baseline.approvals.at(-1);
    sites.push({
      name: site.name,
      url: site.url,
      status: site.status,
      baseline: {
        exists: true,
        path,
        approvedAt: baseline.updatedAt,
        resources: baseline.resources.length,
        ...(lastApproval ? { sourceScanId: lastApproval.scanId } : {}),
      },
      unchangedResources: comparison.unchanged,
      newResources: kinds.filter((k) => k === 'resource-added').length,
      modifiedResources: kinds.filter((k) => k === 'resource-modified' || k === 'resource-formatting-changed' || k === 'policy-accepted-update').length,
      removedResources: kinds.filter((k) => k === 'resource-removed').length,
      newDomains: [...new Set(comparison.changes.filter((c) => c.kind === 'new-script-domain' || c.kind === 'new-outbound-domain').map((c) => c.domain ?? ''))].filter(Boolean).sort(),
      pagesNotCompared: comparison.pagesNotCompared,
      findings: siteFindings.length + libraryFindings.length,
    });
  }

  // Scan health (shared by `scan` and the container `analyze`): update the streaks and raise the
  // site-level scan-unhealthy finding. Read-only commands (diff, report) pass updateState: false.
  let health: ReportHealth | undefined;
  if (options.updateState) {
    const policy = resolved.config.health;
    const healthState = await loadHealthState(resolved.paths, { quarantine: true });
    const recoveries = recordScanHealth(healthState, scan, policy);
    await saveHealthState(resolved.paths, healthState);
    findings.push(...buildHealthFindings(healthState, scan.sites.map((s) => s.name), policy, now));
    health = {
      sites: scan.sites.map((s) => {
        const h = healthState.sites[s.name];
        return { name: s.name, consecutiveFailures: h?.consecutiveFailures ?? 0, ...(h?.streakStart ? { streakStart: h.streakStart } : {}), ...(h?.lastCompleteAt ? { lastCompleteAt: h.lastCompleteAt } : {}) };
      }),
      recoveries,
    };
  }

  // PCI DSS 6.4.3: script inventory (only when the site has an inventory file or justification is required).
  const pciSites: PciReportSection['sites'][number][] = [];
  for (const site of scan.sites) {
    const inventory = await loadInventory(resolved.paths, site.name);
    if (!inventory.exists && !resolved.config.pci.requireJustification) continue;
    const result = buildInventory({ site, baseline: baselines.get(site.name), entries: inventory.entries, now });
    pciSites.push(pciSectionFor(site.name, result, { path: relative(resolved.baseDir, inventory.path) || inventory.path, exists: inventory.exists }));
    if (resolved.config.pci.requireJustification) findings.push(...inventoryFindings(result, { risk: resolved.config.risk, now }));
  }

  const suppression = applySuppressions(findings, resolved.config.suppressions, { now, risk: resolved.config.risk });
  for (const e of suppression.expired) {
    getLogger('analysis').warn({ suppression: e.index, expires: e.expires }, `suppression "${e.reason}" has expired and no longer applies`);
  }
  const state = await loadFindingState(resolved.paths);
  if (options.updateState) {
    trackFindings(suppression.findings, state, now);
    await saveFindingState(resolved.paths, state);
  } else {
    annotateFindings(suppression.findings, state);
  }
  const sorted = sortFindings(suppression.findings);
  const policies = buildPolicyReport(resolved.config, policyUsage, sorted, now);
  for (const e of policies?.expired ?? []) {
    getLogger('analysis').warn({ policy: e.name, expires: e.expires }, `script policy "${e.name}" expired and no longer applies: its scripts are compared normally again`);
  }
  const libraryReport = buildLibraryReport(scan.sites, libraryDb, libraryConfig);
  const base: Omit<AnalysisReport, 'headline'> = {
    schemaVersion: 1,
    kind: 'thirdsentry-report',
    generatedAt: now.toISOString(),
    toolVersion: toolVersion(),
    scanId: scan.scanId,
    scanPath: relative(resolved.baseDir, options.scanPath) || options.scanPath,
    scanStatus: scan.status,
    scanStartedAt: scan.startedAt,
    scanFinishedAt: scan.finishedAt,
    scanSummary: scan.summary,
    scanIssues: scan.issues,
    sites,
    findings: sorted,
    findingCounts: countBy(sorted),
    highestSeverity: highestSeverity(sorted),
    coverageLimitations: scan.coverageLimitations,
    ...(health ? { health } : {}),
    ...(policies ? { policies } : {}),
    ...(libraryReport ? { libraries: libraryReport } : {}),
    ...(pciSites.length > 0 ? { pci: { requireJustification: resolved.config.pci.requireJustification, sites: pciSites } } : {}),
  };
  const recoveryNotes = (health?.recoveries ?? []).map((r) => `Recovered: scanning of ${r.site} works again after ${r.failures} failed scans (since ${r.since}).`);
  return { report: { ...base, headline: [headline(base), ...recoveryNotes].filter(Boolean).join(' ') }, comparisons };
}

export function reportJsonPath(resolved: ResolvedConfig): string {
  return join(resolved.paths.reports, 'report.json');
}

/**
 * Write report.json for a scan to reports/scans/<scan-id>/report.json and
 * atomically update the "latest" copy reports/report.json (read by the
 * `alert` command and the GitHub Action).
 */
export async function saveReportJson(resolved: ResolvedConfig, report: AnalysisReport, extraPath?: string): Promise<string> {
  const scanDir = await ensureScanReportDir(resolved.paths, report.scanId);
  const perScan = join(scanDir, 'report.json');
  await writeJsonAtomic(perScan, report);
  const path = reportJsonPath(resolved);
  await copyFileAtomic(perScan, path);
  if (extraPath) await copyFileAtomic(perScan, extraPath);
  return path;
}

export interface PublishedReports extends WrittenReports {
  /** Directory with this scan's reports (reports/scans/<scan-id>/). */
  readonly scanReportDir: string;
  /** Per-scan copies (stable paths, not overwritten by later scans). */
  readonly perScan: WrittenReports;
}

/**
 * Write reports for one scan: first to reports/scans/<scan-id>/, then as
 * atomically replaced "latest" copies in `outputDir` (default reports/).
 * With `alwaysJson`, report.json is always written and reports/report.json in
 * the storage directory is always updated, whatever the formats or outputDir.
 */
export async function publishReports(
  resolved: ResolvedConfig,
  report: AnalysisReport,
  scan: ScanResult | undefined,
  formats: readonly ReportFormat[],
  options: { outputDir?: string; alwaysJson?: boolean } = {},
): Promise<PublishedReports> {
  const scanDir = await ensureScanReportDir(resolved.paths, report.scanId);
  const perScanFormats: ReportFormat[] = options.alwaysJson && !formats.includes('json') ? [...formats, 'json'] : [...formats];
  const perScan = await writeReports(resolved, report, scan, perScanFormats, scanDir);
  const latestDir = options.outputDir ? (isAbsolute(options.outputDir) ? options.outputDir : resolve(process.cwd(), options.outputDir)) : resolved.paths.reports;
  const latest: { json?: string; sarif?: string; html?: string } = {};
  for (const format of formats) {
    const source = perScan[format];
    if (!source) continue;
    const target = join(latestDir, basename(source));
    await copyFileAtomic(source, target);
    latest[format] = target;
  }
  if (options.alwaysJson && perScan.json) {
    const storageJson = reportJsonPath(resolved);
    if (latest.json === undefined || resolve(latest.json) !== resolve(storageJson)) await copyFileAtomic(perScan.json, storageJson);
  }
  return { ...latest, scanReportDir: scanDir, perScan };
}

/** Exit-code decision for --fail-on. */
export function exceedsThreshold(report: AnalysisReport, failOn: Severity | 'none'): boolean {
  if (failOn === 'none') return false;
  return report.findings.some((f) => !f.suppressed && SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[failOn]);
}

/** Sites in the report that have no approved baseline (nothing was compared for them). */
export function sitesWithoutBaseline(report: AnalysisReport): string[] {
  return report.sites.filter((s) => !s.baseline.exists).map((s) => s.name);
}

export interface ExitPolicy {
  readonly failOn: Severity | 'none';
  /** Exit 0 instead of 3 when a scanned site has no baseline yet. */
  readonly allowMissingBaseline?: boolean;
  /** Exit 4 when alert delivery failed. */
  readonly failOnAlertError?: boolean;
  readonly alertFailed?: boolean;
}

/**
 * Exit code of `scan` and `analyze` (shared so both paths behave the same):
 *
 *   1  a finding met the --fail-on threshold (most urgent, takes precedence)
 *   4  alert delivery failed and --fail-on-alert-error was given
 *   3  the scan was incomplete, or a scanned site has no baseline (unless
 *      --allow-missing-baseline): nothing was compared for that site, so a
 *      green result would be meaningless
 *   0  otherwise
 */
export function analysisExitCode(report: AnalysisReport, policy: ExitPolicy): ExitCodeValue {
  if (exceedsThreshold(report, policy.failOn)) return ExitCode.FindingsThresholdExceeded;
  if (policy.failOnAlertError && policy.alertFailed) return ExitCode.InternalError;
  if (report.scanStatus !== 'complete') return ExitCode.ScanIncomplete;
  if (!policy.allowMissingBaseline && sitesWithoutBaseline(report).length > 0) return ExitCode.ScanIncomplete;
  return ExitCode.Ok;
}

/** First-run guidance (printed to stderr) when scanned sites have no baseline. */
export function missingBaselineNotice(report: AnalysisReport, allowMissingBaseline: boolean): string | undefined {
  const missing = report.sites.filter((s) => !s.baseline.exists);
  if (missing.length === 0) return undefined;
  return [
    `No approved baseline for ${missing.map((s) => s.name).join(', ')} (expected at ${missing.map((s) => s.baseline.path).join(', ')}), so nothing was compared.`,
    'First run? Review the scan above, then approve it with "thirdsentry baseline" and commit the baseline file.',
    'Otherwise check that the baselines are committed, that storageDir points to them and that the site was not renamed.',
    allowMissingBaseline ? '(--allow-missing-baseline: not treated as an error.)' : 'Exiting with code 3. Pass --allow-missing-baseline to accept sites without a baseline.',
  ].join('\n');
}
