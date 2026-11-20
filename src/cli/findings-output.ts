import { libraryDisplayName } from '../analysis/libraries/describe.js';
import { explainScore } from '../analysis/risk-scoring.js';
import type { Finding } from '../types/findings.js';
import type { AnalysisReport } from '../types/report.js';
import { color, print, severityLabel } from './output.js';

export function printFinding(f: Finding, verbose: boolean): void {
  const status = f.status === 'recurring' ? color.gray(' (seen before)') : '';
  const suppressed = f.suppressed ? color.gray(` [suppressed: ${f.suppressed.reason}]`) : '';
  print(`${severityLabel(f.severity)} ${color.gray(`confidence ${f.confidence}`)} ${color.bold(f.title)} ${color.gray(f.id)}${status}${suppressed}`);
  if (f.resourceUrl) print(`    ${f.resourceUrl}`);
  print(`    ${f.reason}`);
  if (f.previousHash !== undefined || f.currentHash !== undefined) {
    print(color.gray(`    previous ${f.previousHash ?? 'none'}`));
    print(color.gray(`    current  ${f.currentHash ?? 'none'}`));
  }
  print(color.gray(`    why: ${explainScore(f.signals)}`));
  if (verbose) for (const e of f.evidence) print(color.gray(`    ${e.label}: ${e.value}`));
  print(`    ${color.cyan('next:')} ${f.recommendedAction.replace('<finding-id>', f.id)}`);
}

/** Recognised libraries and vulnerability database status. */
export function printLibraries(report: AnalysisReport): void {
  const libs = report.libraries;
  if (!libs || (libs.inventory.length === 0 && !libs.db.stale)) return;
  print();
  print(color.bold(`Libraries (${libs.inventory.length})`));
  for (const l of libs.inventory) {
    const vuln = l.advisories.length > 0 ? color.red(` ${l.advisories.length} known vulnerabilit${l.advisories.length === 1 ? 'y' : 'ies'} (${l.advisories.slice(0, 3).join(', ')}${l.advisories.length > 3 ? ', ...' : ''})`) : '';
    print(`  ${l.site}: ${libraryDisplayName(l.name)} ${l.version} ${color.gray(`(${l.method}, ${l.confidence} confidence)`)}${vuln}`);
  }
  const d = libs.db;
  print(color.gray(`  vulnerability database: ${d.source === 'cache' ? `cached${d.fetchedAt ? `, fetched ${d.fetchedAt}` : ''}${d.ageDays !== undefined ? ` (${d.ageDays} days old)` : ''}` : 'bundled seed'}, ${d.advisories} advisories`));
  for (const w of d.warnings) print(color.yellow(`  warning: ${w}`));
}

export function printReport(report: AnalysisReport, verbose: boolean): void {
  print();
  print(color.bold('Summary: ') + report.headline);
  for (const site of report.sites) {
    if (!site.baseline.exists) {
      print(color.yellow(`  ${site.name}: no baseline (${site.baseline.path}). Run "thirdsentry baseline" after reviewing this scan.`));
      continue;
    }
    print(
      `  ${site.name}: ${site.unchangedResources} unchanged, ${site.newResources} new, ${site.modifiedResources} modified, ${site.removedResources} removed` +
        (site.newDomains.length ? `, new domains: ${site.newDomains.join(', ')}` : ''),
    );
    if (site.pagesNotCompared.length) print(color.yellow(`    removals not evaluated for incomplete pages: ${site.pagesNotCompared.join(', ')}`));
  }
  printLibraries(report);
  if (report.findings.length === 0) return;
  print();
  print(color.bold(`Findings (${report.findings.length})`));
  for (const f of report.findings) {
    print();
    printFinding(f, verbose);
  }
}
