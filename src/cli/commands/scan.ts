import { copyFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { Command } from 'commander';
import { loadConfig, selectSites } from '../../config/loader.js';
import { runScan } from '../../monitoring/scan-manager.js';
import { shortHash } from '../../analysis/hashing.js';
import type { ScanResult } from '../../types/index.js';
import { ExitCode } from '../../utils/exit-codes.js';
import { analyzeScan, exceedsThreshold, saveReportJson } from '../../monitoring/analysis-runner.js';
import { globalOptions, logLevelFor } from '../context.js';
import { parseFailOn } from '../fail-on.js';
import { printReport } from '../findings-output.js';
import { color, pad, print, printJson, statusLabel, truncateMiddle } from '../output.js';

export interface ScanCommandOptions {
  site?: string;
  output?: string;
  failOn?: string;
  format?: string;
  skipPreflight?: boolean;
}

export function printScanSummary(result: ScanResult, verbose: boolean): void {
  const s = result.summary;
  print(color.bold(`Scan ${result.scanId}: ${statusLabel(result.status)}`));
  print(
    `  ${s.sites} site(s), ${s.pages} page(s) [${s.pagesComplete} complete, ${s.pagesPartial} partial, ${s.pagesFailed} failed], ` +
      `${s.resources} script resource(s) (${s.firstPartyResources} first-party, ${s.thirdPartyResources} third-party), ` +
      `${s.thirdPartyDomains} third-party domain(s)`,
  );
  if (s.blockedConnections > 0) print(color.yellow(`  ${s.blockedConnections} connection(s) blocked by the network policy`));
  for (const site of result.sites) {
    print();
    print(`${color.bold(site.name)} ${color.gray(site.url)} — ${statusLabel(site.status)} ${color.gray(`(${site.browser.name} ${site.browser.version})`)}`);
    for (const issue of site.issues) print(`  ${issue.level === 'error' ? color.red('!') : color.yellow('!')} ${issue.message}`);
    for (const page of site.pages) {
      print(`  ${pad(statusLabel(page.status), 10)} ${page.key}  ${color.gray(`${page.resourceKeys.length} scripts, ${page.requests.length} requests`)}`);
      for (const issue of page.issues) {
        if (issue.level === 'info' && !verbose) continue;
        print(`      ${issue.level === 'error' ? color.red(issue.code) : color.yellow(issue.code)}: ${issue.message}`);
      }
    }
    if (site.resources.length > 0) {
      print();
      print(`  ${pad('TYPE', 16)} ${pad('PARTY', 6)} ${pad('SHA-256', 14)} RESOURCE`);
      for (const r of site.resources) {
        const label = r.finalUrl ?? r.originalUrl ?? r.identity;
        const flags = [r.dynamic ? 'dynamic' : '', r.content.status !== 'captured' ? r.content.status : '', r.sri?.valid === false ? 'SRI-MISMATCH' : '']
          .filter(Boolean)
          .join(',');
        print(
          `  ${pad(r.type, 16)} ${pad(r.party === 'third-party' ? color.magenta('3rd') : '1st', 6)} ${pad(shortHash(r.hashes.sha256), 14)} ${truncateMiddle(label, 100)}${flags ? color.gray(` [${flags}]`) : ''}`,
        );
      }
    }
    if (site.domains.outbound.length > 0) {
      print();
      print(`  Outbound domains: ${site.domains.outbound.join(', ')}`);
    }
  }
}

export function registerScan(program: Command): void {
  program
    .command('scan')
    .description('Visit the configured pages in a real browser and record the JavaScript they load')
    .option('-s, --site <names>', 'only scan these sites (comma separated)')
    .option('-o, --output <file>', 'also write the scan result JSON to this file')
    .option('--fail-on <severity>', 'exit with code 1 if a finding is at least this severe (info|low|medium|high|critical|none)')
    .option('--skip-preflight', 'skip DNS pre-flight checks (connections are still validated by the egress proxy)')
    .action(async (opts: ScanCommandOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const failOn = parseFailOn(opts.failOn, resolved.config.failOn);
      const sites = selectSites(resolved, opts.site);
      const run = await runScan(resolved, { sites, logLevel: logLevelFor(g), ...(opts.skipPreflight ? { skipPreflight: true } : {}) });
      if (opts.output) {
        const target = resolve(opts.output);
        await mkdir(dirname(target), { recursive: true });
        await copyFile(run.scanPath, target);
      }
      const { report } = await analyzeScan(resolved, run.result, { scanPath: run.scanPath });
      const reportPath = await saveReportJson(resolved, report);
      if (g.json) printJson({ scan: run.result, report });
      else {
        printScanSummary(run.result, g.verbose === true);
        printReport(report, g.verbose === true);
        print();
        print(color.gray(`Scan saved to ${run.scanPath}`));
        print(color.gray(`Report saved to ${reportPath}`));
      }
      if (exceedsThreshold(report, failOn)) process.exitCode = ExitCode.FindingsThresholdExceeded;
      else if (run.result.status !== 'complete') process.exitCode = ExitCode.ScanIncomplete;
    });
}
