import type { Command } from 'commander';
import { loadConfig, selectSites } from '../../config/loader.js';
import { runScan } from '../../monitoring/scan-manager.js';
import { shortHash } from '../../analysis/hashing.js';
import type { ScanResult } from '../../types/index.js';
import { ExitCode } from '../../utils/exit-codes.js';
import { analyzeScan, exceedsThreshold, saveReportJson } from '../../monitoring/analysis-runner.js';
import { parseFormats, writeReports } from '../../reporting/index.js';
import { sendAlerts, type AlertRunResult } from '../../alerts/alert-manager.js';
import { getLogger } from '../../utils/logger.js';
import { printAlertResult } from './alert.js';
import { globalOptions, logLevelFor } from '../context.js';
import { parseFailOn } from '../fail-on.js';
import { printReport } from '../findings-output.js';
import { color, pad, print, printJson, statusLabel, truncateMiddle } from '../output.js';

export interface ScanCommandOptions {
  site?: string;
  output?: string;
  failOn?: string;
  format?: string;
  alerts?: boolean;
  skipPreflight?: boolean;
}

/** Indicators shown in the default resource list (others appear with --verbose). */
const NOTABLE_RULES = new Set(['TS-EVAL', 'TS-NEW-FUNCTION', 'TS-SENSITIVE-FIELD-ACCESS', 'TS-KEYSTROKE-CAPTURE', 'TS-CLIPBOARD', 'TS-NETWORK-API-HOOK', 'TS-OBFUSCATION', 'TS-EXFIL-COMBINATION']);

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
        const notable = Object.keys(r.indicators?.counts ?? {}).filter((id) => verbose || NOTABLE_RULES.has(id));
        const flags = [r.dynamic ? 'dynamic' : '', r.content.status !== 'captured' ? r.content.status : '', r.sri?.valid === false ? 'SRI-MISMATCH' : '', ...notable]
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
    .description('Visit the configured pages in a real browser, compare with the baseline, write reports and send alerts')
    .option('-s, --site <names>', 'only scan these sites (comma separated)')
    .option('-o, --output <dir>', 'directory for reports (default: .thirdsentry/reports)')
    .option('-f, --format <formats>', 'report formats: json, sarif, html (default: reporting.formats)')
    .option('--fail-on <severity>', 'exit with code 1 if a finding is at least this severe (info|low|medium|high|critical|none)')
    .option('--no-alerts', 'do not send alerts even if channels are enabled')
    .option('--skip-preflight', 'skip DNS pre-flight checks (connections are still validated by the egress proxy)')
    .action(async (opts: ScanCommandOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const failOn = parseFailOn(opts.failOn, resolved.config.failOn);
      const formats = parseFormats(opts.format, resolved.config.reporting.formats);
      const sites = selectSites(resolved, opts.site);
      const run = await runScan(resolved, { sites, logLevel: logLevelFor(g), ...(opts.skipPreflight ? { skipPreflight: true } : {}) });
      const { report } = await analyzeScan(resolved, run.result, { scanPath: run.scanPath, updateState: true });
      // report.json in the storage directory is always written: diff/alert/report read it.
      await saveReportJson(resolved, report);
      const written = await writeReports(resolved, report, run.result, formats, opts.output);
      let alertResult: AlertRunResult | undefined;
      if (opts.alerts !== false) {
        try {
          alertResult = await sendAlerts(resolved, report, written.html ? { reportLocation: written.html } : {});
        } catch (error) {
          // Alerting must never destroy or invalidate scan results.
          getLogger('alerts').error({ err: error instanceof Error ? error.message : String(error) }, 'alerting failed; scan results and reports were saved');
        }
      }
      if (g.json) printJson({ scan: run.result, report, reports: written, alerts: alertResult });
      else {
        printScanSummary(run.result, g.verbose === true);
        printReport(report, g.verbose === true);
        print();
        print(color.gray(`Scan saved to ${run.scanPath}`));
        for (const [format, path] of Object.entries(written)) print(color.gray(`${format.toUpperCase()} report: ${path}`));
        if (alertResult) printAlertResult(alertResult);
      }
      if (exceedsThreshold(report, failOn)) process.exitCode = ExitCode.FindingsThresholdExceeded;
      else if (run.result.status !== 'complete') process.exitCode = ExitCode.ScanIncomplete;
    });
}
