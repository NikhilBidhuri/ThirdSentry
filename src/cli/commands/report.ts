import { resolve } from 'node:path';
import type { Command } from 'commander';
import { loadConfig } from '../../config/loader.js';
import { analyzeScan, exceedsThreshold } from '../../monitoring/analysis-runner.js';
import { parseFormats, writeReports } from '../../reporting/index.js';
import { loadLatestScan, loadScanResult } from '../../storage/filesystem-store.js';
import { ExitCode } from '../../utils/exit-codes.js';
import { globalOptions } from '../context.js';
import { parseFailOn } from '../fail-on.js';
import { color, print, printJson } from '../output.js';

interface ReportOptions {
  scan?: string;
  format?: string;
  output?: string;
  failOn?: string;
}

export function registerReport(program: Command): void {
  program
    .command('report')
    .description('Generate JSON, SARIF and/or HTML reports from the latest (or a given) scan without scanning again')
    .option('--scan <file>', 'scan result to report on (default: the latest scan)')
    .option('-f, --format <formats>', 'comma separated: json, sarif, html (default: reporting.formats)')
    .option('-o, --output <dir>', 'directory to write reports to (default: .thirdsentry/reports)')
    .option('--fail-on <severity>', 'exit with code 1 if a finding is at least this severe')
    .action(async (opts: ReportOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const formats = parseFormats(opts.format, resolved.config.reporting.formats);
      const failOn = parseFailOn(opts.failOn, 'none');
      const scanPath = opts.scan ? resolve(opts.scan) : resolved.paths.latestScan;
      const scan = opts.scan ? await loadScanResult(scanPath) : await loadLatestScan(resolved.paths);
      const { report } = await analyzeScan(resolved, scan, { scanPath });
      const written = await writeReports(resolved, report, scan, formats, opts.output);
      if (g.json) printJson({ written, highestSeverity: report.highestSeverity, findings: report.findings.length });
      else {
        print(report.headline);
        for (const [format, path] of Object.entries(written)) print(color.green(`${format.toUpperCase()} report: ${path}`));
      }
      if (exceedsThreshold(report, failOn)) process.exitCode = ExitCode.FindingsThresholdExceeded;
    });
}
