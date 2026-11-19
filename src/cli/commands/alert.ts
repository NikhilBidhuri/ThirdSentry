import { resolve } from 'node:path';
import type { Command } from 'commander';
import { CHANNELS, sendAlerts, type AlertRunResult, type ChannelName } from '../../alerts/alert-manager.js';
import { loadConfig } from '../../config/loader.js';
import { reportJsonPath } from '../../monitoring/analysis-runner.js';
import type { AnalysisReport } from '../../types/report.js';
import { ConfigError, ThirdSentryError } from '../../utils/errors.js';
import { ExitCode } from '../../utils/exit-codes.js';
import { pathExists, readJsonFile } from '../../utils/fs.js';
import { globalOptions } from '../context.js';
import { color, print, printJson } from '../output.js';

interface AlertOptions {
  report?: string;
  channel?: string;
  dryRun?: boolean;
}

export function printAlertResult(result: AlertRunResult): void {
  if (result.dryRun) {
    print(`Dry run: ${result.selected} finding(s) would be sent.`);
    return;
  }
  if (result.results.length === 0) {
    print(color.gray(result.selected === 0 ? 'Alerts: nothing new to send.' : 'Alerts: no channel enabled.'));
    return;
  }
  for (const r of result.results) {
    if (r.ok) print(color.green(`Alert via ${r.channel}: ${r.delivered} finding(s)${r.detail ? ` (${r.detail})` : ''}`));
    else print(color.red(`Alert via ${r.channel} failed after ${r.attempts} attempt(s): ${r.error ?? 'unknown error'}`));
  }
}

export async function loadReport(path: string): Promise<AnalysisReport> {
  if (!(await pathExists(path))) throw new ThirdSentryError(`Report not found: ${path}`, { exitCode: ExitCode.ConfigError, hint: 'Run "thirdsentry scan" or "thirdsentry report" first.' });
  const data = (await readJsonFile(path)) as Partial<AnalysisReport>;
  if (data.kind !== 'thirdsentry-report' || data.schemaVersion !== 1 || !Array.isArray(data.findings)) {
    throw new ThirdSentryError(`${path} is not a ThirdSentry report`, { exitCode: ExitCode.ConfigError });
  }
  return data as AnalysisReport;
}

export function registerAlert(program: Command): void {
  program
    .command('alert')
    .description('Send alerts for new findings in a report (the only command that uses alert credentials)')
    .option('--report <file>', 'report.json to alert on (default: .thirdsentry/reports/report.json)')
    .option('--channel <names>', `only these channels (${CHANNELS.join(', ')})`)
    .option('--dry-run', 'show what would be sent without sending')
    .action(async (opts: AlertOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const channels = opts.channel?.split(',').map((c) => c.trim()).filter(Boolean);
      const unknown = channels?.filter((c) => !(CHANNELS as readonly string[]).includes(c)) ?? [];
      if (unknown.length) throw new ConfigError(`Unknown alert channel(s): ${unknown.join(', ')}`, `Use: ${CHANNELS.join(', ')}`);
      const report = await loadReport(opts.report ? resolve(opts.report) : reportJsonPath(resolved));
      const result = await sendAlerts(resolved, report, { ...(channels ? { channels: channels as ChannelName[] } : {}), ...(opts.dryRun ? { dryRun: true } : {}) });
      if (g.json) printJson(result);
      else printAlertResult(result);
      if (result.results.some((r) => !r.ok)) process.exitCode = ExitCode.InternalError;
    });
}
