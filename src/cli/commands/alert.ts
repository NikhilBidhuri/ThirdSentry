import { resolve } from 'node:path';
import type { Command } from 'commander';
import { CHANNELS, sendAlerts, type AlertRunResult, type ChannelName } from '../../alerts/alert-manager.js';
import { loadConfig } from '../../config/loader.js';
import { recordAlertHealth } from '../../health/run-health.js';
import { sendRunHeartbeat } from '../../health/heartbeat.js';
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
  test?: boolean;
  heartbeat?: boolean;
}

const NO_CHANNEL = 'no alert channel is enabled (set alerts.<slack|webhook|github|email>.enabled: true in thirdsentry.yml)';

export function printAlertResult(result: AlertRunResult): void {
  const label = result.test ? 'Test alert' : 'Alert';
  if (result.channels.length === 0) {
    print(color.gray(`${result.dryRun ? 'Dry run: ' : 'Alerts: '}${NO_CHANNEL}.`));
    return;
  }
  if (result.dryRun) {
    if (result.results.length === 0) {
      print(`Dry run: nothing new to send through ${result.channels.join(', ')}.`);
      return;
    }
    print(`Dry run: ${result.selected} finding(s) selected.`);
    for (const r of result.results) print(`  ${r.channel}: ${r.detail ?? `${r.selected} finding(s) would be sent`}`);
    return;
  }
  if (result.results.length === 0) {
    print(color.gray('Alerts: nothing new to send.'));
    return;
  }
  for (const r of result.results) {
    if (r.ok) print(color.green(`${label} via ${r.channel}: ${r.delivered} finding(s)${r.detail ? ` (${r.detail})` : ''}`));
    else print(color.red(`${label} via ${r.channel} failed after ${r.attempts} attempt(s)${r.delivered ? ` (${r.delivered} delivered)` : ''}: ${r.error ?? 'unknown error'}`));
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
    .option('--test', 'send a clearly-labelled test alert through each enabled channel (no report needed; alert state is not changed)')
    .option('--no-heartbeat', 'do not send the health.heartbeat ping')
    .action(async (opts: AlertOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const channels = opts.channel?.split(',').map((c) => c.trim()).filter(Boolean);
      const unknown = channels?.filter((c) => !(CHANNELS as readonly string[]).includes(c)) ?? [];
      if (unknown.length) throw new ConfigError(`Unknown alert channel(s): ${unknown.join(', ')}`, `Use: ${CHANNELS.join(', ')}`);
      const report = opts.test ? undefined : await loadReport(opts.report ? resolve(opts.report) : reportJsonPath(resolved));
      const result = await sendAlerts(resolved, report, {
        ...(channels ? { channels: channels as ChannelName[] } : {}),
        ...(opts.dryRun ? { dryRun: true } : {}),
        ...(opts.test ? { test: true } : {}),
      });
      const alertFailed = result.results.some((r) => !r.ok);
      await recordAlertHealth(resolved, result);
      // Dead-man's switch: only after a real run (not --test / --dry-run), by the component that has network access.
      const heartbeat = report && !opts.dryRun && opts.heartbeat !== false ? await sendRunHeartbeat(resolved.config.health.heartbeat, report, { alertFailed }) : undefined;
      if (g.json) printJson(heartbeat ? { ...result, heartbeat } : result);
      else printAlertResult(result);
      if (alertFailed) process.exitCode = ExitCode.InternalError;
      // A test with nothing to test is a failed check.
      else if (opts.test && result.channels.length === 0) process.exitCode = ExitCode.ConfigError;
    });
}
