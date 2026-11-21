import { join } from 'node:path';
import type { Command } from 'commander';
import { loadConfig, selectSites } from '../../config/loader.js';
import { loadHealthState } from '../../health/health-state.js';
import { enabledAlertChannels } from '../../health/metrics.js';
import { computeStatus, type StatusSummary } from '../../health/status.js';
import { baselinePath } from '../../storage/paths.js';
import type { AnalysisReport } from '../../types/report.js';
import { pathExists, readJsonFile } from '../../utils/fs.js';
import { ConfigError } from '../../utils/errors.js';
import { globalOptions } from '../context.js';
import { color, pad, print, printJson } from '../output.js';

interface StatusOptions {
  site?: string;
  maxAge?: string;
}

function parseMaxAge(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) throw new ConfigError(`--max-age must be a positive number of hours (got "${value}")`);
  return n;
}

const STATE_COLOR = { healthy: color.green, degraded: color.yellow, unhealthy: color.red, unknown: color.gray } as const;

export function printStatus(summary: StatusSummary): void {
  print(color.bold(`ThirdSentry status: ${STATE_COLOR[summary.overall](summary.overall)}`));
  for (const s of summary.sites) {
    print();
    print(`${color.bold(s.name)}  ${STATE_COLOR[s.state](s.state)}${s.reasons.length ? color.gray(` (${s.reasons.join('; ')})`) : ''}`);
    print(`  ${pad('last scan', 20)} ${s.lastScanAt ?? 'never'}${s.lastStatus ? ` (${s.lastStatus})` : ''}`);
    print(`  ${pad('last complete scan', 20)} ${s.lastCompleteAt ?? 'never'}`);
    print(`  ${pad('consecutive failures', 20)} ${s.consecutiveFailures}${s.streakStart ? color.gray(` since ${s.streakStart}`) : ''}`);
    if (s.lastError) print(`  ${pad('last error', 20)} ${s.lastError}`);
    const open = (['critical', 'high', 'medium', 'low', 'info'] as const).filter((k) => s.openFindings[k] > 0).map((k) => `${s.openFindings[k]} ${k}`);
    print(`  ${pad('open findings', 20)} ${open.length ? open.join(', ') : 'none'}`);
    print(`  ${pad('baseline', 20)} ${s.baselinePresent ? 'present' : color.yellow('missing')}`);
  }
  if (summary.channels.length > 0) {
    print();
    print(color.bold('Alert channels'));
    for (const c of summary.channels) {
      print(`  ${pad(c.channel, 10)} ${STATE_COLOR[c.state](c.state)}${c.consecutiveFailures ? color.gray(` (${c.consecutiveFailures} failed deliveries in a row${c.lastError ? `: ${c.lastError}` : ''})`) : ''}${c.lastSuccessAt ? color.gray(` last success ${c.lastSuccessAt}`) : ''}`);
    }
  }
}

export function registerStatus(program: Command): void {
  program
    .command('status')
    .description('Summarise scan health, open findings, baselines and alert channels (read-only; exit 1 unhealthy, 3 no data)')
    .option('-s, --site <names>', 'only these sites (comma separated)')
    .option('--max-age <hours>', 'treat a site whose last scan finished longer ago than this as unhealthy')
    .action(async (opts: StatusOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const sites = selectSites(resolved, opts.site).map((s) => s.name);
      const maxAgeHours = parseMaxAge(opts.maxAge);
      const health = await loadHealthState(resolved.paths);
      const reportPath = join(resolved.paths.reports, 'report.json');
      let report: AnalysisReport | undefined;
      if (await pathExists(reportPath)) {
        const data = (await readJsonFile(reportPath, 256 * 1024 * 1024).catch(() => undefined)) as Partial<AnalysisReport> | undefined;
        if (data?.kind === 'thirdsentry-report' && Array.isArray(data.findings)) report = data as AnalysisReport;
      }
      const baselinePresent: Record<string, boolean> = {};
      for (const name of sites) baselinePresent[name] = await pathExists(baselinePath(resolved.paths, name));
      const summary = computeStatus({
        now: new Date(),
        sites,
        health,
        ...(report ? { report } : {}),
        baselinePresent,
        enabledChannels: enabledAlertChannels(resolved.config.alerts),
        policy: resolved.config.health,
        ...(maxAgeHours !== undefined ? { maxAgeHours } : {}),
      });
      if (g.json) printJson(summary);
      else printStatus(summary);
      if (summary.exitCode !== 0) process.exitCode = summary.exitCode;
    });
}
