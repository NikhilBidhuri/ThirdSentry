import type { Command } from 'commander';
import { createNetworkPolicy, loadConfig, type ResolvedConfig } from '../../config/loader.js';
import { ConfigSchema } from '../../config/schema.js';
import { buildLintResult, lintHeaders, lintUrl, type CspLintResult, type CspLintTarget } from '../../csp/csp-lint.js';
import { loadLatestScan } from '../../storage/filesystem-store.js';
import { ConfigError, ThirdSentryError } from '../../utils/errors.js';
import { ExitCode } from '../../utils/exit-codes.js';
import { globalOptions } from '../context.js';
import { color, print, printJson } from '../output.js';

interface CspLintOptions {
  fromScan?: boolean;
  site?: string;
  failOn?: string;
}

const LEVEL_COLOR = { error: color.red, warning: color.yellow, info: color.gray } as const;

function printTarget(t: CspLintTarget): void {
  print();
  print(color.bold(t.url) + (t.finalUrl && t.finalUrl !== t.url ? color.gray(` → ${t.finalUrl}`) : '') + (t.status ? color.gray(` (HTTP ${t.status})`) : ''));
  if (t.error) {
    print(color.red(`  Could not fetch: ${t.error}`));
    return;
  }
  for (const p of t.policies) print(color.gray(`  policy #${p.index + 1} (${p.disposition === 'enforce' ? 'enforced' : 'report-only'}): ${p.raw}`));
  for (const level of ['error', 'warning', 'info'] as const) {
    for (const f of t.findings.filter((x) => x.level === level)) {
      print(`  ${LEVEL_COLOR[level](level.toUpperCase().padEnd(7))} ${f.title}${f.directive ? color.gray(` [${f.directive}]`) : ''}${f.policyIndex !== undefined && t.policies.length > 1 ? color.gray(` (policy #${f.policyIndex + 1})`) : ''}`);
      if (f.detail) print(color.gray(`          ${f.detail}`));
      print(`          ${f.explanation}`);
      print(`          ${color.cyan('fix:')} ${f.recommendation}`);
    }
  }
}

async function tryLoadConfig(configPath?: string): Promise<ResolvedConfig | undefined> {
  try {
    return await loadConfig({ ...(configPath ? { configPath } : {}) });
  } catch (error) {
    if (configPath) throw error;
    if (error instanceof ConfigError && /No ThirdSentry configuration found/.test(error.message)) return undefined;
    throw error;
  }
}

export function registerCspLint(program: Command): void {
  program
    .command('csp-lint')
    .description('Analyse Content-Security-Policy headers of a URL (or of pages captured by the latest scan)')
    .argument('[urls...]', 'URLs to fetch and analyse')
    .option('--from-scan', 'analyse the CSP headers captured by the latest scan instead of fetching')
    .option('-s, --site <names>', 'with --from-scan: only these sites')
    .option('--fail-on <level>', 'exit with code 1 if a finding has this level or worse: error, warning, info or none', 'none')
    .action(async (urls: string[], opts: CspLintOptions, command: Command) => {
      const g = globalOptions(command);
      if (!['error', 'warning', 'info', 'none'].includes(opts.failOn ?? 'none')) throw new ConfigError(`Invalid --fail-on "${opts.failOn ?? ''}"`, 'Use error, warning, info or none');
      const resolved = await tryLoadConfig(g.config);
      const targets: CspLintTarget[] = [];
      if (opts.fromScan) {
        if (!resolved) throw new ConfigError('--from-scan needs a ThirdSentry configuration', 'Run inside a project with thirdsentry.yml or pass --config.');
        const scan = await loadLatestScan(resolved.paths);
        const names = opts.site?.split(',').map((s) => s.trim());
        for (const site of scan.sites.filter((s) => !names || names.includes(s.name))) {
          for (const page of site.pages) {
            if (page.status === 'failed') continue;
            targets.push(lintHeaders(page.finalUrl ?? page.url, page.cspHeaders, page.cspReportOnlyHeaders, 'scan'));
          }
        }
      }
      if (urls.length > 0) {
        // Network policy from the project config if present, otherwise safe defaults.
        const policy = createNetworkPolicy(resolved?.config ?? ConfigSchema.parse({ sites: [{ name: 'csp-lint', url: 'https://example.invalid' }] }));
        for (const url of urls) {
          try {
            targets.push(await lintUrl(url, policy));
          } catch (error) {
            if (error instanceof ThirdSentryError) throw error;
            targets.push({ url, source: 'fetch', policies: [], findings: [], scriptsRestricted: false, error: error instanceof Error ? error.message : String(error) });
          }
        }
      }
      if (targets.length === 0) throw new ConfigError('Nothing to analyse', 'Pass one or more URLs, or --from-scan.');
      const result: CspLintResult = buildLintResult(targets);
      if (g.json) printJson(result);
      else {
        for (const t of targets) printTarget(t);
        print();
        print(`${result.counts.error} error(s), ${result.counts.warning} recommendation(s), ${result.counts.info} note(s).`);
        print(color.gray(result.disclaimer));
      }
      const order = { info: 0, warning: 1, error: 2 } as const;
      const threshold = opts.failOn ?? 'none';
      const failed = threshold !== 'none' && targets.some((t) => t.error !== undefined || t.findings.some((f) => order[f.level] >= order[threshold as keyof typeof order]));
      if (failed) process.exitCode = ExitCode.FindingsThresholdExceeded;
      else if (targets.some((t) => t.error)) process.exitCode = ExitCode.ScanIncomplete;
    });
}
