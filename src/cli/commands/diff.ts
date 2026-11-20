import { resolve } from 'node:path';
import type { Command } from 'commander';
import { loadConfig } from '../../config/loader.js';
import { analyzeScan, exceedsThreshold } from '../../monitoring/analysis-runner.js';
import { loadBaseline } from '../../baseline/baseline-manager.js';
import { diffScripts } from '../../analysis/structural-diff.js';
import { ContentStore, loadLatestScan, loadScanResult, scriptContentMode } from '../../storage/filesystem-store.js';
import type { AnalysisReport } from '../../types/report.js';
import type { Finding } from '../../types/findings.js';
import { ConfigError } from '../../utils/errors.js';
import { ExitCode } from '../../utils/exit-codes.js';
import type { ResolvedConfig } from '../../config/loader.js';
import { globalOptions, parseNonNegativeInt, selectScanSites } from '../context.js';
import { parseFailOn } from '../fail-on.js';
import { printReport } from '../findings-output.js';
import { color, print, printJson } from '../output.js';

interface DiffOptions {
  site?: string;
  scan?: string;
  finding?: string;
  context?: string;
  failOn?: string;
}

export interface CodeDiffResult {
  readonly findingId: string;
  readonly available: boolean;
  readonly message?: string;
  readonly mode?: string;
  readonly patch?: string;
}

/** Produce code diffs for modified-resource findings when both versions are in the content store. */
export async function codeDiffsFor(resolved: ResolvedConfig, findings: readonly Finding[], context: number): Promise<CodeDiffResult[]> {
  const store = new ContentStore(resolved.paths.content);
  const out: CodeDiffResult[] = [];
  for (const f of findings) {
    if (f.kind !== 'resource-modified' && f.kind !== 'resource-formatting-changed') continue;
    if (!f.currentHash) {
      out.push({ findingId: f.id, available: false, message: 'Current content was not captured.' });
      continue;
    }
    const baseline = await loadBaseline(resolved.paths, f.site);
    const resource = baseline?.resources.find((r) => r.identity === f.resourceIdentity);
    const previous = resource?.approvedHashes.map((h) => h.sha256).filter((h): h is string => h !== null).reverse() ?? [];
    const current = await store.get(f.currentHash);
    let old: Buffer | undefined;
    for (const sha of previous) {
      old = await store.get(sha);
      if (old) break;
    }
    if (!current || !old) {
      out.push({
        findingId: f.id,
        available: false,
        message:
          scriptContentMode(resolved.config.retention) === 'none'
            ? 'Script content is not retained (retention.scriptContent: none), so only hashes can be compared. Set retention.scriptContent to "findings" to see code diffs for future changes.'
            : 'One of the versions is not in the local content cache (it was captured before content retention was enabled, or was cleaned up by retention). Hashes and behaviour indicators are still compared.',
      });
      continue;
    }
    const d = diffScripts(old.toString('utf8'), current.toString('utf8'), { context, oldLabel: `approved ${previous[0]?.slice(0, 12) ?? ''}`, newLabel: `current ${f.currentHash.slice(0, 12)}` });
    out.push({ findingId: f.id, available: true, mode: d.mode, patch: d.patch });
  }
  return out;
}

function colorPatch(patch: string): string {
  return patch
    .split('\n')
    .map((l) => (l.startsWith('+') && !l.startsWith('+++') ? color.green(l) : l.startsWith('-') && !l.startsWith('---') ? color.red(l) : l.startsWith('@@') ? color.cyan(l) : l))
    .join('\n');
}

export function registerDiff(program: Command): void {
  program
    .command('diff')
    .description('Compare the latest scan with the approved baseline and show findings and code diffs (does not scan)')
    .option('-s, --site <names>', 'only these sites (comma separated)')
    .option('--scan <file>', 'scan result to compare (default: the latest scan)')
    .option('--finding <ids>', 'show only these findings (comma separated)')
    .option('--context <lines>', 'context lines in code diffs (default 3)')
    .option('--fail-on <severity>', 'exit with code 1 if a finding is at least this severe (info|low|medium|high|critical|none)')
    .action(async (opts: DiffOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const failOn = parseFailOn(opts.failOn, resolved.config.failOn);
      const context = parseNonNegativeInt(opts.context, '--context', 3, 10_000);
      const scanPath = opts.scan ? resolve(opts.scan) : resolved.paths.latestScan;
      let scan = opts.scan ? await loadScanResult(scanPath) : await loadLatestScan(resolved.paths);
      if (opts.site !== undefined) scan = { ...scan, sites: selectScanSites(resolved, scan, opts.site) };
      const { report } = await analyzeScan(resolved, scan, { scanPath });
      const findingIds = opts.finding?.split(',').map((s) => s.trim()).filter(Boolean);
      if (findingIds) {
        const missing = findingIds.filter((id) => !report.findings.some((f) => f.id === id));
        if (missing.length > 0 || findingIds.length === 0) {
          throw new ConfigError(`No finding ${missing.join(', ') || '(empty)'} in scan ${scan.scanId}`, 'Run "thirdsentry diff" without --finding to list the current finding IDs.');
        }
      }
      const selected = findingIds ? report.findings.filter((f) => findingIds.includes(f.id)) : report.findings;
      const shown: AnalysisReport = { ...report, findings: selected };
      const diffs = await codeDiffsFor(resolved, selected, context);
      const approveIds = findingIds ? findingIds.join(',') : '<finding-id>[,<finding-id>...]';
      const approveCommand = `thirdsentry baseline --scan-id ${scan.scanId} --approve ${approveIds}`;
      if (g.json) {
        printJson({ ...shown, codeDiffs: diffs, ...(selected.length > 0 ? { approveCommand } : {}) });
      } else {
        print(color.bold(`Scan ${scan.scanId}`) + color.gray(` (${scan.startedAt}, ${opts.scan ? scanPath : 'latest scan'})`));
        printReport(shown, g.verbose === true);
        for (const d of diffs) {
          print();
          print(color.bold(`Code diff for ${d.findingId}`) + (d.mode ? color.gray(` (${d.mode})`) : ''));
          print(d.available && d.patch ? colorPatch(d.patch) : color.gray(`  ${d.message ?? 'not available'}`));
        }
        if (selected.length > 0) {
          print();
          print(`To approve reviewed changes from exactly this scan: ${color.bold(approveCommand)}`);
        }
      }
      if (exceedsThreshold(shown, failOn)) process.exitCode = ExitCode.FindingsThresholdExceeded;
    });
}
