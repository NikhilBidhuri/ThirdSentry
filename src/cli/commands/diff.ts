import { resolve } from 'node:path';
import type { Command } from 'commander';
import { loadConfig } from '../../config/loader.js';
import { analyzeScan, exceedsThreshold } from '../../monitoring/analysis-runner.js';
import { loadBaseline } from '../../baseline/baseline-manager.js';
import { diffScripts } from '../../analysis/structural-diff.js';
import { ContentStore, loadLatestScan, loadScanResult } from '../../storage/filesystem-store.js';
import type { AnalysisReport } from '../../types/report.js';
import type { Finding } from '../../types/findings.js';
import { ExitCode } from '../../utils/exit-codes.js';
import type { ResolvedConfig } from '../../config/loader.js';
import { globalOptions } from '../context.js';
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
        message: resolved.config.retention.storeScriptContent
          ? 'One of the versions is not in the local content cache (it was captured before content retention was enabled, or was cleaned up). Hashes and behaviour indicators are still compared.'
          : 'Script content is not retained by default (retention.storeScriptContent: false), so only hashes can be compared. Enable it to see code diffs for future changes.',
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
    .option('--finding <id>', 'show only this finding')
    .option('--context <lines>', 'context lines in code diffs', '3')
    .option('--fail-on <severity>', 'exit with code 1 if a finding is at least this severe (info|low|medium|high|critical|none)')
    .action(async (opts: DiffOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const failOn = parseFailOn(opts.failOn, resolved.config.failOn);
      const scanPath = opts.scan ? resolve(opts.scan) : resolved.paths.latestScan;
      let scan = opts.scan ? await loadScanResult(scanPath) : await loadLatestScan(resolved.paths);
      const names = opts.site?.split(',').map((s) => s.trim()).filter(Boolean);
      if (names) scan = { ...scan, sites: scan.sites.filter((s) => names.includes(s.name)) };
      const { report } = await analyzeScan(resolved, scan, { scanPath });
      const selected = opts.finding ? report.findings.filter((f) => f.id === opts.finding) : report.findings;
      const shown: AnalysisReport = { ...report, findings: selected };
      const diffs = await codeDiffsFor(resolved, selected, Number(opts.context ?? 3) || 3);
      if (g.json) {
        printJson({ ...shown, codeDiffs: diffs });
      } else {
        printReport(shown, g.verbose === true);
        for (const d of diffs) {
          print();
          print(color.bold(`Code diff for ${d.findingId}`) + (d.mode ? color.gray(` (${d.mode})`) : ''));
          print(d.available && d.patch ? colorPatch(d.patch) : color.gray(`  ${d.message ?? 'not available'}`));
        }
      }
      if (exceedsThreshold(shown, failOn)) process.exitCode = ExitCode.FindingsThresholdExceeded;
    });
}
