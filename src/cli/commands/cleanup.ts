import { rm } from 'node:fs/promises';
import type { Command } from 'commander';
import { loadConfig } from '../../config/loader.js';
import { baselineContentHashes } from '../../monitoring/scan-manager.js';
import { findingStatePath } from '../../monitoring/dedup-state.js';
import { applyRetention } from '../../storage/filesystem-store.js';
import { ConfigError } from '../../utils/errors.js';
import { globalOptions } from '../context.js';
import { color, print, printJson } from '../output.js';

interface CleanupOptions {
  olderThan?: string;
  keep?: string;
  allContent?: boolean;
  includeReferenced?: boolean;
  resetState?: boolean;
  dryRun?: boolean;
}

function positiveInt(value: string | undefined, name: string): number | undefined {
  if (value === undefined) return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new ConfigError(`${name} must be a non-negative integer`);
  return n;
}

export function registerCleanup(program: Command): void {
  program
    .command('cleanup')
    .description('Delete old scan results, screenshots and cached script content (baselines are never touched)')
    .option('--older-than <days>', 'delete data older than this many days (default: retention.maxAgeDays)')
    .option('--keep <n>', 'keep at most this many scan results per site (default: retention.maxScanReports)')
    .option('--all-content', 'delete all cached script bodies (except those referenced by baselines)')
    .option('--include-referenced', 'with --all-content: also delete content referenced by baselines (code diffs become unavailable)')
    .option('--reset-state', 'also delete finding/alert state (findings will be reported and alerted as new)')
    .option('--dry-run', 'only show what would be deleted')
    .action(async (opts: CleanupOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const result = await applyRetention(resolved.paths, {
        maxScans: positiveInt(opts.keep, '--keep') ?? resolved.config.retention.maxScanReports,
        maxAgeDays: positiveInt(opts.olderThan, '--older-than') ?? resolved.config.retention.maxAgeDays,
        purgeContent: opts.allContent === true,
        purgeReferenced: opts.includeReferenced === true,
        keepContent: await baselineContentHashes(resolved),
        dryRun: opts.dryRun === true,
      });
      if (opts.resetState && !opts.dryRun) await rm(findingStatePath(resolved.paths), { force: true });
      if (g.json) printJson({ ...result, stateReset: opts.resetState === true && !opts.dryRun });
      else {
        const verb = result.dryRun ? 'Would delete' : 'Deleted';
        print(`${verb} ${result.removedScans} scan result(s), ${result.removedScreenshots} screenshot folder(s) and ${result.removedContent} cached script body(ies).`);
        if (result.keptReferencedContent > 0) print(color.gray(`Kept ${result.keptReferencedContent} cached body(ies) referenced by approved baselines (use --include-referenced to delete them).`));
        if (opts.resetState) print(result.dryRun ? 'Would reset finding state.' : 'Finding state reset.');
      }
    });
}
