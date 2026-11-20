import type { Command } from 'commander';
import { loadLibraryDb } from '../../analysis/libraries/vulndb.js';
import { updateVulnDb } from '../../analysis/libraries/vulndb-update.js';
import { createNetworkPolicy, loadConfig } from '../../config/loader.js';
import { globalOptions } from '../context.js';
import { color, print, printJson } from '../output.js';

interface UpdateOptions {
  url?: string;
}

export function registerVulnDb(program: Command): void {
  const cmd = program.command('vulndb').description('Manage the JavaScript library vulnerability database (retire.js format)');

  cmd
    .command('update')
    .description('Download the retire.js vulnerability database into .thirdsentry/cache/vulndb (needs internet access; run it in the alerter/tools environment, not the analyzer)')
    .option('--url <url>', 'database URL (default: the retire.js repository on GitHub)')
    .action(async (opts: UpdateOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const policy = createNetworkPolicy(resolved.config);
      const result = await updateVulnDb(resolved.paths.cache, policy, { ...(opts.url ? { url: opts.url } : {}) });
      if (g.json) {
        printJson({ path: result.path, ...result.meta, skippedPatterns: result.skippedPatterns, skippedAdvisories: result.skippedAdvisories });
        return;
      }
      print(`${color.green('Updated')} the vulnerability database: ${result.meta.libraries} libraries, ${result.meta.advisories} advisories (${result.meta.bytes} bytes).`);
      print(color.gray(`  source ${result.meta.sourceUrl}`));
      print(color.gray(`  sha256 ${result.meta.sha256}`));
      print(color.gray(`  saved  ${result.path}`));
      if (result.skippedPatterns > 0 || result.skippedAdvisories > 0) {
        print(color.yellow(`  skipped ${result.skippedPatterns} unsafe or invalid detection pattern(s) and ${result.skippedAdvisories} advisory entries with unusable version ranges.`));
      }
    });

  cmd
    .command('status')
    .description('Show which vulnerability database the analyzer would use and how old it is')
    .action(async (_opts: unknown, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const db = await loadLibraryDb(resolved.paths.cache, { maxAgeDays: resolved.config.libraries.maxDbAgeDays });
      if (g.json) {
        printJson(db.info);
        return;
      }
      const i = db.info;
      print(`Source: ${i.source === 'cache' ? 'cached download' : 'bundled seed (small)'}`);
      if (i.sourceUrl) print(`URL: ${i.sourceUrl}`);
      if (i.fetchedAt) print(`Fetched: ${i.fetchedAt}${i.ageDays !== undefined ? ` (${i.ageDays} days ago)` : ''}`);
      print(`Libraries: ${i.libraries}, advisories: ${i.advisories}`);
      for (const w of i.warnings) print(color.yellow(`warning: ${w}`));
    });
}
