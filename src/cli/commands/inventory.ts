import { resolve } from 'node:path';
import type { Command } from 'commander';
import { loadBaseline } from '../../baseline/baseline-manager.js';
import { loadConfig, type ResolvedConfig } from '../../config/loader.js';
import { applyPoliciesToBaseline, applyPoliciesToSite } from '../../policies/apply.js';
import { buildInventory, checkFailures, loadInventory, looksLikeIdentity, REQUIRED_JUSTIFICATION_FIELDS, saveInventoryEdit, type InventoryEntry, type InventoryRow } from '../../pci/inventory.js';
import { EXPORT_FORMATS, formatInventory, type ExportFormat } from '../../pci/inventory-export.js';
import { loadLatestScan, loadScanResult } from '../../storage/filesystem-store.js';
import { ConfigError } from '../../utils/errors.js';
import { ExitCode } from '../../utils/exit-codes.js';
import { writeFileAtomic } from '../../utils/fs.js';
import { globalOptions, selectScanSites } from '../context.js';
import { color, print } from '../output.js';

interface ListOptions {
  site?: string;
  all?: boolean;
  format?: string;
  check?: boolean;
  fromScan?: string;
  output?: string;
}

interface EditOptions {
  site?: string;
  purpose?: string;
  owner?: string;
  authorizedBy?: string;
  authorizedAt?: string;
  reviewBy?: string;
  notes?: string;
}

function parseFormat(value: string | undefined, json: boolean): ExportFormat {
  const f = (value ?? (json ? 'json' : 'table')).toLowerCase();
  if (!(EXPORT_FORMATS as readonly string[]).includes(f)) throw new ConfigError(`Unknown --format "${value}"`, `Use one of: ${EXPORT_FORMATS.join(', ')}`);
  return f as ExportFormat;
}

/** The single site an edit applies to: --site, or the only configured site. */
function editSite(resolved: ResolvedConfig, site: string | undefined): string {
  const configured = resolved.config.sites.map((s) => s.name);
  if (site !== undefined) {
    if (!configured.includes(site)) throw new ConfigError(`Unknown site: ${site}`, `Configured sites: ${configured.join(', ')}`);
    return site;
  }
  if (configured.length === 1) return configured[0] as string;
  throw new ConfigError('--site is required when several sites are configured', `Configured sites: ${configured.join(', ')}`);
}

function addDays(date: Date, days: number): string {
  return new Date(date.getTime() + days * 86_400_000).toISOString().slice(0, 10);
}

async function runList(opts: ListOptions, command: Command): Promise<void> {
  const g = globalOptions(command);
  const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
  const format = parseFormat(opts.format, g.json === true);
  const scan = opts.fromScan ? await loadScanResult(resolve(opts.fromScan)) : await loadLatestScan(resolved.paths);
  const sites = selectScanSites(resolved, scan, opts.site);
  const all: InventoryRow[] = [];
  const unmatched: InventoryEntry[] = [];
  for (const site of sites) {
    const [baseline, inventory] = await Promise.all([loadBaseline(resolved.paths, site.name), loadInventory(resolved.paths, site.name)]);
    // Same view as the analysis: scripts governed by a script policy are one row under the
    // policy identity (a renamed bundle stays approved and keeps its inventory status).
    const now = new Date();
    const result = buildInventory({
      site: applyPoliciesToSite(site, resolved.config, now),
      baseline: baseline ? applyPoliciesToBaseline(baseline, resolved.config, now) : undefined,
      entries: inventory.entries,
    });
    all.push(...result.rows);
    unmatched.push(...result.unmatchedEntries);
    const unsure = site.pages.filter((p) => p.sensitive && p.status !== 'complete');
    if (opts.check && unsure.length > 0) {
      process.stderr.write(`${color.yellow('Warning:')} ${site.name}: sensitive page(s) not scanned completely (${unsure.map((p) => p.key).join(', ')}); the check may miss scripts.\n`);
    }
  }
  const rows = opts.all ? all : all.filter((r) => r.sensitive);
  const out = formatInventory({ rows, unmatchedEntries: unmatched }, format);
  if (opts.output) {
    await writeFileAtomic(resolve(opts.output), out);
    print(color.green(`Wrote ${rows.length} script(s) to ${resolve(opts.output)}`));
  } else {
    process.stdout.write(out);
  }
  if (format === 'table' && !opts.output) {
    const count = (s: string): number => rows.filter((r) => r.status === s).length;
    print();
    print(`${rows.length} script(s)${opts.all ? '' : ' on sensitive pages'}: ${count('authorized')} authorized, ${count('missing-justification')} missing justification, ${count('review-overdue')} review overdue, ${count('not-approved')} not approved`);
    if (unmatched.length > 0) print(color.gray(`${unmatched.length} inventory entr${unmatched.length === 1 ? 'y matches' : 'ies match'} no script in this scan (stale or mistyped).`));
    if (!opts.all && rows.length === 0) print(color.gray('No scripts on sensitive pages. Mark pages with "sensitivePages" in thirdsentry.yml, or use --all.'));
  }
  if (opts.check) {
    const failures = checkFailures(all);
    if (failures.length > 0) {
      process.stderr.write(`${color.red('Inventory check failed:')} ${failures.length} script(s) on sensitive pages lack a justification or are overdue for review.\n`);
      for (const f of failures.slice(0, 20)) process.stderr.write(`  ${f.status}: ${f.url} (${f.issues.join('; ')})\n`);
      process.exitCode = ExitCode.FindingsThresholdExceeded;
    }
  }
}

async function runEdit(mode: 'add' | 'set', target: string, command: Command): Promise<void> {
  const opts = command.optsWithGlobals<EditOptions>();
  const g = globalOptions(command);
  const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
  const site = editSite(resolved, opts.site);
  const now = new Date();
  const fields = {
    purpose: opts.purpose,
    owner: opts.owner,
    authorizedBy: opts.authorizedBy,
    authorizedAt: opts.authorizedAt ?? (mode === 'add' && opts.authorizedBy ? now.toISOString().slice(0, 10) : undefined),
    reviewBy: opts.reviewBy ?? (mode === 'add' && opts.authorizedBy ? addDays(now, resolved.config.pci.reviewIntervalDays) : undefined),
    notes: opts.notes,
  };
  const path = await saveInventoryEdit(resolved.paths, site, target, fields, mode);
  const inventory = await loadInventory(resolved.paths, site);
  const key = looksLikeIdentity(target) ? 'identity' : 'url';
  const entry = inventory.entries.find((e) => e[key] === target);
  const missing = REQUIRED_JUSTIFICATION_FIELDS.filter((f) => !entry?.[f]);
  print(color.green(`${mode === 'add' ? 'Added' : 'Updated'} inventory entry for ${target} in ${path}`));
  if (missing.length > 0) print(color.yellow(`The entry is still incomplete (missing: ${missing.join(', ')}). Complete it with "thirdsentry inventory set".`));
  print(color.gray('Only the inventory file was changed; baselines are untouched. Commit the file after review.'));
}

export function registerInventory(program: Command): void {
  const inventory = program
    .command('inventory')
    .description('PCI DSS 6.4.3: list the scripts of the latest scan with justification, owner, baseline approval and integrity status')
    .option('-s, --site <names>', 'only these sites (comma separated; for add/set: the site whose inventory is edited)')
    .option('--all', 'include scripts on pages that are not marked sensitive')
    .option('--format <format>', `output format: ${EXPORT_FORMATS.join('|')} (default: table, or json with --json)`)
    .option('--check', 'exit with code 1 if a script on a sensitive page lacks a justification or is overdue for review')
    .option('--from-scan <file>', 'scan result to use (default: the latest scan)')
    .option('-o, --output <file>', 'write the export to a file instead of stdout')
    .action(async (opts: ListOptions, command: Command) => runList(opts, command));

  const editOptions = (c: Command): Command =>
    c
      .option('--purpose <text>', 'business/technical justification: why is the script needed?')
      .option('--owner <name>', 'team or person responsible for the script')
      .option('--authorized-by <name>', 'who authorized the script')
      .option('--authorized-at <date>', 'authorization date (YYYY-MM-DD; default today)')
      .option('--review-by <date>', 'date by which the justification must be reviewed (YYYY-MM-DD; default per pci.reviewIntervalDays)')
      .option('--notes <text>', 'free-form notes');

  editOptions(inventory.command('add <identity-or-url>').description('add an inventory entry (edits .thirdsentry/inventory/<site>.yml only; never touches baselines)')).action(
    async (target: string, _opts: EditOptions, command: Command) => runEdit('add', target, command),
  );
  editOptions(inventory.command('set <identity-or-url>').description('update fields of an existing inventory entry')).action(
    async (target: string, _opts: EditOptions, command: Command) => runEdit('set', target, command),
  );
}
