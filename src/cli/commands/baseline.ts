import { createInterface } from 'node:readline/promises';
import { resolve } from 'node:path';
import type { Command } from 'commander';
import {
  approveFullScan,
  approveSelected,
  createBaseline,
  loadBaseline,
  saveBaseline,
  summarizeBaselineChange,
  type ApprovalItem,
  type BaselineChangeSummary,
} from '../../baseline/baseline-manager.js';
import type { Baseline } from '../../baseline/baseline-schema.js';
import { loadConfig } from '../../config/loader.js';
import { compareSite, type Change } from '../../monitoring/comparison-engine.js';
import { buildFindings } from '../../monitoring/finding-engine.js';
import { loadLatestScan, loadScanResult } from '../../storage/filesystem-store.js';
import type { Finding } from '../../types/findings.js';
import type { SiteResult } from '../../types/index.js';
import { BaselineError, ConfigError } from '../../utils/errors.js';
import { globalOptions } from '../context.js';
import { color, print, printJson, severityLabel } from '../output.js';

interface BaselineOptions {
  site?: string;
  fromScan?: string;
  approve?: string;
  keepVariants?: boolean;
  allowPartial?: boolean;
  reason?: string;
  approvedBy?: string;
  yes?: boolean;
  dryRun?: boolean;
}

interface PlannedUpdate {
  readonly site: SiteResult;
  readonly previous: Baseline | undefined;
  readonly next: Baseline;
  readonly summary: BaselineChangeSummary;
  readonly approvedFindings: readonly Finding[];
}

/** Map a finding (via its originating change) to the baseline items it approves. */
export function approvalItemsFor(change: Change): ApprovalItem[] {
  switch (change.kind) {
    case 'resource-modified':
    case 'resource-formatting-changed':
    case 'resource-added':
    case 'resource-type-changed':
    case 'redirect-changed':
    case 'content-unavailable':
    case 'sri-mismatch':
      return change.identity ? [{ kind: 'resource', value: change.identity }] : [];
    case 'resource-moved':
      return [
        ...(change.identity ? [{ kind: 'resource' as const, value: change.identity }] : []),
        ...(change.details.previousIdentity ? [{ kind: 'remove-resource' as const, value: change.details.previousIdentity }] : []),
      ];
    case 'resource-removed':
      return change.identity ? [{ kind: 'remove-resource', value: change.identity }] : [];
    case 'new-script-domain':
      return change.domain ? [{ kind: 'script-domain', value: change.domain }] : [];
    case 'new-outbound-domain':
      return [
        ...(change.domain ? [{ kind: 'outbound-domain' as const, value: change.domain }] : []),
        ...(change.details.hosts ?? '').split(' ').filter(Boolean).map((h) => ({ kind: 'outbound-host' as const, value: h })),
      ];
    case 'new-outbound-host':
      return change.host ? [{ kind: 'outbound-host', value: change.host }] : [];
    case 'iframe-origin-added':
      return change.origin ? [{ kind: 'iframe-origin', value: change.origin }] : [];
    case 'iframe-origin-removed':
      return change.origin ? [{ kind: 'remove-iframe-origin', value: change.origin }] : [];
    default:
      return [];
  }
}

function printSummary(plan: PlannedUpdate): void {
  const s = plan.summary;
  print(color.bold(`${plan.site.name}: ${plan.previous ? 'update baseline' : 'create baseline'}`));
  print(`  ${s.totalResources} approved resource(s) after this change`);
  const list = (label: string, items: readonly string[], paint: (x: string) => string): void => {
    if (items.length === 0) return;
    print(`  ${label} (${items.length}):`);
    for (const item of items.slice(0, 25)) print(`    ${paint(item)}`);
    if (items.length > 25) print(color.gray(`    … and ${items.length - 25} more`));
  };
  list('+ newly approved', s.addedResources, color.green);
  list('~ new approved version', s.changedResources, color.yellow);
  list('- no longer approved', s.removedResources, color.red);
  list('+ newly approved domains', s.addedDomains, color.green);
  list('- domains no longer approved', s.removedDomains, color.red);
  const risky = plan.approvedFindings.filter((f) => f.severity === 'high' || f.severity === 'critical' || f.category === 'suspicious');
  if (risky.length > 0) {
    print(color.red(`  ! You are approving ${risky.length} high-priority or suspicious finding(s):`));
    for (const f of risky) print(`    ${severityLabel(f.severity)} ${f.title} ${color.gray(f.id)}`);
  }
}

async function confirm(question: string): Promise<boolean> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await rl.question(question);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

export function registerBaseline(program: Command): void {
  program
    .command('baseline')
    .description('Approve the scripts and domains from a scan as the expected state (explicit, never automatic)')
    .option('-s, --site <names>', 'only these sites (comma separated)')
    .option('--from-scan <file>', 'scan result to approve (default: the latest scan)')
    .option('--approve <finding-ids>', 'approve only the changes behind these findings (comma separated)')
    .option('--keep-variants', 'keep previously approved versions as well (for vendors that serve several variants)')
    .option('--allow-partial', 'allow approving from an incomplete scan (only complete pages are approved)')
    .option('--reason <text>', 'reason recorded in the approval history')
    .option('--approved-by <name>', 'name recorded in the approval history')
    .option('--dry-run', 'show what would change without writing')
    .option('-y, --yes', 'do not ask for confirmation (required in non-interactive environments)')
    .action(async (opts: BaselineOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const scanPath = opts.fromScan ? resolve(opts.fromScan) : resolved.paths.latestScan;
      const scan = opts.fromScan ? await loadScanResult(scanPath) : await loadLatestScan(resolved.paths);
      const names = opts.site?.split(',').map((s) => s.trim()).filter(Boolean);
      const sites = scan.sites.filter((s) => !names || names.includes(s.name));
      if (sites.length === 0) throw new ConfigError(`The scan ${scan.scanId} contains none of the requested sites`);
      const requested = new Set((opts.approve ?? '').split(',').map((s) => s.trim()).filter(Boolean));

      const plans: PlannedUpdate[] = [];
      const matchedIds = new Set<string>();
      for (const site of sites) {
        const previous = await loadBaseline(resolved.paths, site.name);
        const common = {
          scanId: scan.scanId,
          ...(opts.reason ? { reason: opts.reason } : {}),
          ...(opts.approvedBy ? { approvedBy: opts.approvedBy } : {}),
          ...(opts.keepVariants ? { keepVariants: true } : {}),
        };
        let findings: Finding[] = [];
        let changes: readonly Change[] = [];
        if (previous) {
          changes = compareSite(site, previous, resolved.config.domains).changes;
          findings = buildFindings(changes, { site, risk: resolved.config.risk, rules: resolved.config.rules, domains: resolved.config.domains });
        }
        if (requested.size > 0) {
          if (!previous) continue;
          const items: ApprovalItem[] = [];
          const approved: Finding[] = [];
          findings.forEach((f, i) => {
            if (!requested.has(f.id)) return;
            matchedIds.add(f.id);
            approved.push(f);
            items.push(...approvalItemsFor(changes[i] as Change));
          });
          if (items.length === 0) continue;
          const next = approveSelected(previous, site, items, common);
          plans.push({ site, previous, next, summary: summarizeBaselineChange(previous, next), approvedFindings: approved });
          continue;
        }
        const completeCount = site.pages.filter((p) => p.status === 'complete').length;
        if (completeCount === 0) {
          throw new BaselineError(`Site ${site.name} has no completely scanned pages in scan ${scan.scanId}`, 'Fix the scan problems and scan again.');
        }
        if (site.status !== 'complete' && !opts.allowPartial) {
          throw new BaselineError(
            `Scan ${scan.scanId} is incomplete for site ${site.name} (${site.pages.length - completeCount} page(s) not scanned completely)`,
            'Re-scan, or pass --allow-partial to approve only the completely scanned pages.',
          );
        }
        const next = previous
          ? approveFullScan(previous, site, { ...common, includePartial: false })
          : createBaseline(site, { ...common, includePartial: false });
        plans.push({ site, previous, next, summary: summarizeBaselineChange(previous, next), approvedFindings: findings });
      }

      const unmatched = [...requested].filter((id) => !matchedIds.has(id));
      if (unmatched.length > 0) {
        throw new BaselineError(`No current finding matches: ${unmatched.join(', ')}`, 'Run "scriptdrift diff" to list current finding IDs.');
      }
      if (plans.length === 0) {
        if (g.json) printJson({ updated: [] });
        else print('Nothing to approve.');
        return;
      }

      if (!g.json) for (const plan of plans) printSummary(plan);
      if (opts.dryRun) {
        if (g.json) printJson({ dryRun: true, plans: plans.map((p) => ({ site: p.site.name, summary: p.summary })) });
        return;
      }
      if (!opts.yes) {
        if (!process.stdin.isTTY) {
          throw new BaselineError('Refusing to change baselines without confirmation in a non-interactive session', 'Review the summary and re-run with --yes.');
        }
        const ok = await confirm(`\nWrite ${plans.length} baseline file(s)? Approved scripts will no longer be reported. [y/N] `);
        if (!ok) {
          print('Aborted. No baseline was changed.');
          return;
        }
      }
      const written: string[] = [];
      for (const plan of plans) written.push(await saveBaseline(resolved.paths, plan.next));
      if (g.json) printJson({ updated: written, scanId: scan.scanId });
      else {
        for (const p of written) print(color.green(`Saved ${p}`));
        print(color.gray('Commit the baseline files after review so that the approval is recorded in version control.'));
      }
    });
}
