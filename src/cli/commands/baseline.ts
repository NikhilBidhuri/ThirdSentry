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
import { assertScanSitesConfigured } from '../../monitoring/analysis-runner.js';
import type { Change } from '../../monitoring/comparison-engine.js';
import { applyPoliciesToSite, compareSiteWithPolicies } from '../../policies/apply.js';
import { buildFindings } from '../../monitoring/finding-engine.js';
import { loadLatestScan, loadScanResult } from '../../storage/filesystem-store.js';
import type { Finding } from '../../types/findings.js';
import type { SiteResult } from '../../types/index.js';
import { BaselineError } from '../../utils/errors.js';
import { defaultApprover } from '../../utils/identity.js';
import { globalOptions, selectScanSites } from '../context.js';
import { color, print, printJson, severityLabel } from '../output.js';

interface BaselineOptions {
  site?: string;
  fromScan?: string;
  scanId?: string;
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

/** Approved hashes of a baseline resource, as reviewed (see ApprovalItem 'remove-resource'). */
function reviewedHashes(change: Change): string[] {
  return (change.baseline?.approvedHashes ?? []).map((h) => h.sha256 ?? h.normalizedSha256 ?? 'none');
}

/**
 * Map a finding (via its originating change) to the baseline items it
 * approves. Resource items carry the hash of the reviewed version, so
 * approving one finding never approves another variant of the same URL.
 */
export function approvalItemsFor(change: Change): ApprovalItem[] {
  const resource = (): ApprovalItem[] =>
    change.identity && change.current ? [{ kind: 'resource', value: change.identity, sha256: change.current.hashes.sha256 }] : [];
  switch (change.kind) {
    case 'resource-modified':
    case 'resource-formatting-changed':
    case 'policy-accepted-update':
    case 'resource-added':
    case 'resource-type-changed':
    case 'redirect-changed':
    case 'content-unavailable':
    case 'sri-mismatch':
      return resource();
    case 'resource-moved':
      return [
        ...resource(),
        ...(change.details.previousIdentity ? [{ kind: 'remove-resource' as const, value: change.details.previousIdentity, hashes: reviewedHashes(change) }] : []),
      ];
    case 'resource-removed':
      return change.identity ? [{ kind: 'remove-resource', value: change.identity, hashes: reviewedHashes(change) }] : [];
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
    .option('--scan-id <id>', 'refuse unless the scan to approve is this one (the scan ID printed by "thirdsentry diff")')
    .option('--approve <finding-ids>', 'approve only the changes behind these findings (comma separated)')
    .option('--keep-variants', 'keep previously approved versions as well (for vendors that serve several variants)')
    .option('--allow-partial', 'allow approving from an incomplete scan (only complete pages are approved)')
    .option('--reason <text>', 'reason recorded in the approval history')
    .option('--approved-by <name>', 'name recorded in the approval history (default: git user.name, else the OS user name)')
    .option('--dry-run', 'show what would change without writing')
    .option('-y, --yes', 'do not ask for confirmation (required in non-interactive environments)')
    .action(async (opts: BaselineOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const scanPath = opts.fromScan ? resolve(opts.fromScan) : resolved.paths.latestScan;
      const scan = opts.fromScan ? await loadScanResult(scanPath) : await loadLatestScan(resolved.paths);
      // Bind the approval to the scan that was reviewed: a scheduled scan may
      // have replaced the latest scan since "thirdsentry diff" was run.
      if (opts.scanId !== undefined && opts.scanId !== scan.scanId) {
        throw new BaselineError(
          `The scan to approve is ${scan.scanId}, not ${opts.scanId} (--scan-id). Nothing was approved.`,
          `A newer scan was saved after your review. Review it with "thirdsentry diff", or approve the scan you reviewed with --from-scan ${opts.fromScan ? '<its file>' : `.thirdsentry/reports/scans/${opts.scanId}.json`}.`,
        );
      }
      assertScanSitesConfigured(resolved, scan.sites.map((s) => s.name), `Scan ${scan.scanId}`);
      const sites = selectScanSites(resolved, scan, opts.site);
      const requested = new Set((opts.approve ?? '').split(',').map((s) => s.trim()).filter(Boolean));
      const approvedBy = opts.approvedBy ?? (await defaultApprover(resolved.baseDir));
      if (!g.json) print(color.gray(`Approving from scan ${scan.scanId} (${scan.startedAt}${opts.fromScan ? `, ${scanPath}` : ', latest scan'})${approvedBy ? ` as ${approvedBy}` : ''}`));

      const plans: PlannedUpdate[] = [];
      const matchedIds = new Set<string>();
      const notApprovable: Finding[] = [];
      for (const site of sites) {
        const previous = await loadBaseline(resolved.paths, site.name);
        const common = {
          scanId: scan.scanId,
          ...(opts.reason ? { reason: opts.reason } : {}),
          ...(approvedBy ? { approvedBy } : {}),
          ...(opts.keepVariants ? { keepVariants: true } : {}),
        };
        let findings: Finding[] = [];
        let changes: readonly Change[] = [];
        // Script policies re-key governed scripts to their policy identity before anything is approved,
        // so the baseline approves the policy identity and finding IDs match `thirdsentry diff`.
        let effSite = site;
        let effPrevious = previous;
        if (previous) {
          const applied = compareSiteWithPolicies(site, previous, resolved.config, { domains: resolved.config.domains });
          effSite = applied.site;
          effPrevious = applied.baseline;
          changes = applied.comparison.changes;
          findings = buildFindings(changes, { site: effSite, risk: resolved.config.risk, rules: resolved.config.rules, domains: resolved.config.domains });
        }
        if (!previous) effSite = applyPoliciesToSite(site, resolved.config, new Date());
        if (requested.size > 0) {
          if (!effPrevious) continue;
          const items: ApprovalItem[] = [];
          const approved: Finding[] = [];
          findings.forEach((f, i) => {
            if (!requested.has(f.id)) return;
            matchedIds.add(f.id);
            const forFinding = approvalItemsFor(changes[i] as Change);
            if (forFinding.length === 0) {
              notApprovable.push(f);
              return;
            }
            approved.push(f);
            items.push(...forFinding);
          });
          if (items.length === 0) continue;
          const next = approveSelected(effPrevious, effSite, items, common);
          plans.push({ site: effSite, previous, next, summary: summarizeBaselineChange(previous, next), approvedFindings: approved });
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
        const next = effPrevious
          ? approveFullScan(effPrevious, effSite, { ...common, includePartial: false })
          : createBaseline(effSite, { ...common, includePartial: false });
        plans.push({ site: effSite, previous, next, summary: summarizeBaselineChange(previous, next), approvedFindings: findings });
      }

      const unmatched = [...requested].filter((id) => !matchedIds.has(id));
      if (unmatched.length > 0) {
        throw new BaselineError(`No current finding matches: ${unmatched.join(', ')}`, 'Run "thirdsentry diff" to list current finding IDs.');
      }
      if (notApprovable.length > 0) {
        // Coverage findings (page failed, coverage degraded) describe the scan, not the
        // site's code: there is nothing to add to a baseline, and silently doing nothing
        // would look like an approval.
        throw new BaselineError(
          `These findings cannot be approved into a baseline: ${notApprovable.map((f) => `${f.id} (${f.kind})`).join(', ')}`,
          notApprovable.some((f) => f.kind === 'pinned-hash-mismatch')
            ? 'A pinned-hash-mismatch is decided by the script policy, not the baseline: after reviewing the new version, add its hash to the policy\'s hashes in thirdsentry.yml.'
            : 'They clear when the page is scanned completely again. To silence a known outage, add a time-limited suppression in thirdsentry.yml.',
        );
      }
      if (plans.length === 0) {
        if (g.json) printJson({ updated: [], scanId: scan.scanId });
        else print('Nothing to approve.');
        return;
      }

      if (!g.json) for (const plan of plans) printSummary(plan);
      if (opts.dryRun) {
        if (g.json) printJson({ dryRun: true, scanId: scan.scanId, plans: plans.map((p) => ({ site: p.site.name, summary: p.summary })) });
        return;
      }
      if (!opts.yes) {
        if (!process.stdin.isTTY) {
          throw new BaselineError('Refusing to change baselines without confirmation in a non-interactive session', 'Review the summary and re-run with --yes.');
        }
        const ok = await confirm(`\nWrite ${plans.length} baseline file(s) from scan ${scan.scanId}? Approved scripts will no longer be reported. [y/N] `);
        if (!ok) {
          print('Aborted. No baseline was changed.');
          return;
        }
      }
      const written: string[] = [];
      for (const plan of plans) written.push(await saveBaseline(resolved.paths, plan.next));
      if (g.json) printJson({ updated: written, scanId: scan.scanId, ...(approvedBy ? { approvedBy } : {}) });
      else {
        for (const p of written) print(color.green(`Saved ${p} (approved from scan ${scan.scanId})`));
        print(color.gray('Commit the baseline files after review so that the approval is recorded in version control.'));
      }
    });
}
