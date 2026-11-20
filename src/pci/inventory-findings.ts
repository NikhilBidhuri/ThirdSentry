import { assess, signal, type RiskConfig, DEFAULT_RISK_CONFIG } from '../analysis/risk-scoring.js';
import { fingerprint } from '../monitoring/finding-engine.js';
import type { Evidence, Finding, Signal } from '../types/findings.js';
import type { PciReportSection } from '../types/report.js';
import { checkFailures, type InventoryResult, type InventoryRow } from './inventory.js';

/**
 * Inventory gaps as findings (`script-unjustified`, PCI DSS 6.4.3) and as a report section.
 * Findings are only produced for scripts on sensitive pages and only when
 * `pci.requireJustification` is enabled; they are info/low so they stay out of the way.
 */

function findingFor(row: InventoryRow, risk: RiskConfig, detectedAt: string): Finding {
  const overdue = row.status === 'review-overdue';
  const sig: Signal = overdue ? signal('script-review-overdue', risk) : row.party === 'third-party' ? signal('script-unjustified-third-party', risk) : signal('script-unjustified-first-party', risk);
  const a = assess([sig], 'high', risk);
  const evidence: Evidence[] = [
    { label: 'Resource identity', value: row.identity },
    { label: 'Inventory status', value: row.status },
    { label: 'Issues', value: row.issues.join('; ') || 'none' },
    { label: 'Pages', value: row.pages.join(', ') },
  ];
  if (row.reviewBy) evidence.push({ label: 'Review by', value: row.reviewBy });
  return {
    // One finding per script and status: stable across scans, a new one when the status changes.
    id: fingerprint([row.site, 'script-unjustified', row.identity, row.status]),
    kind: 'script-unjustified',
    title: overdue ? `Script justification review overdue: ${row.url}` : `Script on a payment page has no documented justification: ${row.url}`,
    site: row.site,
    page: row.pages[0] ?? '',
    pages: row.pages,
    resourceIdentity: row.identity,
    resourceUrl: row.url,
    party: row.party,
    detectedAt,
    severity: a.severity,
    confidence: a.confidence,
    category: a.category,
    score: a.score,
    signals: [sig],
    reason: overdue
      ? `The inventory entry for this script says it had to be reviewed by ${row.reviewBy ?? 'an earlier date'}. PCI DSS 6.4.3 expects each script on payment pages to be authorized, justified and kept in an inventory.`
      : `This script runs on a payment page, but the inventory has no complete entry for it (${row.issues.filter((i) => i.startsWith('entry') || i.startsWith('no inventory')).join('; ') || 'missing purpose, owner or authorization'}). PCI DSS 6.4.3 expects a written business or technical justification for each script.`,
    evidence,
    recommendedAction: `Document why the script is needed: thirdsentry inventory ${overdue ? 'set' : 'add'} "${row.url}" --site ${row.site} --purpose "..." --owner "..." --authorized-by "...". This edits the inventory file only; it does not approve the script's content (use "thirdsentry baseline" for that).`,
  };
}

export function inventoryFindings(result: InventoryResult, options: { risk?: RiskConfig; now?: Date } = {}): Finding[] {
  const detectedAt = (options.now ?? new Date()).toISOString();
  return checkFailures(result.rows).map((r) => findingFor(r, options.risk ?? DEFAULT_RISK_CONFIG, detectedAt));
}

export function pciSectionFor(site: string, result: InventoryResult, inventoryFile: { path: string; exists: boolean }): PciReportSection['sites'][number] {
  const sensitive = result.rows.filter((r) => r.sensitive);
  const count = (s: InventoryRow['status']): number => sensitive.filter((r) => r.status === s).length;
  return {
    site,
    inventoryFile: inventoryFile.exists ? inventoryFile.path : null,
    sensitiveScripts: sensitive.length,
    authorized: count('authorized'),
    missingJustification: count('missing-justification'),
    reviewOverdue: count('review-overdue'),
    notApproved: count('not-approved'),
    unmatchedEntries: result.unmatchedEntries.length,
    gaps: sensitive
      .filter((r) => r.status !== 'authorized')
      .slice(0, 50)
      .map((r) => ({ url: r.url, status: r.status, issues: [...r.issues] })),
  };
}
