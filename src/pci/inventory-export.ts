import type { InventoryResult, InventoryRow } from './inventory.js';

/**
 * Exports of the script inventory for assessors (QSAs): table, JSON, CSV, Markdown.
 * Script URLs and purposes come from scanned pages or hand-edited files, so CSV and
 * Markdown output neutralise spreadsheet formulas and table-breaking characters.
 */

export const EXPORT_FORMATS = ['table', 'json', 'csv', 'markdown'] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

const COLUMNS: ReadonlyArray<{ readonly key: string; readonly title: string; readonly get: (r: InventoryRow) => string }> = [
  { key: 'site', title: 'Site', get: (r) => r.site },
  { key: 'status', title: 'Status', get: (r) => r.status },
  { key: 'sensitive', title: 'Payment page', get: (r) => (r.sensitive ? 'yes' : 'no') },
  { key: 'url', title: 'Script', get: (r) => r.url },
  { key: 'type', title: 'Type', get: (r) => r.type },
  { key: 'party', title: 'Party', get: (r) => r.party },
  { key: 'pages', title: 'Pages', get: (r) => r.pages.join(' ') },
  { key: 'purpose', title: 'Purpose', get: (r) => r.purpose ?? '' },
  { key: 'owner', title: 'Owner', get: (r) => r.owner ?? '' },
  { key: 'authorizedBy', title: 'Authorized by', get: (r) => r.authorizedBy ?? '' },
  { key: 'authorizedAt', title: 'Authorized at', get: (r) => r.authorizedAt ?? '' },
  { key: 'reviewBy', title: 'Review by', get: (r) => r.reviewBy ?? '' },
  { key: 'approval', title: 'Baseline approval', get: (r) => r.approval },
  { key: 'approvedSha256', title: 'Approved SHA-256', get: (r) => r.approvedSha256 ?? '' },
  { key: 'currentSha256', title: 'Current SHA-256', get: (r) => r.currentSha256 ?? '' },
  { key: 'currentSri', title: 'Current SRI', get: (r) => r.currentSri ?? '' },
  { key: 'sri', title: 'Integrity attribute', get: (r) => (r.integrityAttribute ? `${r.sri}: ${r.integrityAttribute}` : 'none') },
  { key: 'issues', title: 'Issues', get: (r) => r.issues.join('; ') },
  { key: 'notes', title: 'Notes', get: (r) => r.notes ?? '' },
];

/** Prefix cells that a spreadsheet would interpret as a formula. */
function csvCell(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

export function toCsv(rows: readonly InventoryRow[]): string {
  const lines = [COLUMNS.map((c) => csvCell(c.title)).join(',')];
  for (const r of rows) lines.push(COLUMNS.map((c) => csvCell(c.get(r))).join(','));
  return `${lines.join('\r\n')}\r\n`;
}

function mdCell(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ').replace(/[<>]/g, (c) => (c === '<' ? '&lt;' : '&gt;'));
}

export function toMarkdown(result: InventoryResult, title = 'Script inventory'): string {
  const rows = result.rows;
  const cols = COLUMNS.filter((c) => ['status', 'url', 'purpose', 'owner', 'authorizedBy', 'authorizedAt', 'reviewBy', 'approval', 'sri'].includes(c.key));
  const lines = [`# ${title}`, ''];
  const count = (s: string): number => rows.filter((r) => r.status === s).length;
  lines.push(`${rows.length} script(s): ${count('authorized')} authorized, ${count('missing-justification')} missing justification, ${count('review-overdue')} review overdue, ${count('not-approved')} not approved.`, '');
  lines.push(`| ${cols.map((c) => c.title).join(' | ')} |`, `| ${cols.map(() => '---').join(' | ')} |`);
  for (const r of rows) lines.push(`| ${cols.map((c) => mdCell(c.get(r))).join(' | ')} |`);
  if (result.unmatchedEntries.length > 0) {
    lines.push('', `Inventory entries that match no script in the scan (${result.unmatchedEntries.length}):`, '');
    for (const e of result.unmatchedEntries) lines.push(`- ${mdCell(e.identity ?? e.url ?? '')}`);
  }
  return `${lines.join('\n')}\n`;
}

function clip(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}~`;
}

export function toTable(rows: readonly InventoryRow[]): string {
  const cols = [
    { title: 'STATUS', get: (r: InventoryRow) => r.status, max: 22 },
    { title: 'PAY', get: (r: InventoryRow) => (r.sensitive ? 'yes' : ''), max: 3 },
    { title: 'SCRIPT', get: (r: InventoryRow) => r.url, max: 60 },
    { title: 'PURPOSE', get: (r: InventoryRow) => r.purpose ?? '-', max: 30 },
    { title: 'OWNER', get: (r: InventoryRow) => r.owner ?? '-', max: 16 },
    { title: 'REVIEW BY', get: (r: InventoryRow) => r.reviewBy ?? '-', max: 10 },
    { title: 'APPROVAL', get: (r: InventoryRow) => r.approval, max: 11 },
    { title: 'SRI', get: (r: InventoryRow) => r.sri, max: 10 },
  ];
  const cells = rows.map((r) => cols.map((c) => clip(c.get(r).replace(/[\r\n\t]+/g, ' '), c.max)));
  const widths = cols.map((c, i) => Math.max(c.title.length, ...cells.map((row) => (row[i] as string).length)));
  const fmt = (row: readonly string[]): string => row.map((v, i) => v.padEnd(widths[i] as number)).join('  ').trimEnd();
  return [fmt(cols.map((c) => c.title)), ...cells.map(fmt)].join('\n');
}

export function formatInventory(result: InventoryResult, format: ExportFormat): string {
  switch (format) {
    case 'json':
      return `${JSON.stringify({ rows: result.rows, unmatchedEntries: result.unmatchedEntries }, null, 2)}\n`;
    case 'csv':
      return toCsv(result.rows);
    case 'markdown':
      return toMarkdown(result);
    default:
      return `${toTable(result.rows)}\n`;
  }
}
