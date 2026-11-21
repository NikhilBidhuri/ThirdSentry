import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { isMap, isSeq, parse as parseYaml, parseDocument, stringify as stringifyYaml, YAMLParseError } from 'yaml';
import { z } from 'zod';
import type { Baseline, BaselineResource } from '../baseline/baseline-schema.js';
import { formatZodIssues } from '../config/loader.js';
import { assertInside, assertSiteName, type StoragePaths } from '../storage/paths.js';
import type { ScriptResource, SiteResult } from '../types/index.js';
import { ConfigError } from '../utils/errors.js';
import { pathExists, writeFileAtomic } from '../utils/fs.js';
import { matchesGlob } from '../utils/patterns.js';

/**
 * Script authorization inventory (PCI DSS v4.0 requirement 6.4.3).
 *
 * A human-edited YAML file per site (`.thirdsentry/inventory/<site>.yml`) records
 * why each script on payment pages is needed, who owns it and who authorized it.
 * Entries are matched by resource identity or by URL pattern, so the metadata
 * survives version changes of the script. The inventory is never written by scans
 * and never changes a baseline: approving a script's content (baseline) and
 * authorizing its purpose (inventory) are separate decisions.
 */

const day = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, 'must be a date such as 2026-12-31')
  .refine((v) => !Number.isNaN(Date.parse(v)), 'must be a valid date');

export const InventoryEntrySchema = z
  .object({
    /** Exact resource identity (e.g. "url:https://cdn.example.com/pay.js"); `*` is a wildcard. */
    identity: z.string().min(1).max(20_000).optional(),
    /** URL pattern matched against the script URL (e.g. "https://js.stripe.com/v3/*"); `*` is a wildcard. */
    url: z.string().min(1).max(16_384).optional(),
    /** Business and technical justification: why is this script needed? */
    purpose: z.string().max(4_000).optional(),
    owner: z.string().max(256).optional(),
    authorizedBy: z.string().max(256).optional(),
    authorizedAt: day.optional(),
    /** Date by which the justification must be reviewed again. */
    reviewBy: day.optional(),
    notes: z.string().max(4_000).optional(),
  })
  .strict()
  .refine((e) => e.identity !== undefined || e.url !== undefined, 'an entry needs "identity" or "url" to say which script it describes');

export const InventoryFileSchema = z
  .object({
    version: z.literal(1).default(1),
    scripts: z.array(InventoryEntrySchema).max(10_000).default([]),
  })
  .strict();

export type InventoryEntry = z.infer<typeof InventoryEntrySchema>;
export type InventoryFile = z.infer<typeof InventoryFileSchema>;

export const REQUIRED_JUSTIFICATION_FIELDS = ['purpose', 'owner', 'authorizedBy', 'authorizedAt'] as const;

export function inventoryPath(paths: StoragePaths, site: string): string {
  return assertInside(join(paths.root, 'inventory'), join(paths.root, 'inventory', `${assertSiteName(site)}.yml`));
}

export function parseInventory(text: string, source: string): InventoryFile {
  let data: unknown;
  try {
    data = text.trim() === '' ? {} : parseYaml(text);
  } catch (error) {
    throw new ConfigError(`Invalid inventory ${source}: ${error instanceof YAMLParseError ? error.message : String(error)}`);
  }
  const parsed = InventoryFileSchema.safeParse(data ?? {});
  if (!parsed.success) {
    throw new ConfigError(`Invalid inventory ${source}:\n${formatZodIssues(parsed.error)}`, 'Fix the file; see docs/pci.md for the format.');
  }
  return parsed.data;
}

export interface LoadedInventory {
  readonly path: string;
  readonly exists: boolean;
  readonly entries: readonly InventoryEntry[];
}

export async function loadInventory(paths: StoragePaths, site: string): Promise<LoadedInventory> {
  const path = inventoryPath(paths, site);
  if (!(await pathExists(path))) return { path, exists: false, entries: [] };
  const text = await readFile(path, 'utf8');
  return { path, exists: true, entries: parseInventory(text, path).scripts };
}

// ---------------------------------------------------------------------------
// Matching

function hasWildcard(s: string): boolean {
  return s.includes('*');
}

function patternMatches(value: string, pattern: string): boolean {
  return value === pattern || (hasWildcard(pattern) && matchesGlob(value, pattern));
}

/** URLs a resource can be matched by: final URL, requested URL and identity URL. */
function urlsOf(r: Pick<ScriptResource, 'finalUrl' | 'originalUrl' | 'identity'>): string[] {
  const urls = [r.finalUrl, r.originalUrl, r.identity.startsWith('url:') ? r.identity.slice(4) : undefined].filter((u): u is string => typeof u === 'string');
  return [...new Set(urls)];
}

/** Specificity of a match (higher wins): exact identity, exact URL, then the longest wildcard pattern. */
function matchScore(entry: InventoryEntry, r: Pick<ScriptResource, 'finalUrl' | 'originalUrl' | 'identity'>): number {
  let best = 0;
  if (entry.identity !== undefined && patternMatches(r.identity, entry.identity)) best = Math.max(best, hasWildcard(entry.identity) ? 1_000 + entry.identity.length : 1_000_000);
  if (entry.url !== undefined && urlsOf(r).some((u) => patternMatches(u, entry.url as string))) best = Math.max(best, hasWildcard(entry.url) ? 1_000 + entry.url.length : 500_000);
  return best;
}

/** The most specific inventory entry that describes a script, if any. */
export function matchInventoryEntry(entries: readonly InventoryEntry[], r: Pick<ScriptResource, 'finalUrl' | 'originalUrl' | 'identity'>): InventoryEntry | undefined {
  let best: InventoryEntry | undefined;
  let bestScore = 0;
  for (const e of entries) {
    const s = matchScore(e, r);
    if (s > bestScore) {
      best = e;
      bestScore = s;
    }
  }
  return best;
}

// ---------------------------------------------------------------------------
// Status

export type InventoryStatus = 'authorized' | 'missing-justification' | 'review-overdue' | 'not-approved';
export type ApprovalState = 'approved' | 'changed' | 'new' | 'no-baseline' | 'no-content';
export type SriState = 'valid' | 'mismatch' | 'unverified' | 'none';

export interface InventoryRow {
  readonly site: string;
  readonly identity: string;
  readonly url: string;
  readonly type: string;
  readonly party: 'first-party' | 'third-party';
  readonly pages: readonly string[];
  /** True when the script was observed on at least one sensitive (payment) page. */
  readonly sensitive: boolean;
  readonly status: InventoryStatus;
  /** Why the status is not "authorized" (missing fields, overdue date, approval state). */
  readonly issues: readonly string[];
  readonly purpose?: string;
  readonly owner?: string;
  readonly authorizedBy?: string;
  readonly authorizedAt?: string;
  readonly reviewBy?: string;
  readonly notes?: string;
  readonly approval: ApprovalState;
  /** Latest approved SHA-256 from the baseline. */
  readonly approvedSha256?: string;
  readonly currentSha256?: string;
  /** Subresource-Integrity form (sha256-...) of the current content. */
  readonly currentSri?: string;
  readonly sri: SriState;
  /** Integrity attribute of the page's script tag, if any. */
  readonly integrityAttribute?: string;
}

export interface InventoryResult {
  readonly rows: readonly InventoryRow[];
  /** Inventory entries that match no script in the scan (stale or mistyped). */
  readonly unmatchedEntries: readonly InventoryEntry[];
}

function today(now: Date): string {
  return now.toISOString().slice(0, 10);
}

function approvalOf(variants: readonly ScriptResource[], baseline: BaselineResource | undefined, hasBaseline: boolean): ApprovalState {
  if (!hasBaseline) return 'no-baseline';
  if (!baseline) return 'new';
  if (variants.every((v) => v.hashes.sha256 === null)) return 'no-content';
  const approved = variants.every((v) => baseline.approvedHashes.some((h) => (v.hashes.sha256 !== null && h.sha256 === v.hashes.sha256) || (v.hashes.sha256 === null && h.sha256 === null)));
  return approved ? 'approved' : 'changed';
}

function sriOf(variants: readonly ScriptResource[]): { state: SriState; attribute?: string } {
  const withSri = variants.find((v) => v.sri);
  if (!withSri?.sri) return { state: 'none' };
  const valid = variants.every((v) => !v.sri || v.sri.valid === true);
  const mismatch = variants.some((v) => v.sri?.valid === false);
  return { state: mismatch ? 'mismatch' : valid ? 'valid' : 'unverified', attribute: withSri.sri.attribute };
}

export interface InventoryOptions {
  readonly site: SiteResult;
  readonly baseline?: Baseline | undefined;
  readonly entries: readonly InventoryEntry[];
  readonly now?: Date;
}

/** Join the scripts of a scan with inventory metadata, baseline approval state and integrity information. */
export function buildInventory(options: InventoryOptions): InventoryResult {
  const { site, baseline, entries } = options;
  const todayStr = today(options.now ?? new Date());
  const sensitivePages = new Set(site.pages.filter((p) => p.sensitive).map((p) => p.key));
  const byIdentity = new Map<string, ScriptResource[]>();
  for (const r of site.resources) byIdentity.set(r.identity, [...(byIdentity.get(r.identity) ?? []), r]);
  const baselineById = new Map((baseline?.resources ?? []).map((b) => [b.identity, b]));
  const used = new Set<InventoryEntry>();
  const rows: InventoryRow[] = [];

  for (const [identity, variants] of byIdentity) {
    const first = variants[0] as ScriptResource;
    const entry = matchInventoryEntry(entries, first);
    if (entry) used.add(entry);
    const pages = [...new Set(variants.flatMap((v) => v.pages))].sort();
    const missing = entry ? REQUIRED_JUSTIFICATION_FIELDS.filter((f) => !entry[f]?.trim()) : [...REQUIRED_JUSTIFICATION_FIELDS];
    const issues: string[] = [];
    if (!entry) issues.push('no inventory entry');
    else if (missing.length > 0) issues.push(`entry lacks: ${missing.join(', ')}`);
    const overdue = entry?.reviewBy !== undefined && entry.reviewBy < todayStr;
    if (overdue) issues.push(`review was due ${entry?.reviewBy}`);
    if (entry && !entry.reviewBy) issues.push('no reviewBy date');
    const approval = approvalOf(variants, baselineById.get(identity), baseline !== undefined);
    if (approval !== 'approved') issues.push(`baseline: ${approval}`);
    const sri = sriOf(variants);
    if (sri.state === 'mismatch') issues.push('integrity attribute does not match the served content');
    const status: InventoryStatus = missing.length > 0 ? 'missing-justification' : overdue ? 'review-overdue' : approval !== 'approved' ? 'not-approved' : 'authorized';
    const current = variants.find((v) => v.hashes.sha256) ?? first;
    const approvedHash = baselineById.get(identity)?.approvedHashes.at(-1)?.sha256;
    rows.push({
      site: site.name,
      identity,
      url: first.finalUrl ?? first.originalUrl ?? identity,
      type: first.type,
      party: first.party,
      pages,
      sensitive: pages.some((p) => sensitivePages.has(p)),
      status,
      issues,
      ...(entry?.purpose ? { purpose: entry.purpose } : {}),
      ...(entry?.owner ? { owner: entry.owner } : {}),
      ...(entry?.authorizedBy ? { authorizedBy: entry.authorizedBy } : {}),
      ...(entry?.authorizedAt ? { authorizedAt: entry.authorizedAt } : {}),
      ...(entry?.reviewBy ? { reviewBy: entry.reviewBy } : {}),
      ...(entry?.notes ? { notes: entry.notes } : {}),
      approval,
      ...(approvedHash ? { approvedSha256: approvedHash } : {}),
      ...(current.hashes.sha256 ? { currentSha256: current.hashes.sha256 } : {}),
      ...(current.hashes.sri ? { currentSri: current.hashes.sri } : {}),
      sri: sri.state,
      ...(sri.attribute ? { integrityAttribute: sri.attribute } : {}),
    });
  }
  rows.sort((a, b) => Number(b.sensitive) - Number(a.sensitive) || a.identity.localeCompare(b.identity));
  return { rows, unmatchedEntries: entries.filter((e) => !used.has(e)) };
}

/** Rows that make `inventory --check` fail: scripts on sensitive pages without justification or with an overdue review. */
export function checkFailures(rows: readonly InventoryRow[]): InventoryRow[] {
  return rows.filter((r) => r.sensitive && (r.status === 'missing-justification' || r.status === 'review-overdue'));
}

// ---------------------------------------------------------------------------
// Editing (comment-preserving)

const FILE_HEADER = `# ThirdSentry script inventory (PCI DSS 6.4.3): why each script is needed and who authorized it.
# Edited by humans and committed to Git. Each entry matches a script by "identity" (exact) or by
# "url" (pattern with * wildcards), so it survives version changes of the script.
`;

export function looksLikeIdentity(target: string): boolean {
  return /^(url|inline|blob|data):/i.test(target);
}

export interface EntryFields {
  readonly purpose?: string | undefined;
  readonly owner?: string | undefined;
  readonly authorizedBy?: string | undefined;
  readonly authorizedAt?: string | undefined;
  readonly reviewBy?: string | undefined;
  readonly notes?: string | undefined;
}

function cleanFields(fields: EntryFields): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(fields)) if (typeof v === 'string' && v.trim() !== '') out[k] = v.trim();
  return out;
}

function validateEntry(entry: Record<string, string>): InventoryEntry {
  const parsed = InventoryEntrySchema.safeParse(entry);
  if (!parsed.success) throw new ConfigError(`Invalid inventory entry:\n${formatZodIssues(parsed.error)}`);
  return parsed.data;
}

/** Add or update the entry for `target` (an identity such as "url:https://..." or a URL pattern). Returns the new file text. */
export function editInventoryText(existingText: string | undefined, target: string, fields: EntryFields, mode: 'add' | 'set', source: string): { text: string; created: boolean } {
  const key = looksLikeIdentity(target) ? 'identity' : 'url';
  const text = existingText ?? `${FILE_HEADER}version: 1\nscripts: []\n`;
  parseInventory(text, source); // refuse to edit a file that does not validate
  const doc = parseDocument(text);
  if (!isMap(doc.contents)) doc.contents = doc.createNode({ version: 1, scripts: [] }) as never;
  let scripts = doc.get('scripts', true);
  if (!isSeq(scripts)) {
    doc.set('scripts', doc.createNode([]));
    scripts = doc.get('scripts', true);
  }
  if (!isSeq(scripts)) throw new ConfigError(`Cannot edit ${source}: "scripts" is not a list`);
  const index = scripts.items.findIndex((item) => isMap(item) && item.get(key) === target);
  const changes = cleanFields(fields);
  if (mode === 'add') {
    if (index >= 0) throw new ConfigError(`${source} already has an entry for ${target}`, 'Use "thirdsentry inventory set" to change it.');
    scripts.add(doc.createNode(validateEntry({ [key]: target, ...changes })));
  } else {
    if (index < 0) throw new ConfigError(`${source} has no entry for ${target}`, 'Use "thirdsentry inventory add" to create it.');
    const item = scripts.items[index];
    if (!isMap(item)) throw new ConfigError(`Cannot edit ${source}: entry ${index + 1} is not a mapping`);
    const merged: Record<string, string> = { [key]: target };
    for (const k of ['purpose', 'owner', 'authorizedBy', 'authorizedAt', 'reviewBy', 'notes']) {
      const v = changes[k] ?? (item.get(k) as string | undefined);
      if (typeof v === 'string') merged[k] = v;
    }
    validateEntry(merged);
    for (const [k, v] of Object.entries(changes)) item.set(k, v);
  }
  return { text: String(doc), created: existingText === undefined };
}

export async function saveInventoryEdit(paths: StoragePaths, site: string, target: string, fields: EntryFields, mode: 'add' | 'set'): Promise<string> {
  const path = inventoryPath(paths, site);
  const existing = (await pathExists(path)) ? await readFile(path, 'utf8') : undefined;
  const { text } = editInventoryText(existing, target, fields, mode, path);
  await writeFileAtomic(path, text);
  return path;
}

/** Serialise entries to YAML (used by tests and tooling). */
export function stringifyInventory(file: InventoryFile): string {
  return `${FILE_HEADER}${stringifyYaml(file)}`;
}
