import { join } from 'node:path';
import { z } from 'zod';
import type { StoragePaths } from '../storage/paths.js';
import type { Finding, Severity } from '../types/findings.js';
import { pathExists, readJsonFile, writeJsonAtomic } from '../utils/fs.js';
import { getLogger } from '../utils/logger.js';

/**
 * Finding state used to avoid reporting and alerting on the same unchanged
 * finding again and again.
 *
 * Finding IDs are content-addressed fingerprints (site, kind, resource,
 * current hash, ...): the same unchanged problem has the same ID across scans,
 * while any further change produces a new ID and is therefore "new" again.
 */

const EntrySchema = z.object({
  firstSeen: z.string(),
  lastSeen: z.string(),
  timesSeen: z.number().int().min(1),
  severity: z.string(),
  lastAlertedAt: z.string().optional(),
  lastAlertedSeverity: z.string().optional(),
});

const StateSchema = z.object({ version: z.literal(1), findings: z.record(z.string(), EntrySchema) });

export type FindingStateEntry = z.infer<typeof EntrySchema>;
export type FindingState = z.infer<typeof StateSchema>;

const RETENTION_DAYS = 180;

export function findingStatePath(paths: StoragePaths): string {
  return join(paths.state, 'findings.json');
}

export async function loadFindingState(paths: StoragePaths): Promise<FindingState> {
  const path = findingStatePath(paths);
  if (!(await pathExists(path))) return { version: 1, findings: {} };
  try {
    return StateSchema.parse(await readJsonFile(path, 64 * 1024 * 1024));
  } catch (error) {
    getLogger('state').warn({ err: (error as Error).message }, 'finding state is unreadable; starting fresh (findings will be reported as new)');
    return { version: 1, findings: {} };
  }
}

export async function saveFindingState(paths: StoragePaths, state: FindingState): Promise<void> {
  await writeJsonAtomic(findingStatePath(paths), state);
}

/** Mark findings as new or recurring and update the state in place. */
export function trackFindings(findings: Finding[], state: FindingState, now: Date = new Date()): void {
  const at = now.toISOString();
  for (const f of findings) {
    const entry = state.findings[f.id];
    if (entry) {
      f.status = 'recurring';
      state.findings[f.id] = { ...entry, lastSeen: at, timesSeen: entry.timesSeen + 1, severity: f.severity };
    } else {
      f.status = 'new';
      state.findings[f.id] = { firstSeen: at, lastSeen: at, timesSeen: 1, severity: f.severity };
    }
  }
  const cutoff = now.getTime() - RETENTION_DAYS * 86_400_000;
  for (const [id, entry] of Object.entries(state.findings)) {
    if (Date.parse(entry.lastSeen) < cutoff) delete state.findings[id];
  }
}

/** Annotate statuses without modifying state (read-only commands such as diff). */
export function annotateFindings(findings: Finding[], state: FindingState): void {
  for (const f of findings) f.status = state.findings[f.id] ? 'recurring' : 'new';
}

export function recordAlerted(state: FindingState, ids: readonly string[], severityOf: (id: string) => Severity | undefined, now: Date = new Date()): void {
  const at = now.toISOString();
  for (const id of ids) {
    const severity = severityOf(id) ?? 'info';
    const entry = state.findings[id] ?? { firstSeen: at, lastSeen: at, timesSeen: 1, severity };
    state.findings[id] = { ...entry, lastAlertedAt: at, lastAlertedSeverity: severity };
  }
}
