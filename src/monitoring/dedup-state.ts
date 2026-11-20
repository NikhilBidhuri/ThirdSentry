import { rename } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { CHANNELS, type ChannelName } from '../alerts/channels.js';
import type { StoragePaths } from '../storage/paths.js';
import type { Finding, Severity } from '../types/findings.js';
import { ThirdSentryError } from '../utils/errors.js';
import { pathExists, readJsonFile, writeJsonAtomic } from '../utils/fs.js';
import { getLogger } from '../utils/logger.js';

/**
 * Finding state used to avoid reporting and alerting on the same unchanged
 * finding again and again.
 *
 * Finding IDs are content-addressed fingerprints (site, kind, resource,
 * current hash, ...): the same unchanged problem has the same ID across scans,
 * while any further change produces a new ID and is therefore "new" again.
 *
 * State format:
 *  - version 2 (current): alert delivery is tracked per channel in
 *    `entry.alerts[channel] = { at, severity }`, so a channel that failed (or
 *    skipped a finding) is retried independently of the channels that
 *    succeeded.
 *  - version 1 (legacy): a single `lastAlertedAt`/`lastAlertedSeverity` per
 *    finding. On load it is migrated by treating the finding as delivered to
 *    every channel at that time (the old code marked it alerted for all of
 *    them), so upgrading never re-sends old alerts.
 */

const AlertMarkSchema = z.object({ at: z.string(), severity: z.string() });

const EntrySchema = z.object({
  firstSeen: z.string(),
  lastSeen: z.string(),
  timesSeen: z.number().int().min(1),
  severity: z.string(),
  /** Per-channel delivery record (version 2). */
  alerts: z.record(z.string(), AlertMarkSchema).optional(),
  /** Legacy (version 1) fields, migrated on load; never written. */
  lastAlertedAt: z.string().optional(),
  lastAlertedSeverity: z.string().optional(),
});

const RecoverySchema = z.object({
  /** When the unreadable state file was replaced. */
  at: z.string(),
  /** Where the unreadable file was moved to. */
  backup: z.string(),
  reason: z.string(),
  /** Channels that have already received the "alert history was reset" notice. */
  notified: z.array(z.string()),
});

const StateSchema = z.object({
  version: z.union([z.literal(1), z.literal(2)]),
  findings: z.record(z.string(), EntrySchema),
  recovery: RecoverySchema.optional(),
});

export type AlertMark = z.infer<typeof AlertMarkSchema>;
export type FindingStateEntry = z.infer<typeof EntrySchema>;
export type StateRecovery = z.infer<typeof RecoverySchema>;
export type FindingState = z.infer<typeof StateSchema>;

export const FINDING_STATE_VERSION = 2 as const;
const RETENTION_DAYS = 180;
const MAX_STATE_BYTES = 64 * 1024 * 1024;

export function findingStatePath(paths: StoragePaths): string {
  return join(paths.state, 'findings.json');
}

/** Convert legacy per-finding alert fields into per-channel marks (in place). */
export function migrateFindingState(state: FindingState): FindingState {
  for (const [id, entry] of Object.entries(state.findings)) {
    const { lastAlertedAt, lastAlertedSeverity, ...rest } = entry;
    if (lastAlertedAt === undefined && lastAlertedSeverity === undefined) continue;
    const alerts = { ...(rest.alerts ?? {}) };
    if (lastAlertedAt) {
      for (const channel of CHANNELS) alerts[channel] ??= { at: lastAlertedAt, severity: lastAlertedSeverity ?? entry.severity };
    }
    state.findings[id] = { ...rest, ...(Object.keys(alerts).length ? { alerts } : {}) };
  }
  state.version = FINDING_STATE_VERSION;
  return state;
}

/**
 * Load the finding state.
 *
 * A state file whose content cannot be parsed is never silently discarded:
 * it is moved aside to `findings.json.corrupt-<timestamp>`, an error is
 * logged, and a fresh state carrying a `recovery` marker is written in its
 * place. Alerts sent while the marker is present say that the alert history
 * was reset (so earlier findings may be repeated once). Repeats stay bounded:
 * one message per channel, at most `maxFindingsPerAlert` findings each,
 * GitHub issues de-duplicated by their marker and capped by `maxIssuesPerRun`.
 * I/O errors (permissions, locked file) are not treated as corruption: they
 * are raised so that the run fails visibly instead of resetting state.
 */
export async function loadFindingState(paths: StoragePaths, now: Date = new Date()): Promise<FindingState> {
  const path = findingStatePath(paths);
  if (!(await pathExists(path))) return { version: FINDING_STATE_VERSION, findings: {} };
  let reason: string;
  try {
    const parsed = StateSchema.safeParse(await readJsonFile(path, MAX_STATE_BYTES));
    if (parsed.success) return migrateFindingState(parsed.data);
    reason = `invalid structure: ${parsed.error.issues[0]?.message ?? 'schema mismatch'}`;
  } catch (error) {
    if (typeof (error as { code?: unknown }).code === 'string') {
      throw new ThirdSentryError(`Cannot read finding state ${path}: ${(error as Error).message}`, {
        hint: 'Fix the file permissions or release the lock; the state was left untouched.',
        cause: error,
      });
    }
    reason = (error as Error).message;
  }
  const backup = `${path}.corrupt-${now.toISOString().replace(/[:.]/g, '-')}`;
  await rename(path, backup);
  const state: FindingState = { version: FINDING_STATE_VERSION, findings: {}, recovery: { at: now.toISOString(), backup, reason, notified: [] } };
  await writeJsonAtomic(path, state);
  getLogger('state').error(
    { backup, reason },
    'finding state was unreadable; it was moved aside and a fresh state was started. Findings will be reported as new, and the next alert on each channel says that its history was reset.',
  );
  return state;
}

export async function saveFindingState(paths: StoragePaths, state: FindingState): Promise<void> {
  migrateFindingState(state);
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

/** When (and at which severity) a finding was last delivered through a channel. */
export function lastAlert(entry: FindingStateEntry | undefined, channel: ChannelName): AlertMark | undefined {
  if (!entry) return undefined;
  const mark = entry.alerts?.[channel];
  if (mark) return mark;
  // Not migrated yet (legacy in-memory state): the old format meant "delivered everywhere".
  return entry.lastAlertedAt ? { at: entry.lastAlertedAt, severity: entry.lastAlertedSeverity ?? entry.severity } : undefined;
}

/** Record that `ids` were delivered through `channel`. Other channels are unaffected. */
export function recordAlerted(state: FindingState, channel: ChannelName, ids: readonly string[], severityOf: (id: string) => Severity | undefined, now: Date = new Date()): void {
  const at = now.toISOString();
  for (const id of ids) {
    const severity = severityOf(id) ?? 'info';
    const entry = state.findings[id] ?? { firstSeen: at, lastSeen: at, timesSeen: 1, severity };
    state.findings[id] = { ...entry, alerts: { ...(entry.alerts ?? {}), [channel]: { at, severity } } };
  }
}
