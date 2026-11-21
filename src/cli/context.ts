import type { Command } from 'commander';
import { loadConfig, type ResolvedConfig } from '../config/loader.js';
import { acquireStorageLock, type StorageLock } from '../storage/storage-lock.js';
import type { ScanResult, SiteResult } from '../types/index.js';
import { ConfigError } from '../utils/errors.js';
import { configureLogger } from '../utils/logger.js';

export interface GlobalOptions {
  readonly config?: string;
  readonly verbose?: boolean;
  readonly json?: boolean;
  readonly quiet?: boolean;
  readonly lockTimeout?: string;
}

function rootOf(command: Command): Command {
  let root: Command = command;
  while (root.parent) root = root.parent;
  return root;
}

/** Read global options from the root program and configure logging accordingly. */
export function globalOptions(command: Command): GlobalOptions {
  const opts = rootOf(command).opts<GlobalOptions>();
  configureLogger({ verbose: opts.verbose === true, quiet: opts.json === true || opts.quiet === true });
  return opts;
}

export function logLevelFor(opts: GlobalOptions): string {
  if (opts.verbose) return 'debug';
  if (opts.json || opts.quiet) return 'warn';
  return 'info';
}

/** Parse a non-negative integer option strictly ("abc", "1.5", "-1" are errors). */
export function parseNonNegativeInt(value: string | undefined, name: string, fallback: number, max = Number.MAX_SAFE_INTEGER): number {
  if (value === undefined) return fallback;
  const v = value.trim();
  if (!/^\d+$/.test(v) || Number(v) > max) throw new ConfigError(`${name} must be a whole number between 0 and ${max} (got "${value}")`);
  return Number(v);
}

/**
 * Validate a `--site` filter against the configured sites (unknown names are
 * an error in every command) and return the scan's sites it selects. A
 * configured site that the scan does not contain is an error too.
 */
export function selectScanSites(resolved: ResolvedConfig, scan: ScanResult, siteOption: string | undefined): SiteResult[] {
  if (siteOption === undefined) return [...scan.sites];
  const names = [...new Set(siteOption.split(',').map((s) => s.trim()).filter(Boolean))];
  if (names.length === 0) throw new ConfigError('--site needs at least one site name');
  const configured = resolved.config.sites.map((s) => s.name);
  const unknown = names.filter((n) => !configured.includes(n));
  if (unknown.length > 0) throw new ConfigError(`Unknown site(s): ${unknown.join(', ')}`, `Configured sites: ${configured.join(', ')}`);
  const notInScan = names.filter((n) => !scan.sites.some((s) => s.name === n));
  if (notInScan.length > 0) {
    throw new ConfigError(`Scan ${scan.scanId} does not contain site(s): ${notInScan.join(', ')}`, `It contains: ${scan.sites.map((s) => s.name).join(', ') || 'no sites'}. Scan them first.`);
  }
  return scan.sites.filter((s) => names.includes(s.name));
}

/** Commands that write to the storage directory and therefore run under the storage lock. */
export const STORAGE_WRITING_COMMANDS: ReadonlySet<string> = new Set(['scan', 'analyze', 'baseline', 'alert', 'cleanup', 'report']);

let heldLock: StorageLock | undefined;

/**
 * Acquire the storage lock for `command` (called centrally before every
 * storage-writing command runs, see index.ts). Commands that do not write
 * storage are not locked.
 */
export async function lockStorageFor(command: Command): Promise<void> {
  const name = command.name();
  if (!STORAGE_WRITING_COMMANDS.has(name) || heldLock) return;
  const g = rootOf(command).opts<GlobalOptions>();
  const waitSeconds = parseNonNegativeInt(g.lockTimeout, '--lock-timeout', 0, 86_400);
  const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
  heldLock = await acquireStorageLock(resolved.paths, { command: name, waitMs: waitSeconds * 1000 });
}

/** Release the storage lock if this process holds it. */
export async function releaseStorageLock(): Promise<void> {
  const lock = heldLock;
  heldLock = undefined;
  await lock?.release();
}
