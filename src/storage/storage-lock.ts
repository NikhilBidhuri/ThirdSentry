import { readFileSync, unlinkSync } from 'node:fs';
import { link, mkdir, open, readFile, rename, rm, stat, utimes } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { hostname } from 'node:os';
import { dirname } from 'node:path';
import { ThirdSentryError } from '../utils/errors.js';
import { ExitCode } from '../utils/exit-codes.js';
import type { StoragePaths } from './paths.js';

/**
 * Single-writer lock for the storage directory.
 *
 * Every command that writes scan results, reports, baselines, finding state
 * or the content cache holds this lock for its whole run, so concurrent runs
 * (a cron scan and a manual `baseline`, `analyze` and `alert` in parallel
 * containers) cannot interleave read-modify-write cycles.
 *
 * The lock is a file created with O_EXCL in `state/` (the one directory every
 * writer can write to, also in the hardened containers). It records pid, host,
 * start time and command. The holder refreshes its mtime periodically
 * (heartbeat). A lock is stale when its holder ran on this host and is no
 * longer alive, or when its heartbeat is older than `staleAfterMs` (holder on
 * another host/container that crashed). Stale locks are taken over safely:
 * the stale file is renamed away and checked before a new lock is created.
 */

export interface LockInfo {
  readonly pid: number;
  readonly host: string;
  readonly startedAt: string;
  readonly command: string;
  readonly token: string;
}

export interface AcquireLockOptions {
  /** Command name recorded in the lock (for the error message of a waiting command). */
  readonly command: string;
  /** How long to wait for another holder to finish (0 = fail immediately). */
  readonly waitMs?: number;
  /** A lock whose heartbeat is older than this is considered abandoned. */
  readonly staleAfterMs?: number;
  readonly heartbeatMs?: number;
  readonly pollMs?: number;
}

export const DEFAULT_LOCK_STALE_MS = 10 * 60_000;
const DEFAULT_HEARTBEAT_MS = 30_000;
const DEFAULT_POLL_MS = 500;

export class StorageLockedError extends ThirdSentryError {
  readonly holder: LockInfo | undefined;
  constructor(path: string, holder: LockInfo | undefined) {
    const who = holder ? `"thirdsentry ${holder.command}" (pid ${holder.pid} on ${holder.host}, started ${holder.startedAt})` : 'another ThirdSentry command';
    super(`The storage directory is in use by ${who}`, {
      exitCode: ExitCode.ConfigError,
      hint: `Wait for it to finish, or pass --lock-timeout <seconds> to wait. If no ThirdSentry command is running, delete ${path}.`,
    });
    this.holder = holder;
  }
}

function parseInfo(text: string): LockInfo | undefined {
  try {
    const v = JSON.parse(text) as Partial<LockInfo>;
    if (typeof v.pid === 'number' && typeof v.host === 'string' && typeof v.token === 'string') {
      return { pid: v.pid, host: v.host, token: v.token, startedAt: String(v.startedAt ?? ''), command: String(v.command ?? 'unknown') };
    }
  } catch {
    // partially written or corrupt
  }
  return undefined;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

async function readHolder(path: string): Promise<{ info: LockInfo | undefined; mtimeMs: number } | undefined> {
  try {
    const [text, info] = await Promise.all([readFile(path, 'utf8'), stat(path)]);
    return { info: parseInfo(text), mtimeMs: info.mtimeMs };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}

export function isStale(holder: { info: LockInfo | undefined; mtimeMs: number }, staleAfterMs: number, now = Date.now()): boolean {
  if (now - holder.mtimeMs > staleAfterMs) return true;
  const info = holder.info;
  if (!info) return false; // being written right now, or corrupt but recent
  return info.host === hostname() && info.pid !== process.pid && !processAlive(info.pid);
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export class StorageLock {
  private released = false;
  private readonly timer: NodeJS.Timeout;
  private readonly onExit = (): void => this.releaseSync();

  constructor(
    readonly path: string,
    readonly info: LockInfo,
    heartbeatMs: number,
  ) {
    this.timer = setInterval(() => {
      const now = new Date();
      utimes(this.path, now, now).catch(() => undefined);
    }, heartbeatMs);
    this.timer.unref();
    process.once('exit', this.onExit);
  }

  private stillOurs(text: string): boolean {
    return parseInfo(text)?.token === this.info.token;
  }

  async release(): Promise<void> {
    if (this.released) return;
    this.released = true;
    clearInterval(this.timer);
    process.removeListener('exit', this.onExit);
    try {
      if (this.stillOurs(await readFile(this.path, 'utf8'))) await rm(this.path, { force: true });
    } catch {
      // already gone
    }
  }

  /** Synchronous release for process exit handlers. */
  releaseSync(): void {
    if (this.released) return;
    this.released = true;
    clearInterval(this.timer);
    try {
      if (this.stillOurs(readFileSync(this.path, 'utf8'))) unlinkSync(this.path);
    } catch {
      // already gone
    }
  }
}

async function tryCreate(path: string, info: LockInfo): Promise<boolean> {
  let handle;
  try {
    handle = await open(path, 'wx');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw error;
  }
  try {
    await handle.writeFile(JSON.stringify(info));
    await handle.sync();
  } finally {
    await handle.close();
  }
  return true;
}

/** Move a stale lock out of the way, making sure it is the one we judged stale. */
async function takeOver(path: string, stale: { info: LockInfo | undefined }): Promise<void> {
  const aside = `${path}.stale-${randomBytes(6).toString('hex')}`;
  try {
    await rename(path, aside);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; // someone else took it over
    throw error;
  }
  const moved = parseInfo(await readFile(aside, 'utf8').catch(() => ''));
  if (moved && stale.info && moved.token !== stale.info.token) {
    // A live lock was created between our check and the rename: put it back.
    await link(aside, path).catch(() => undefined);
  }
  await rm(aside, { force: true });
}

/** Acquire the storage lock, waiting up to `waitMs`. Throws StorageLockedError when it stays held. */
export async function acquireStorageLock(paths: StoragePaths, options: AcquireLockOptions): Promise<StorageLock> {
  const path = paths.lock;
  await mkdir(dirname(path), { recursive: true });
  const staleAfterMs = options.staleAfterMs ?? DEFAULT_LOCK_STALE_MS;
  const deadline = Date.now() + Math.max(0, options.waitMs ?? 0);
  const info: LockInfo = {
    pid: process.pid,
    host: hostname(),
    startedAt: new Date().toISOString(),
    command: options.command,
    token: randomBytes(16).toString('hex'),
  };
  for (;;) {
    if (await tryCreate(path, info)) return new StorageLock(path, info, options.heartbeatMs ?? DEFAULT_HEARTBEAT_MS);
    const holder = await readHolder(path);
    if (!holder) continue; // released in the meantime
    if (isStale(holder, staleAfterMs)) {
      await takeOver(path, holder);
      continue;
    }
    if (Date.now() >= deadline) throw new StorageLockedError(path, holder.info);
    await sleep(Math.min(options.pollMs ?? DEFAULT_POLL_MS, Math.max(10, deadline - Date.now())));
  }
}
