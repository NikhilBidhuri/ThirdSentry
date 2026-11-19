import { copyFile, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { ThirdSentryError } from '../utils/errors.js';
import { pathExists, readJsonFile, writeFileAtomic, writeJsonAtomic } from '../utils/fs.js';
import type { ScanResult } from '../types/index.js';
import type { StoragePaths } from './paths.js';

/**
 * Filesystem persistence for scan results, screenshots and optional script
 * contents. All writes are atomic and confined to the storage directory.
 */

const SHA256_HEX = /^[0-9a-f]{64}$/;

function assertInside(root: string, target: string): string {
  const r = resolve(root);
  const t = resolve(target);
  if (t !== r && !t.startsWith(r + sep)) throw new ThirdSentryError(`Refusing to write outside storage directory: ${t}`);
  return t;
}

export async function ensureStorage(paths: StoragePaths): Promise<void> {
  for (const dir of [paths.root, paths.baselines, paths.reports, paths.scans, paths.state]) {
    await mkdir(dir, { recursive: true });
  }
}

export function scanResultPath(paths: StoragePaths, scanId: string): string {
  if (!/^[A-Za-z0-9._-]+$/.test(scanId)) throw new ThirdSentryError(`Invalid scan id: ${scanId}`);
  return join(paths.scans, `${scanId}.json`);
}

export async function saveScanResult(paths: StoragePaths, result: ScanResult): Promise<string> {
  await ensureStorage(paths);
  const target = scanResultPath(paths, result.scanId);
  await writeJsonAtomic(target, result);
  await copyFile(target, paths.latestScan);
  return target;
}

export async function saveScreenshots(paths: StoragePaths, screenshots: ReadonlyArray<{ path: string; data: Buffer }>): Promise<void> {
  for (const shot of screenshots) {
    const target = assertInside(paths.reports, join(paths.reports, shot.path));
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, shot.data);
  }
}

export async function loadScanResult(path: string): Promise<ScanResult> {
  const data = (await readJsonFile(path)) as Partial<ScanResult>;
  if (data.kind !== 'thirdsentry-scan' || data.schemaVersion !== 1 || !Array.isArray(data.sites)) {
    throw new ThirdSentryError(`${path} is not a ThirdSentry scan result`, { exitCode: 2 });
  }
  return data as ScanResult;
}

export async function loadLatestScan(paths: StoragePaths): Promise<ScanResult> {
  if (!(await pathExists(paths.latestScan))) {
    throw new ThirdSentryError('No scan results found', { exitCode: 2, hint: 'Run "thirdsentry scan" first.' });
  }
  return loadScanResult(paths.latestScan);
}

/** Content-addressed store for script bodies (only used when retention.storeScriptContent is enabled). */
export class ContentStore {
  constructor(private readonly dir: string) {}

  private pathFor(sha256: string): string {
    if (!SHA256_HEX.test(sha256)) throw new ThirdSentryError(`Invalid content hash: ${sha256}`);
    return join(this.dir, sha256.slice(0, 2), sha256);
  }

  async put(sha256: string, data: Buffer): Promise<void> {
    const target = this.pathFor(sha256);
    if (await pathExists(target)) return;
    await writeFileAtomic(target, data);
  }

  async get(sha256: string): Promise<Buffer | undefined> {
    const target = this.pathFor(sha256);
    if (!(await pathExists(target))) return undefined;
    return readFile(target);
  }

  async has(sha256: string): Promise<boolean> {
    return pathExists(this.pathFor(sha256));
  }
}

export interface CleanupResult {
  readonly removedScans: number;
  readonly removedContent: number;
  readonly removedScreenshots: number;
  readonly keptReferencedContent: number;
  readonly dryRun: boolean;
}

export interface RetentionOptions {
  readonly maxScans: number;
  readonly maxAgeDays: number;
  readonly now?: Date;
  /** Delete all cached script content (except content referenced by baselines, unless purgeReferenced). */
  readonly purgeContent?: boolean;
  readonly purgeReferenced?: boolean;
  /** Content hashes still referenced by approved baselines (kept so code diffs remain possible). */
  readonly keepContent?: ReadonlySet<string>;
  readonly dryRun?: boolean;
}

/**
 * Apply retention: keep at most `maxScans` scan files, and remove scan
 * results, screenshots and cached script content older than `maxAgeDays`.
 * Baselines, reports and finding state are never touched.
 */
export async function applyRetention(paths: StoragePaths, options: RetentionOptions): Promise<CleanupResult> {
  const now = (options.now ?? new Date()).getTime();
  const maxAgeMs = options.maxAgeDays * 86_400_000;
  const remove = async (path: string, recursive = false): Promise<void> => {
    if (!options.dryRun) await rm(path, { recursive, force: true });
  };
  let removedScans = 0;
  let removedContent = 0;
  let removedScreenshots = 0;
  let keptReferencedContent = 0;

  if (await pathExists(paths.scans)) {
    const files = (await readdir(paths.scans)).filter((f) => f.endsWith('.json'));
    const withTimes = await Promise.all(files.map(async (f) => ({ f, mtime: (await stat(join(paths.scans, f))).mtimeMs })));
    withTimes.sort((a, b) => b.mtime - a.mtime);
    for (const [i, entry] of withTimes.entries()) {
      if (i >= options.maxScans || now - entry.mtime > maxAgeMs) {
        await remove(join(paths.scans, entry.f));
        removedScans++;
      }
    }
  }

  const shotsDir = join(paths.reports, 'screenshots');
  if (await pathExists(shotsDir)) {
    for (const dir of await readdir(shotsDir)) {
      const full = join(shotsDir, dir);
      const info = await stat(full);
      if (now - info.mtimeMs > maxAgeMs) {
        await remove(full, true);
        removedScreenshots++;
      }
    }
  }

  if (await pathExists(paths.content)) {
    for (const prefix of await readdir(paths.content)) {
      const dir = join(paths.content, prefix);
      if (!(await stat(dir)).isDirectory()) continue;
      for (const file of await readdir(dir)) {
        const full = join(dir, file);
        const info = await stat(full);
        const expired = options.purgeContent === true || now - info.mtimeMs > maxAgeMs;
        if (!expired) continue;
        if (options.keepContent?.has(file) && !options.purgeReferenced) {
          keptReferencedContent++;
          continue;
        }
        await remove(full);
        removedContent++;
      }
    }
  }
  return { removedScans, removedContent, removedScreenshots, keptReferencedContent, dryRun: options.dryRun === true };
}
