import { mkdir, readdir, readFile, rm, stat, utimes } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { ThirdSentryConfig } from '../config/schema.js';
import { ThirdSentryError } from '../utils/errors.js';
import { ExitCode } from '../utils/exit-codes.js';
import { copyFileAtomic, pathExists, readJsonFile, writeFileAtomic, writeJsonAtomic } from '../utils/fs.js';
import type { ScanResult } from '../types/index.js';
import { SCAN_RESULT_MIGRATIONS, upgradeDocument } from './migrations.js';
import { assertInside, scanReportDir, scanResultPath, type StoragePaths } from './paths.js';

export { scanResultPath } from './paths.js';

/**
 * Filesystem persistence for scan results, screenshots and retained script
 * contents. All writes are atomic (temp file + fsync + rename) and confined to
 * the storage directory. Commands that write here hold the storage lock
 * (storage-lock.ts), so there is a single writer at a time.
 */

const SHA256_HEX = /^[0-9a-f]{64}$/;

export async function ensureStorage(paths: StoragePaths): Promise<void> {
  for (const dir of [paths.root, paths.baselines, paths.reports, paths.scans, paths.state]) {
    await mkdir(dir, { recursive: true });
  }
}

/**
 * Persist a scan result to reports/scans/<scan-id>.json and, unless
 * `updateLatest` is false, atomically update reports/latest-scan.json.
 */
export async function saveScanResult(paths: StoragePaths, result: ScanResult, options: { updateLatest?: boolean } = {}): Promise<string> {
  await ensureStorage(paths);
  const target = scanResultPath(paths, result.scanId);
  await writeJsonAtomic(target, result);
  if (options.updateLatest !== false) await copyFileAtomic(target, paths.latestScan);
  return target;
}

export async function saveScreenshots(paths: StoragePaths, screenshots: ReadonlyArray<{ path: string; data: Buffer }>): Promise<void> {
  for (const shot of screenshots) {
    const target = assertInside(paths.reports, join(paths.reports, shot.path));
    await mkdir(dirname(target), { recursive: true });
    await writeFileAtomic(target, shot.data);
  }
}

export async function loadScanResult(path: string): Promise<ScanResult> {
  const raw = await readJsonFile(path);
  const data = upgradeDocument(SCAN_RESULT_MIGRATIONS, raw, path) as Partial<ScanResult>;
  if (data.kind !== 'thirdsentry-scan' || data.schemaVersion !== SCAN_RESULT_MIGRATIONS.current || !Array.isArray(data.sites) || typeof data.scanId !== 'string') {
    throw new ThirdSentryError(`${path} is not a ThirdSentry scan result`, { exitCode: ExitCode.ConfigError });
  }
  return data as ScanResult;
}

export async function loadLatestScan(paths: StoragePaths): Promise<ScanResult> {
  if (!(await pathExists(paths.latestScan))) {
    throw new ThirdSentryError('No scan results found', { exitCode: ExitCode.ConfigError, hint: 'Run "thirdsentry scan" first.' });
  }
  return loadScanResult(paths.latestScan);
}

/** Per-scan report directory (reports/scans/<scan-id>/), created if needed. */
export async function ensureScanReportDir(paths: StoragePaths, scanId: string): Promise<string> {
  const dir = scanReportDir(paths, scanId);
  await mkdir(dir, { recursive: true });
  return dir;
}

export type ScriptContentMode = 'none' | 'findings' | 'all';

/** Effective script-content retention mode (honours the deprecated storeScriptContent flag). */
export function scriptContentMode(retention: Pick<ThirdSentryConfig['retention'], 'scriptContent' | 'storeScriptContent'>): ScriptContentMode {
  if (retention.scriptContent) return retention.scriptContent;
  if (retention.storeScriptContent !== undefined) return retention.storeScriptContent ? 'all' : 'none';
  return 'findings';
}

/** Content-addressed store for script bodies (see retention.scriptContent). */
export class ContentStore {
  constructor(private readonly dir: string) {}

  private pathFor(sha256: string): string {
    if (!SHA256_HEX.test(sha256)) throw new ThirdSentryError(`Invalid content hash: ${sha256}`);
    return assertInside(this.dir, join(this.dir, sha256.slice(0, 2), sha256));
  }

  /**
   * Store a body. If it is already stored, its modification time is refreshed
   * instead: retention expires content by mtime, and content that is still
   * being observed must not expire.
   */
  async put(sha256: string, data: Buffer): Promise<void> {
    const target = this.pathFor(sha256);
    if (await pathExists(target)) {
      const now = new Date();
      await utimes(target, now, now);
      return;
    }
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
  /** Scan results to keep per site. */
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

const SCAN_FILE = /^([A-Za-z0-9][A-Za-z0-9._-]*)\.json$/;

async function scanSites(path: string): Promise<string[] | undefined> {
  try {
    const data = (await readJsonFile(path)) as { sites?: Array<{ name?: unknown }> };
    if (!Array.isArray(data.sites)) return undefined;
    return [...new Set(data.sites.map((s) => s.name).filter((n): n is string => typeof n === 'string'))];
  } catch {
    return undefined;
  }
}

/**
 * Apply retention: keep at most `maxScans` scan results PER SITE (so a site
 * scanned often cannot evict the history of another), and remove scan results
 * (with their per-scan report directories), screenshots and cached script
 * content older than `maxAgeDays`. Baselines, latest reports and finding
 * state are never touched.
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
    const entries = await readdir(paths.scans, { withFileTypes: true });
    const scans: Array<{ id: string; mtime: number; sites: string[] | undefined }> = [];
    for (const e of entries) {
      const m = e.isFile() ? SCAN_FILE.exec(e.name) : null;
      if (!m) continue;
      const full = join(paths.scans, e.name);
      scans.push({ id: m[1] as string, mtime: (await stat(full)).mtimeMs, sites: await scanSites(full) });
    }
    scans.sort((a, b) => b.mtime - a.mtime || b.id.localeCompare(a.id));
    const perSite = new Map<string, number>();
    const kept = new Set<string>();
    for (const scan of scans) {
      if (now - scan.mtime > maxAgeMs) continue;
      // Unreadable scan files form their own group so they cannot evict real scans.
      const groups = scan.sites && scan.sites.length > 0 ? scan.sites : ['\u0000unreadable'];
      let keep = false;
      for (const site of groups) {
        const count = perSite.get(site) ?? 0;
        if (count < options.maxScans) keep = true;
        perSite.set(site, count + 1);
      }
      if (keep) kept.add(scan.id);
    }
    for (const scan of scans) {
      if (kept.has(scan.id)) continue;
      await remove(join(paths.scans, `${scan.id}.json`));
      await remove(join(paths.scans, scan.id), true);
      removedScans++;
    }
    // Report directories whose scan result is gone: expire by age.
    const ids = new Set(scans.map((s) => s.id));
    for (const e of entries) {
      if (!e.isDirectory() || ids.has(e.name)) continue;
      const full = join(paths.scans, e.name);
      if (now - (await stat(full)).mtimeMs > maxAgeMs) await remove(full, true);
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
