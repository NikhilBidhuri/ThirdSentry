import { describe, expect, it } from 'vitest';
import { mkdir, readdir, readFile, stat, utimes, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { approveSelected, createBaseline } from '../../src/baseline/baseline-manager.js';
import { validateBaseline } from '../../src/baseline/baseline-validator.js';
import { analysisExitCode, missingBaselineNotice } from '../../src/monitoring/analysis-runner.js';
import { ContentStore, applyRetention, loadScanResult, saveScanResult, scriptContentMode } from '../../src/storage/filesystem-store.js';
import { BASELINE_MIGRATIONS, SCAN_RESULT_MIGRATIONS, upgradeDocument } from '../../src/storage/migrations.js';
import { assertInside, baselinePath, scanResultPath, storagePaths } from '../../src/storage/paths.js';
import { StorageLockedError, acquireStorageLock } from '../../src/storage/storage-lock.js';
import { renderConfig } from '../../src/cli/commands/init.js';
import { parseNonNegativeInt } from '../../src/cli/context.js';
import { copyFileAtomic } from '../../src/utils/fs.js';
import type { AnalysisReport } from '../../src/types/report.js';
import type { ScanResult } from '../../src/types/index.js';
import { page, scriptResource, site } from '../fixtures/builders.js';
import { tempDir } from '../helpers.js';

const A = 'https://cdn.vendor-a.example/a.js';

function reportWith(baselineExists: boolean, scanStatus = 'complete'): AnalysisReport {
  return { findings: [], scanStatus, sites: [{ name: 'shop', baseline: { exists: baselineExists, path: 'x' } }] } as unknown as AnalysisReport;
}

describe('approval is bound to the reviewed content hash', () => {
  it('approving the benign variant does not approve the malicious variant of the same URL', () => {
    const initial = createBaseline(site([scriptResource(A, 'v1')]), { scanId: 's1' });
    const benign = scriptResource(A, 'benign', { pages: ['/'] });
    const evil = scriptResource(A, 'evil()', { pages: ['/checkout'] });
    const scan = site([benign, evil], { pages: [page('/'), page('/checkout')] });
    const next = approveSelected(initial, scan, [{ kind: 'resource', value: `url:${A}`, sha256: benign.hashes.sha256 }], { scanId: 's2' });
    const hashes = next.resources.find((r) => r.identity === `url:${A}`)?.approvedHashes.map((h) => h.sha256);
    expect(hashes).toEqual([benign.hashes.sha256]);
    expect(hashes).not.toContain(evil.hashes.sha256);
  });

  it('refuses an approval for a version that is not in the scan', () => {
    const initial = createBaseline(site([scriptResource(A, 'v1')]), { scanId: 's1' });
    expect(() => approveSelected(initial, site([scriptResource(A, 'v2')]), [{ kind: 'resource', value: `url:${A}`, sha256: 'f'.repeat(64) }], { scanId: 's2' })).toThrow(/does not contain version/);
  });
});

describe('exit codes', () => {
  it('exits 3 when a site has no baseline unless allowed', () => {
    expect(analysisExitCode(reportWith(false), { failOn: 'none' })).toBe(3);
    expect(analysisExitCode(reportWith(false), { failOn: 'none', allowMissingBaseline: true })).toBe(0);
    expect(analysisExitCode(reportWith(true), { failOn: 'none' })).toBe(0);
    expect(missingBaselineNotice(reportWith(false), false)).toMatch(/First run/);
    expect(missingBaselineNotice(reportWith(true), false)).toBeUndefined();
  });

  it('exits 4 on alert failure only with --fail-on-alert-error', () => {
    expect(analysisExitCode(reportWith(true), { failOn: 'none', alertFailed: true })).toBe(0);
    expect(analysisExitCode(reportWith(true), { failOn: 'none', alertFailed: true, failOnAlertError: true })).toBe(4);
  });
});

describe('storage lock', () => {
  it('is exclusive, released on release, and stale locks of dead processes are taken over', async () => {
    const paths = storagePaths(await tempDir('lock-'));
    const first = await acquireStorageLock(paths, { command: 'scan' });
    await expect(acquireStorageLock(paths, { command: 'baseline' })).rejects.toBeInstanceOf(StorageLockedError);
    await expect(acquireStorageLock(paths, { command: 'baseline', waitMs: 100, pollMs: 20 })).rejects.toThrow(/in use by "thirdsentry scan"/);
    await first.release();
    const second = await acquireStorageLock(paths, { command: 'baseline' });
    await second.release();

    // A lock left by a crashed process on this host (pid that is not alive).
    const { hostname } = await import('node:os');
    await writeFile(paths.lock, JSON.stringify({ pid: 2_000_000_000, host: hostname(), startedAt: 'x', command: 'scan', token: 'dead' }));
    const third = await acquireStorageLock(paths, { command: 'cleanup' });
    await third.release();
  });

  it('takes over a lock whose heartbeat is stale', async () => {
    const paths = storagePaths(await tempDir('lock-stale-'));
    await mkdir(paths.state, { recursive: true });
    await writeFile(paths.lock, JSON.stringify({ pid: process.pid + 1, host: 'other-host', startedAt: 'x', command: 'scan', token: 't' }));
    const old = new Date(Date.now() - 3_600_000);
    await utimes(paths.lock, old, old);
    const lock = await acquireStorageLock(paths, { command: 'scan', staleAfterMs: 60_000 });
    await lock.release();
  });
});

describe('atomic latest copies and path safety', () => {
  it('copyFileAtomic replaces the target and leaves no temp files', async () => {
    const dir = await tempDir('atomic-');
    await writeFile(join(dir, 'a.json'), '{"v":1}');
    await writeFile(join(dir, 'latest.json'), '{"v":0}');
    await copyFileAtomic(join(dir, 'a.json'), join(dir, 'latest.json'));
    expect(await readFile(join(dir, 'latest.json'), 'utf8')).toBe('{"v":1}');
    expect((await readdir(dir)).filter((f) => f.endsWith('.tmp'))).toEqual([]);
  });

  it('rejects traversal in site names and scan ids', async () => {
    const paths = storagePaths(await tempDir('paths-'));
    expect(() => baselinePath(paths, '../../../x')).toThrow();
    expect(() => baselinePath(paths, 'a/b')).toThrow();
    expect(() => scanResultPath(paths, '../x')).toThrow();
    expect(() => assertInside(paths.baselines, join(paths.baselines, '..', 'x'))).toThrow(/outside/);
    expect(baselinePath(paths, 'shop')).toContain('baseline.json');
  });
});

describe('retention', () => {
  const scan = (id: string, siteName: string): ScanResult => ({ kind: 'thirdsentry-scan', schemaVersion: 1, scanId: id, sites: [{ name: siteName }] }) as unknown as ScanResult;

  it('keeps scans per site, not globally', async () => {
    const paths = storagePaths(await tempDir('ret-'));
    const now = Date.now();
    for (const [i, id] of ['a1', 'a2', 'a3', 'b1'].entries()) {
      const p = await saveScanResult(paths, scan(id, id.startsWith('a') ? 'alpha' : 'beta'), { updateLatest: false });
      const t = new Date(now - (10 - i) * 60_000);
      await utimes(p, t, t);
    }
    // b1 is the newest, a1/a2/a3 older. Keep 2 per site: alpha loses a1 only, beta keeps b1.
    const result = await applyRetention(paths, { maxScans: 2, maxAgeDays: 365 });
    expect(result.removedScans).toBe(1);
    expect((await readdir(paths.scans)).sort()).toEqual(['a2.json', 'a3.json', 'b1.json']);
  });

  it('ContentStore.put refreshes mtime of existing content', async () => {
    const dir = await tempDir('content-');
    const store = new ContentStore(dir);
    const sha = 'ab'.repeat(32);
    await store.put(sha, Buffer.from('x'));
    const file = join(dir, 'ab', sha);
    const old = new Date(Date.now() - 100 * 86_400_000);
    await utimes(file, old, old);
    await store.put(sha, Buffer.from('x'));
    expect(Date.now() - (await stat(file)).mtimeMs).toBeLessThan(60_000);
  });

  it('defaults to findings mode and honours the deprecated flag', () => {
    expect(scriptContentMode({})).toBe('findings');
    expect(scriptContentMode({ storeScriptContent: true })).toBe('all');
    expect(scriptContentMode({ storeScriptContent: false })).toBe('none');
    expect(scriptContentMode({ scriptContent: 'none' })).toBe('none');
  });
});

describe('schema migrations', () => {
  it('upgrades older documents in order and refuses newer ones', () => {
    const reg = { name: 'thing', current: 3, migrations: { 1: (d: Record<string, unknown>) => ({ ...d, a: 1 }), 2: (d: Record<string, unknown>) => ({ ...d, b: 2 }) } };
    expect(upgradeDocument(reg, { schemaVersion: 1 }, 'f')).toEqual({ schemaVersion: 3, a: 1, b: 2 });
    expect(() => upgradeDocument(reg, { schemaVersion: 4 }, 'f')).toThrow(/only understands up to version/);
    expect(() => upgradeDocument({ ...reg, migrations: {} }, { schemaVersion: 1 }, 'f')).toThrow(/cannot be upgraded/);
  });

  it('refuses baselines and scan results from a newer version', async () => {
    const b = createBaseline(site([scriptResource(A, 'a')]), { scanId: 's1' });
    expect(() => validateBaseline({ ...b, schemaVersion: 99 }, 'shop', 'x')).toThrow(/only understands up to version/);
    expect(BASELINE_MIGRATIONS.current).toBe(b.schemaVersion);
    const dir = await tempDir('scanver-');
    await writeFile(join(dir, 's.json'), JSON.stringify({ kind: 'thirdsentry-scan', schemaVersion: SCAN_RESULT_MIGRATIONS.current + 1, scanId: 's', sites: [] }));
    await expect(loadScanResult(join(dir, 's.json'))).rejects.toThrow(/only understands up to version/);
  });
});

describe('cli helpers', () => {
  it('parses numeric options strictly', () => {
    expect(parseNonNegativeInt('0', '--context', 3)).toBe(0);
    expect(parseNonNegativeInt(undefined, '--context', 3)).toBe(3);
    expect(() => parseNonNegativeInt('abc', '--context', 3)).toThrow();
    expect(() => parseNonNegativeInt('-1', '--context', 3)).toThrow();
  });

  it('init inserts values literally and YAML-quoted', () => {
    const text = renderConfig('shop', "https://e.com/$'x\nevil: true");
    expect(text).not.toMatch(/^evil: true/m);
    expect(text).toContain(JSON.stringify("https://e.com/$'x\nevil: true"));
  });
});
