import { describe, expect, it } from 'vitest';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  approveFullScan,
  approveSelected,
  createBaseline,
  loadBaseline,
  saveBaseline,
  summarizeBaselineChange,
} from '../../src/baseline/baseline-manager.js';
import { validateBaseline } from '../../src/baseline/baseline-validator.js';
import { storagePaths } from '../../src/storage/paths.js';
import { BaselineError } from '../../src/utils/errors.js';
import { page, scriptResource, site } from '../fixtures/builders.js';
import { tempDir } from '../helpers.js';

const A = 'https://cdn.vendor-a.example/a.js';
const B = 'https://cdn.vendor-b.example/b.js';

describe('baseline manager', () => {
  it('creates a baseline with hashes, domains and an approval record', () => {
    const b = createBaseline(site([scriptResource(A, 'a()')]), { scanId: 's1', reason: 'initial review' });
    expect(b.kind).toBe('thirdsentry-baseline');
    expect(b.resources[0]?.approvedHashes[0]?.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(b.domains.scripts).toEqual(['vendor-a.example']);
    expect(b.approvals[0]).toMatchObject({ scope: 'initial', scanId: 's1', reason: 'initial review' });
  });

  it('only approves resources from completely scanned pages', () => {
    const s = site([scriptResource(A, 'a()', { pages: ['/'] }), scriptResource(B, 'b()', { pages: ['/broken'] })], {
      pages: [page('/'), page('/broken', { status: 'partial' })],
    });
    const b = createBaseline(s, { scanId: 's1' });
    expect(b.resources.map((r) => r.identity)).toEqual([`url:${A}`]);
    expect(b.pages).toEqual(['/']);
  });

  it('full re-approval keeps resources of pages that were not scanned completely', () => {
    const initial = createBaseline(
      site([scriptResource(A, 'a()', { pages: ['/'] }), scriptResource(B, 'b()', { pages: ['/checkout'] })], { pages: [page('/'), page('/checkout')] }),
      { scanId: 's1' },
    );
    const partial = site([scriptResource(A, 'a2()', { pages: ['/'] })], { pages: [page('/'), page('/checkout', { status: 'failed' })] });
    const next = approveFullScan(initial, partial, { scanId: 's2' });
    expect(next.resources.map((r) => r.identity).sort()).toEqual([`url:${A}`, `url:${B}`]);
    expect(next.approvals.map((a) => a.scope)).toEqual(['initial', 'full']);
  });

  it('keeps previous variants only when asked', () => {
    const initial = createBaseline(site([scriptResource(A, 'v1')]), { scanId: 's1' });
    const replaced = approveFullScan(initial, site([scriptResource(A, 'v2')]), { scanId: 's2' });
    expect(replaced.resources[0]?.approvedHashes).toHaveLength(1);
    const kept = approveFullScan(initial, site([scriptResource(A, 'v2')]), { scanId: 's2', keepVariants: true });
    expect(kept.resources[0]?.approvedHashes).toHaveLength(2);
  });

  it('approves selected items only', () => {
    const initial = createBaseline(site([scriptResource(A, 'v1'), scriptResource(B, 'b1')]), { scanId: 's1' });
    const current = site([scriptResource(A, 'v2'), scriptResource(B, 'b2')]);
    const next = approveSelected(initial, current, [{ kind: 'resource', value: `url:${A}`, sha256: current.resources[0]?.hashes.sha256 ?? null }, { kind: 'outbound-domain', value: 'new.example' }], { scanId: 's2' });
    const a = next.resources.find((r) => r.identity === `url:${A}`);
    const b = next.resources.find((r) => r.identity === `url:${B}`);
    expect(a?.approvedHashes[0]?.sha256).toBe(current.resources[0]?.hashes.sha256);
    expect(b?.approvedHashes[0]?.sha256).toBe(initial.resources[1]?.approvedHashes[0]?.sha256);
    expect(next.domains.outbound).toContain('new.example');
    expect(next.approvals.at(-1)?.items).toEqual([`resource:url:${A}@${current.resources[0]?.hashes.sha256}`, 'outbound-domain:new.example']);
  });

  it('summarises changes for the confirmation prompt', () => {
    const initial = createBaseline(site([scriptResource(A, 'v1')]), { scanId: 's1' });
    const next = approveFullScan(initial, site([scriptResource(A, 'v2'), scriptResource(B, 'b')]), { scanId: 's2' });
    const summary = summarizeBaselineChange(initial, next);
    expect(summary.addedResources).toEqual([`url:${B}`]);
    expect(summary.changedResources).toEqual([`url:${A}`]);
    expect(summary.addedDomains).toEqual(['vendor-b.example']);
  });

  it('round-trips through disk with stable formatting', async () => {
    const paths = storagePaths(await tempDir('baseline-'));
    const b = createBaseline(site([scriptResource(A, 'a()')]), { scanId: 's1' });
    const path = await saveBaseline(paths, b);
    expect(path.replaceAll('\\', '/')).toMatch(/baselines\/shop\/baseline\.json$/);
    expect(await loadBaseline(paths, 'shop')).toEqual(b);
    expect(await loadBaseline(paths, 'other')).toBeUndefined();
  });

  it('rejects tampered or malformed baselines', async () => {
    const b = createBaseline(site([scriptResource(A, 'a()')]), { scanId: 's1' });
    expect(() => validateBaseline({ ...b, site: 'other' }, 'shop', 'x')).toThrow(BaselineError);
    expect(() => validateBaseline({ ...b, resources: [...b.resources, ...b.resources] }, 'shop', 'x')).toThrow(/more than once/);
    const bad = structuredClone(b) as { resources: Array<{ approvedHashes: Array<{ sha256: string }> }> };
    (bad.resources[0] as { approvedHashes: Array<{ sha256: string }> }).approvedHashes[0] = { sha256: 'not-a-hash' };
    expect(() => validateBaseline(bad, 'shop', 'x')).toThrow(BaselineError);
    const paths = storagePaths(await tempDir('baseline-bad-'));
    await mkdir(join(paths.baselines, 'shop'), { recursive: true });
    await writeFile(join(paths.baselines, 'shop', 'baseline.json'), '{"kind":"nope"}');
    await expect(loadBaseline(paths, 'shop')).rejects.toBeInstanceOf(BaselineError);
  });
});
