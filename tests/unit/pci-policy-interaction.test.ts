import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { createBaseline, saveBaseline } from '../../src/baseline/baseline-manager.js';
import { main } from '../../src/cli/index.js';
import { analyzeScan } from '../../src/monitoring/analysis-runner.js';
import { applyPoliciesToSite } from '../../src/policies/apply.js';
import { saveScanResult } from '../../src/storage/filesystem-store.js';
import { page, scan, scriptResource, site } from '../fixtures/builders.js';
import { makeProject } from '../helpers.js';

/**
 * A vendor bundle that is renamed on every build (main.<hash>.js) and governed by a
 * path-versions script policy must be ONE inventory row with a stable identity. Before,
 * the PCI inventory looked at raw URLs, so every rename raised a new "script-unjustified"
 * finding (with a new ID, so it was alerted again). Found by the Docker end-to-end test.
 */
describe('PCI inventory and script policies', () => {
  it('keeps the script-unjustified finding stable when a policy-governed bundle is renamed', async () => {
    const project = await makeProject(80, {
      scriptPolicies: [{ name: 'vendor-sdk', match: { urlPrefix: 'https://cdn.vendor.example/sdk/' }, mode: 'path-versions', reason: 'hash-named bundles' }],
      pci: { requireJustification: true },
    });
    try {
      const checkout = page('/checkout', { sensitive: true });
      const scanWith = (file: string) =>
        scan([site([scriptResource(`https://cdn.vendor.example/sdk/${file}`, 'window.Sdk={}', { pages: ['/checkout'] })], { pages: [checkout] })]);
      const idsOf = async (file: string) =>
        (await analyzeScan(project.resolved, scanWith(file), { scanPath: 'x' })).report.findings.filter((f) => f.kind === 'script-unjustified').map((f) => f.id);

      const first = await idsOf('main.aaaa1111.js');
      const second = await idsOf('main.bbbb2222.js');
      expect(first).toHaveLength(1);
      expect(second).toEqual(first);
    } finally {
      await project.cleanup();
    }
  });

  it('the inventory command shows a renamed, policy-approved bundle as approved', async () => {
    const project = await makeProject(80, {
      scriptPolicies: [{ name: 'vendor-sdk', match: { urlPrefix: 'https://cdn.vendor.example/sdk/' }, mode: 'path-versions', reason: 'hash-named bundles' }],
    });
    try {
      const checkout = page('/checkout', { sensitive: true });
      const siteWith = (file: string) => site([scriptResource(`https://cdn.vendor.example/sdk/${file}`, 'window.Sdk={}', { pages: ['/checkout'] })], { pages: [checkout] });
      // Approve the first build (under the policy identity), then scan a renamed build.
      await saveBaseline(project.resolved.paths, createBaseline(applyPoliciesToSite(siteWith('main.aaaa1111.js'), project.resolved.config, new Date()), { scanId: 'base' }));
      await saveScanResult(project.resolved.paths, scan([siteWith('main.bbbb2222.js')], '20260102T000000Z-test0002'), { updateLatest: true });

      const chunks: string[] = [];
      const spy = vi.spyOn(process.stdout, 'write').mockImplementation((c: string | Uint8Array) => {
        chunks.push(typeof c === 'string' ? c : Buffer.from(c).toString());
        return true;
      });
      try {
        await main(['node', 'thirdsentry', '--config', join(project.dir, 'thirdsentry.yml'), 'inventory', '--format', 'json']);
      } finally {
        spy.mockRestore();
        process.exitCode = undefined;
      }
      const rows = (JSON.parse(chunks.join('')) as { rows: Array<{ identity: string; approval: string }> }).rows;
      expect(rows).toHaveLength(1);
      expect(rows[0]?.identity).toBe('policy:vendor-sdk');
      expect(rows[0]?.approval).toBe('approved');
    } finally {
      await project.cleanup();
    }
  });

  it('still reports a script that no policy covers by its own identity', async () => {
    const project = await makeProject(80, { pci: { requireJustification: true } });
    try {
      const s = scan([site([scriptResource('https://cdn.other.example/x.js', 'x()', { pages: ['/checkout'] })], { pages: [page('/checkout', { sensitive: true })] })]);
      const f = (await analyzeScan(project.resolved, s, { scanPath: 'x' })).report.findings.find((x) => x.kind === 'script-unjustified');
      expect(f?.resourceIdentity).toBe('url:https://cdn.other.example/x.js');
    } finally {
      await project.cleanup();
    }
  });
});
