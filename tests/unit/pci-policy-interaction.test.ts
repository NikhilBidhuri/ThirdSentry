import { describe, expect, it } from 'vitest';
import { analyzeScan } from '../../src/monitoring/analysis-runner.js';
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
