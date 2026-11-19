import { existsSync } from 'node:fs';
import { chromium, firefox, webkit, type BrowserType } from 'playwright';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FixtureServer } from '../fixtures/server.js';
import { installStoreSite } from '../fixtures/store-site.js';
import { makeProject } from '../helpers.js';
import { runScan } from '../../src/monitoring/scan-manager.js';
import { selectSites } from '../../src/config/loader.js';

/**
 * Scans the fixture checkout page with every browser profile whose engine is
 * installed and can start on this host (`npx playwright install --with-deps
 * chromium firefox webkit`). Engines that are missing, or that lack host
 * dependencies (e.g. WebKit on some Windows editions), are skipped, not failed.
 */

const server = new FixtureServer();

async function canLaunch(engine: BrowserType): Promise<boolean> {
  if (!existsSync(engine.executablePath())) return false;
  try {
    const browser = await engine.launch({ headless: true, timeout: 30_000 });
    await browser.close();
    return true;
  } catch {
    return false;
  }
}

const installed = {
  chromium: await canLaunch(chromium),
  firefox: await canLaunch(firefox),
  webkit: await canLaunch(webkit),
};

beforeAll(async () => {
  await server.start();
  installStoreSite(server);
});
afterAll(async () => {
  await server.stop();
});

describe.each([
  ['desktop-firefox', installed.firefox],
  ['desktop-webkit', installed.webkit],
  ['mobile-webkit', installed.webkit],
  ['mobile-chromium', installed.chromium],
] as const)('profile %s', (profile, available) => {
  it.skipIf(!available)('scans pages through the egress proxy and captures scripts', async () => {
    const project = await makeProject(server.port, {
      sites: [{ name: 'shop', url: `http://shop.test:${server.port}/`, pages: ['/checkout'], browser: { profile } }],
    });
    try {
      const run = await runScan(project.resolved, { sites: selectSites(project.resolved) });
      const site = run.result.sites[0];
      expect(site?.status).toBe('complete');
      expect(site?.browser.emulation.length).toBeGreaterThan(20);
      const lib = site?.resources.find((r) => r.finalUrl?.endsWith('/lib.js'));
      expect(lib?.hashes.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(lib?.party).toBe('third-party');
    } finally {
      await project.cleanup();
    }
  }, 120_000);
});
