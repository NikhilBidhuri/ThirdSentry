import { existsSync } from 'node:fs';
import { runIsolatedCollection } from '../../src/security/worker-sandbox.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FixtureServer } from '../fixtures/server.js';
import { makeProject } from '../helpers.js';
import { collectEvidence } from '../../src/browser/collector.js';
import { selectSites } from '../../src/config/loader.js';
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse, stringify } from 'yaml';
import { loadConfig } from '../../src/config/loader.js';
import { newScanId } from '../../src/browser/collector.js';

const server = new FixtureServer();
beforeAll(async () => {
  await server.start();
});
afterAll(async () => {
  await server.stop();
});

async function collect(pagePath: string, limits: Record<string, unknown>) {
  const project = await makeProject(server.port);
  try {
    const cfgPath = join(project.dir, 'thirdsentry.yml');
    const cfg = parse(await readFile(cfgPath, 'utf8')) as { sites: Array<Record<string, unknown>>; limits?: Record<string, unknown> };
    (cfg.sites[0] as Record<string, unknown>).pages = [pagePath];
    cfg.limits = limits;
    await writeFile(cfgPath, stringify(cfg));
    const resolved = await loadConfig({ cwd: project.dir });
    const sites = selectSites(resolved);
    return await collectEvidence({
      scanId: newScanId(),
      sites,
      limits: resolved.config.limits,
      network: resolved.config.security.network,
      serviceWorkers: { strategy: 'block', probeBlockedRegistrations: false },
      chromiumSandbox: resolved.config.security.isolation.chromiumSandbox ?? true,
      isolation: 'none',
    } as never);
  } finally {
    await project.cleanup();
  }
}

describe('hostile pages cannot exhaust the evidence budget', () => {
  it('records over-budget bodies as budget-exceeded and marks the page partial', async () => {
    const big = `/*${'x'.repeat(700_000)}*/`;
    for (let i = 0; i < 6; i++) server.js('cdn.vendor-a.test', `/big${i}.js`, big);
    server.html('shop.test', '/budget', `<html><body>${[0, 1, 2, 3, 4, 5].map((i) => `<script src="http://cdn.vendor-a.test:${server.port}/big${i}.js"></script>`).join('')}</body></html>`);
    const evidence = await collect('/budget', { maxEvidenceBytesPerPage: 1024 * 1024 });
    const page = evidence.sites[0]?.pages[0];
    const statuses = page?.scriptResponses.map((r) => r.bodyStatus) ?? [];
    expect(statuses.filter((s) => s === 'captured').length).toBeLessThan(6);
    expect(statuses).toContain('budget-exceeded');
    expect(page?.status).toBe('partial');
    expect(page?.issues.some((i) => i.code === 'evidence-budget')).toBe(true);
    // network facts survive
    expect(page?.scriptResponses.length).toBe(6);
  }, 90_000);

  it('bounds calls to the in-page reporting binding and reports the drop', async () => {
    server.html(
      'shop.test',
      '/spam',
      `<html><body><script>
        for (let i = 0; i < 400; i++) { const s = document.createElement('script'); s.textContent = 'var a' + i + '=1;'; document.body.appendChild(s); }
      </script></body></html>`,
    );
    const evidence = await collect('/spam', { maxReportCallsPerPage: 100, maxScriptsPerPage: 100 });
    const page = evidence.sites[0]?.pages[0];
    expect(page?.status).toBe('partial');
    expect(page?.issues.some((i) => ['report-budget', 'instrumentation-report-limit', 'script-limit'].includes(i.code))).toBe(true);
  }, 90_000);

  it('marks the page partial when frames cannot all be inspected', async () => {
    server.html('shop.test', '/frames', `<html><body>${'<iframe></iframe>'.repeat(1100)}</body></html>`);
    const evidence = await collect('/frames', {});
    const page = evidence.sites[0]?.pages[0];
    expect(page?.status).not.toBe('complete');
    expect(page?.issues.some((i) => i.code === 'frames-not-inspected')).toBe(true);
  }, 120_000);

  it('counts blob reports dropped by the per-page entry limit', async () => {
    server.html(
      'shop.test',
      '/blobs',
      `<html><body><script>
        for (let i = 0; i < 1200; i++) URL.createObjectURL(new Blob(['var b' + i + '=1;'], { type: 'text/javascript' }));
      </script></body></html>`,
    );
    const evidence = await collect('/blobs', { maxScriptsPerPage: 1000 });
    const page = evidence.sites[0]?.pages[0];
    expect(page?.status).toBe('partial');
    expect(page?.issues.some((i) => ['blob-limit', 'instrumentation-report-limit', 'report-budget', 'script-limit'].includes(i.code))).toBe(true);
  }, 90_000);
});

describe.skipIf(!existsSync(join(process.cwd(), 'dist', 'browser', 'worker-entry.js')))('process-mode worker', () => {
  async function request(pages: string[]) {
    const project = await makeProject(server.port);
    const cfgPath = join(project.dir, 'thirdsentry.yml');
    const cfg = parse(await readFile(cfgPath, 'utf8')) as { sites: Array<Record<string, unknown>> };
    (cfg.sites[0] as Record<string, unknown>).pages = pages;
    await writeFile(cfgPath, stringify(cfg));
    const resolved = await loadConfig({ cwd: project.dir });
    return {
      project,
      req: {
        scanId: newScanId(),
        sites: selectSites(resolved),
        limits: resolved.config.limits,
        network: resolved.config.security.network,
        serviceWorkers: { strategy: 'block', probeBlockedRegistrations: false },
        chromiumSandbox: resolved.config.security.isolation.chromiumSandbox ?? true,
        isolation: 'process',
      } as never,
    };
  }

  it('assembles incremental evidence from a finished worker', async () => {
    server.html('shop.test', '/ok', '<html><body>ok</body></html>');
    const { project, req } = await request(['/ok']);
    try {
      const evidence = await runIsolatedCollection(req, { maxEvidenceBytes: 512 * 1024 * 1024, timeoutMs: 120_000 });
      expect(evidence.sites[0]?.pages[0]?.status).toBe('complete');
    } finally {
      await project.cleanup();
    }
  }, 150_000);

  it('keeps completed pages when the worker is killed on timeout', async () => {
    server.html('shop.test', '/fast', '<html><body>fast</body></html>');
    server.set('shop.test', '/hang', { delayMs: 60_000, headers: { 'content-type': 'text/html' }, body: 'late' });
    const { project, req } = await request(['/fast', '/hang']);
    try {
      const evidence = await runIsolatedCollection(req, { maxEvidenceBytes: 512 * 1024 * 1024, timeoutMs: 9_000, killGraceMs: 500 });
      const pages = evidence.sites[0]?.pages ?? [];
      expect(pages[0]?.pageKey).toBe('/fast');
      expect(pages[0]?.status).toBe('complete');
      expect(pages[1]?.status).toBe('failed');
      expect(evidence.issues.some((i) => i.code === 'worker-incomplete')).toBe(true);
    } finally {
      await project.cleanup();
    }
  }, 150_000);
});
