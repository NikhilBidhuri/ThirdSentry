import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { FixtureServer } from '../fixtures/server.js';
import { installStoreSite } from '../fixtures/store-site.js';
import { SKIMMER } from '../fixtures/scripts.js';
import { makeProject } from '../helpers.js';
import { main } from '../../src/cli/index.js';
import type { AnalysisReport } from '../../src/types/report.js';
import type { ScanResult } from '../../src/types/index.js';

const server = new FixtureServer();
let dir = '';
let cleanup: () => Promise<void> = () => Promise.resolve();

async function cli(...args: string[]): Promise<number> {
  const spy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  try {
    return await main(['node', 'thirdsentry', '--config', join(dir, 'thirdsentry.yml'), ...args]);
  } finally {
    spy.mockRestore();
    process.exitCode = undefined;
  }
}

const readJson = async <T>(...parts: string[]): Promise<T> => JSON.parse(await readFile(join(dir, '.thirdsentry', ...parts), 'utf8')) as T;

beforeAll(async () => {
  await server.start();
  installStoreSite(server);
  const project = await makeProject(server.port, {
    sites: [{ name: 'shop', url: `http://shop.test:${server.port}/`, pages: ['/checkout'], sensitivePages: ['/checkout'] }],
    failOn: 'none',
  });
  dir = project.dir;
  cleanup = project.cleanup;
}, 60_000);

afterAll(async () => {
  await cleanup();
  await server.stop();
});

describe('security analysis end to end', () => {
  it('records behaviour indicators for scanned scripts', async () => {
    expect(await cli('scan')).toBe(0);
    const scan = await readJson<ScanResult>('reports', 'latest-scan.json');
    const lib = scan.sites[0]?.resources.find((r) => r.finalUrl?.endsWith('/lib.js'));
    expect(lib?.indicators?.analyzed).toBe(true);
    expect(await cli('baseline', '--yes')).toBe(0);
  }, 120_000);

  it('rates a vendor update that adds skimming code on the checkout page as high priority', async () => {
    server.js('cdn.vendor-a.test', '/pay.js', `window.Pay = { mount: function () {} };\n${SKIMMER.replace('cdn-metrics.exfil.example', 'exfil.vendor-e.test:{port}')}`);
    expect(await cli('scan', '--fail-on', 'high')).toBe(1);
    const report = await readJson<AnalysisReport>('reports', 'report.json');
    const pay = report.findings.find((f) => f.kind === 'resource-modified' && f.resourceUrl?.endsWith('/pay.js'));
    expect(pay).toBeDefined();
    expect(['high', 'critical']).toContain(pay?.severity);
    expect(pay?.status).toBe('new');
    const ids = pay?.signals.map((s) => s.id) ?? [];
    expect(ids).toEqual(expect.arrayContaining(['hash-changed-third-party', 'sensitive-page', 'new-rule:TS-SENSITIVE-FIELD-ACCESS', 'new-rule:TS-EXFIL-COMBINATION']));
    expect(pay?.reason).not.toMatch(/malware/i);
  }, 120_000);

  it('reports the same unchanged finding as recurring on the next scan', async () => {
    await cli('scan');
    const report = await readJson<AnalysisReport>('reports', 'report.json');
    const pay = report.findings.find((f) => f.kind === 'resource-modified' && f.resourceUrl?.endsWith('/pay.js'));
    expect(pay?.status).toBe('recurring');
  }, 120_000);
});
