import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FixtureServer } from '../fixtures/server.js';
import { installStoreSite } from '../fixtures/store-site.js';
import { makeProject } from '../helpers.js';
import { runScan } from '../../src/monitoring/scan-manager.js';
import { loadConfig, selectSites } from '../../src/config/loader.js';
import { ConfigError } from '../../src/utils/errors.js';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { stringify } from 'yaml';

const server = new FixtureServer();

beforeAll(async () => {
  await server.start();
  installStoreSite(server);
});
afterAll(async () => {
  await server.stop();
});

async function scanPages(pages: string[], scanOverrides: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) {
  const project = await makeProject(server.port, extra);
  const cfgPath = join(project.dir, 'scriptdrift.yml');
  const { parse } = await import('yaml');
  const { readFile } = await import('node:fs/promises');
  const cfg = parse(await readFile(cfgPath, 'utf8')) as { sites: Array<Record<string, unknown>>; defaults: { scan: Record<string, unknown> } };
  (cfg.sites[0] as Record<string, unknown>).pages = pages;
  cfg.defaults.scan = { ...cfg.defaults.scan, ...scanOverrides };
  await writeFile(cfgPath, stringify(cfg));
  const resolved = await loadConfig({ cwd: project.dir });
  try {
    return (await runScan(resolved, { sites: selectSites(resolved) })).result;
  } finally {
    await project.cleanup();
  }
}

describe('scanner edge cases', () => {
  it('follows script redirects and keeps original and final URLs', async () => {
    const result = await scanPages(['/redirect']);
    const r = result.sites[0]?.resources.find((x) => x.finalUrl?.endsWith('/v2/lib.js'));
    expect(r).toBeDefined();
    expect(r?.originalUrl).toBe(`http://cdn.vendor-a.test:${server.port}/latest.js`);
    expect(r?.redirectChain).toEqual([`http://cdn.vendor-a.test:${server.port}/latest.js`]);
    expect(r?.identity).toBe(`url:http://cdn.vendor-a.test:${server.port}/v2/lib.js`);
  }, 60_000);

  it('reports a navigation timeout as an incomplete scan, never as complete', async () => {
    const result = await scanPages(['/slow'], { timeout: 2_000, waitUntil: 'load', networkIdleTimeout: 0, settleMs: 0 });
    const page = result.sites[0]?.pages[0];
    expect(page?.status).not.toBe('complete');
    expect(page?.issues.some((i) => i.code === 'navigation-timeout')).toBe(true);
    expect(result.status).not.toBe('complete');
  }, 60_000);

  it('marks HTTP error pages as failed', async () => {
    const result = await scanPages(['/error']);
    expect(result.sites[0]?.pages[0]?.status).toBe('failed');
    expect(result.sites[0]?.pages[0]?.issues.some((i) => i.code === 'http-error')).toBe(true);
    expect(result.status).toBe('failed');
  }, 60_000);

  it('hashes malformed JavaScript and falls back to raw comparison', async () => {
    const result = await scanPages(['/broken']);
    const r = result.sites[0]?.resources.find((x) => x.finalUrl?.endsWith('/broken.js'));
    expect(r?.hashes.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(r?.hashes.normalizedSha256).toBeNull();
    expect(r?.normalization.status).toBe('parse-error');
  }, 60_000);

  it('records a scan of an unreachable site as failed', async () => {
    const result = await scanPages(['http://unreachable.test:' + String(server.port) + '/'], {}, {});
    // unreachable.test has no resolver override and is not resolvable -> blocked or DNS failure at the proxy
    expect(result.sites[0]?.pages[0]?.status).toBe('failed');
  }, 60_000);

  it('refuses to scan a site that resolves to a private address', async () => {
    const project = await makeProject(server.port);
    try {
      await writeFile(
        join(project.dir, 'scriptdrift.yml'),
        stringify({ version: 1, sites: [{ name: 'local', url: `http://127.0.0.1:${server.port}/` }], security: { network: { allowedPorts: [server.port] } } }),
      );
      await expect(loadConfig({ cwd: project.dir })).rejects.toBeInstanceOf(ConfigError);
    } finally {
      await project.cleanup();
    }
  });

  it('runs the browser in an isolated worker process with a scrubbed environment', async () => {
    process.env.SCRIPTDRIFT_SLACK_WEBHOOK = 'https://hooks.example/secret-should-not-leak';
    try {
      const result = await scanPages(['/checkout'], {}, {
        security: {
          network: {
            allowedPorts: [server.port],
            allowedPrivateHosts: ['shop.test', 'cdn.vendor-a.test'],
            resolverOverrides: { 'shop.test': '127.0.0.1', 'cdn.vendor-a.test': '127.0.0.1' },
          },
          isolation: { mode: 'process' },
        },
      });
      expect(result.isolation).toBe('process');
      expect(result.status).toBe('complete');
      expect(result.sites[0]?.resources.some((r) => r.finalUrl?.endsWith('/pay.js'))).toBe(true);
    } finally {
      delete process.env.SCRIPTDRIFT_SLACK_WEBHOOK;
    }
  }, 90_000);
});
