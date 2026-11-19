import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { FixtureServer } from '../fixtures/server.js';
import { installStoreSite } from '../fixtures/store-site.js';
import { makeProject } from '../helpers.js';
import { runScan } from '../../src/monitoring/scan-manager.js';
import { selectSites } from '../../src/config/loader.js';
import type { ScanResult, ScriptResource } from '../../src/types/index.js';

const server = new FixtureServer();

beforeAll(async () => {
  await server.start();
  installStoreSite(server);
});
afterAll(async () => {
  await server.stop();
});

function find(result: ScanResult, predicate: (r: ScriptResource) => boolean): ScriptResource | undefined {
  return result.sites[0]?.resources.find(predicate);
}

describe('browser scanner (local fixture site)', () => {
  let result: ScanResult;

  beforeAll(async () => {
    const project = await makeProject(server.port);
    const run = await runScan(project.resolved, { sites: selectSites(project.resolved) });
    result = run.result;
    await project.cleanup();
  }, 120_000);

  it('completes the scan of the home page', () => {
    expect(result.status).toBe('complete');
    expect(result.sites[0]?.pages[0]?.status).toBe('complete');
  });

  it('discovers the parser-inserted third-party library with hashes', () => {
    const lib = find(result, (r) => r.finalUrl?.endsWith('cdn.vendor-a.test:' + String(server.port) + '/lib.js') === true);
    expect(lib).toBeDefined();
    expect(lib?.type).toBe('script');
    expect(lib?.party).toBe('third-party');
    expect(lib?.dynamic).toBe(false);
    expect(lib?.hashes.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(lib?.hashes.normalizedSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(lib?.hashes.sri).toMatch(/^sha256-/);
    expect(lib?.registrableDomain).toBe('vendor-a.test');
  });

  it('marks runtime-injected scripts as dynamic', () => {
    const tag = find(result, (r) => r.finalUrl?.includes('analytics.vendor-b.test') === true);
    expect(tag).toBeDefined();
    expect(tag?.dynamic).toBe(true);
    expect(tag?.party).toBe('third-party');
  });

  it('captures inline scripts', () => {
    const inline = result.sites[0]?.resources.filter((r) => r.type === 'inline-script') ?? [];
    expect(inline.length).toBeGreaterThanOrEqual(2);
    expect(inline.every((r) => r.hashes.sha256 !== null)).toBe(true);
    expect(inline.every((r) => r.party === 'first-party')).toBe(true);
  });

  it('classifies ES modules and dynamic import()', () => {
    const app = find(result, (r) => r.finalUrl?.endsWith('/app.mjs') === true);
    const lazy = find(result, (r) => r.finalUrl?.endsWith('/lazy.mjs') === true);
    expect(app?.type).toBe('module');
    expect(lazy?.type).toBe('module');
    expect(lazy?.party).toBe('first-party');
  });

  it('discovers dedicated workers, wasm and blob scripts', () => {
    expect(find(result, (r) => r.finalUrl?.endsWith('/worker.js') === true)?.type).toBe('dedicated-worker');
    expect(find(result, (r) => r.finalUrl?.endsWith('/module.wasm') === true)?.type).toBe('wasm');
    const blob = find(result, (r) => r.type === 'blob-script');
    expect(blob).toBeDefined();
    expect(blob?.hashes.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('discovers scripts inside third-party iframes', () => {
    const frameScript = find(result, (r) => r.finalUrl?.endsWith('/frame.js') === true);
    expect(frameScript?.frameContext).toBe('iframe');
    expect(result.sites[0]?.domains.iframes).toContain(`http://frame.vendor-d.test:${server.port}`);
  });

  it('records outbound destinations including the beacon endpoint', () => {
    const outbound = result.sites[0]?.domains.outbound ?? [];
    expect(outbound).toContain('vendor-c.test');
    const beacon = result.sites[0]?.pages[0]?.requests.find((r) => r.hostname === 'collect.vendor-c.test');
    expect(beacon?.method).toBe('POST');
  });

  it('blocks connections to hosts that resolve to private addresses and records them', () => {
    const blocked = result.sites[0]?.blockedConnections ?? [];
    expect(blocked.some((e) => e.host === 'internal.test' && e.code === 'ip-blocked')).toBe(true);
    expect(server.hits.some((h) => h.startsWith('internal.test'))).toBe(false);
  });
});
