import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { FixtureServer } from '../fixtures/server.js';
import { ANALYTICS_TAG_V1, installStoreSite } from '../fixtures/store-site.js';
import { makeProject } from '../helpers.js';
import { main } from '../../src/cli/index.js';
import type { AnalysisReport } from '../../src/types/report.js';

/**
 * End-to-end drift detection through the CLI:
 * scan -> baseline -> vendor changes -> scan detects them -> selective approval.
 */

const server = new FixtureServer();
let dir = '';
let cleanup: () => Promise<void> = () => Promise.resolve();

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
  installStoreSite(server);
  // Remove the blocked internal script from the home page so the baseline is clean.
  const project = await makeProject(server.port, {
    sites: [{ name: 'shop', url: `http://shop.test:${server.port}/`, pages: ['/', '/checkout'], sensitivePages: ['/checkout'] }],
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

describe('drift detection end to end', () => {
  it('first scan without a baseline reports no findings and asks for a baseline', async () => {
    const r = await cli('scan');
    expect(r.code).toBe(0);
    const rep = await report();
    expect(rep.sites[0]?.baseline.exists).toBe(false);
    expect(rep.findings).toEqual([]);
    expect(rep.headline).toMatch(/No approved baseline/);
    for (const f of ['report.json', 'report.sarif', 'report.html']) {
      expect((await readFile(join(dir, '.thirdsentry', 'reports', f), 'utf8')).length).toBeGreaterThan(100);
    }
  }, 120_000);

  it('refuses to write a baseline without confirmation in non-interactive mode', async () => {
    const r = await cli('baseline');
    expect(r.code).toBe(2);
  });

  it('creates the baseline explicitly', async () => {
    const r = await cli('baseline', '--yes', '--reason', 'initial review');
    expect(r.code).toBe(0);
    const baseline = JSON.parse(await readFile(join(dir, '.thirdsentry', 'baselines', 'shop', 'baseline.json'), 'utf8')) as { resources: unknown[]; approvals: Array<{ reason: string }> };
    expect(baseline.resources.length).toBeGreaterThan(5);
    expect(baseline.approvals[0]?.reason).toBe('initial review');
  });

  it('a re-scan of the unchanged site produces no findings and does not touch the baseline', async () => {
    const path = join(dir, '.thirdsentry', 'baselines', 'shop', 'baseline.json');
    const before = await readFile(path, 'utf8');
    const r = await cli('scan', '--fail-on', 'info');
    const rep = await report();
    expect(rep.findings.map((f) => `${f.kind} ${f.resourceUrl ?? f.domain ?? ''}`)).toEqual([]);
    expect(r.code).toBe(0);
    expect(await readFile(path, 'utf8')).toBe(before);
  }, 120_000);

  it('detects a modified vendor script, a modified inline script, a removed resource and a new outbound domain', async () => {
    server.js('cdn.vendor-a.test', '/lib.js', `/* Vendor A widget library v2 */\n(function () {\n  window.VendorA = { version: 2, init: function () { return document.cookie; } };\n})();\n`);
    const home = server.routes.get('shop.test/')?.body as string;
    server.html(
      'shop.test',
      '/',
      home.replace(`currency: 'EUR'`, `currency: 'USD'`).replace(`<script src="http://frame.vendor-d.test:{port}/frame.js"></script>`, ''),
    );
    server.html('frame.vendor-d.test', '/frame.html', '<!doctype html><html><body>no script now</body></html>');
    server.js('analytics.vendor-b.test', '/tag.js', ANALYTICS_TAG_V1.replace('collect.vendor-c.test', 'exfil.vendor-e.test'));
    server.set('exfil.vendor-e.test', '/collect', { status: 204 });

    const r = await cli('scan', '--fail-on', 'medium');
    const rep = await report();
    const kinds = rep.findings.map((f) => f.kind);
    expect(r.code).toBe(1);
    const lib = rep.findings.find((f) => f.kind === 'resource-modified' && f.resourceUrl?.endsWith('/lib.js'));
    expect(lib).toBeDefined();
    expect(lib?.previousHash).not.toBe(lib?.currentHash);
    expect(lib?.pages).toEqual(['/', '/checkout']);
    expect(rep.findings.some((f) => f.kind === 'resource-modified' && f.resourceType === 'inline-script')).toBe(true);
    expect(rep.findings.some((f) => f.kind === 'resource-removed' && f.resourceUrl?.endsWith('/frame.js'))).toBe(true);
    const exfil = rep.findings.find((f) => f.kind === 'new-outbound-domain' && f.domain === 'vendor-e.test');
    expect(exfil).toBeDefined();
    expect(kinds).toContain('resource-modified');
  }, 120_000);

  it('diff shows the code change for the modified script', async () => {
    const r = await cli('--json', 'diff');
    const out = JSON.parse(r.stdout) as { findings: Array<{ id: string; kind: string; resourceUrl?: string }>; codeDiffs: Array<{ findingId: string; available: boolean; patch?: string }> };
    const lib = out.findings.find((f) => f.kind === 'resource-modified' && f.resourceUrl?.endsWith('/lib.js'));
    const d = out.codeDiffs.find((x) => x.findingId === lib?.id);
    expect(d?.available).toBe(true);
    expect(d?.patch).toContain('+');
    expect(d?.patch).toContain('document.cookie');
  });

  it('approves a single finding without approving the others', async () => {
    const before = await report();
    const lib = before.findings.find((f) => f.kind === 'resource-modified' && f.resourceUrl?.endsWith('/lib.js'));
    expect(lib).toBeDefined();
    const r = await cli('baseline', '--approve', lib?.id ?? '', '--yes', '--reason', 'vendor release 2.0');
    expect(r.code).toBe(0);
    const d = await cli('--json', 'diff');
    const out = JSON.parse(d.stdout) as AnalysisReport;
    expect(out.findings.some((f) => f.id === lib?.id)).toBe(false);
    expect(out.findings.some((f) => f.kind === 'new-outbound-domain')).toBe(true);
  });

  it('regenerates reports in a chosen format and directory, and previews alerts', async () => {
    const out = join(dir, 'out');
    const r = await cli('report', '--format', 'sarif,html', '--output', out, '--fail-on', 'info');
    expect(r.code).toBe(1);
    const sarif = JSON.parse(await readFile(join(out, 'report.sarif'), 'utf8')) as { runs: Array<{ results: unknown[] }> };
    expect(sarif.runs[0]?.results.length).toBeGreaterThan(0);
    expect(await readFile(join(out, 'report.html'), 'utf8')).toContain('ThirdSentry report');
    const a = await cli('--json', 'alert', '--dry-run');
    expect(a.code).toBe(0);
    const csp = await cli('--json', 'csp-lint', '--from-scan');
    expect(csp.code).toBe(0);
    const lint = JSON.parse(csp.stdout) as { targets: Array<{ findings: Array<{ id: string }> }> };
    expect(lint.targets.length).toBe(2);
    expect(lint.targets[0]?.findings.map((f) => f.id)).toContain('no-policy');
    const clean = await cli('--json', 'cleanup', '--dry-run');
    expect(clean.code).toBe(0);
  });

  it('rejects unknown finding IDs', async () => {
    const r = await cli('baseline', '--approve', 'TS-doesnotexist', '--yes');
    expect(r.code).toBe(2);
  });
});
