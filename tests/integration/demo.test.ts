import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createDemoServer, demoConfig } from '../../demo/site/server.mjs';
import { makeProject } from '../helpers.js';
import { main } from '../../src/cli/index.js';
import type { AnalysisReport } from '../../src/types/report.js';

/**
 * The `npm run demo` scenario, end to end. The README and demo/README.md
 * promise that each simulated attack is caught; this test keeps that true.
 */

const shop = createDemoServer();
let dir = '';
let cleanup: () => Promise<void> = () => Promise.resolve();

async function cli(...args: string[]): Promise<number> {
  const spy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  try {
    const code = await main(['node', 'thirdsentry', '--config', join(dir, 'thirdsentry.yml'), ...args]);
    return Number(process.exitCode ?? code);
  } finally {
    spy.mockRestore();
    process.exitCode = undefined;
  }
}

const report = async (): Promise<AnalysisReport> => JSON.parse(await readFile(join(dir, '.thirdsentry', 'reports', 'report.json'), 'utf8')) as AnalysisReport;

beforeAll(async () => {
  const port = await shop.start();
  const config = demoConfig(port);
  const project = await makeProject(port, {
    ...config,
    security: { ...config.security, isolation: { mode: 'none' } },
  });
  dir = project.dir;
  cleanup = project.cleanup;
}, 60_000);

afterAll(async () => {
  await cleanup();
  await shop.stop();
});

describe('demo: Magecart-style attack on the Acme Outfitters shop', () => {
  it('the clean shop produces no findings once baselined', async () => {
    expect(await cli('scan', '--allow-missing-baseline', '--fail-on', 'none')).toBe(0);
    expect(await cli('baseline', '--yes')).toBe(0);
    expect(await cli('scan', '--fail-on', 'low')).toBe(0);
    expect((await report()).findings).toEqual([]);
  }, 180_000);

  it('catches every simulated attack and fails the scan', async () => {
    shop.setState('compromised');
    expect(await cli('scan', '--fail-on', 'high')).toBe(1);
    const { findings } = await report();
    const find = (kind: string, match = ''): AnalysisReport['findings'][number] | undefined =>
      findings.find((f) => f.kind === kind && `${f.resourceUrl ?? ''} ${f.title} ${f.reason}`.includes(match));

    // 1. skimmer appended to the payment vendor's script
    const pay = find('resource-modified', '/v3/pay.js');
    expect(pay?.severity).toBe('critical');
    expect(pay?.signals.map((s) => s.id)).toEqual(expect.arrayContaining(['new-rule:TS-SENSITIVE-FIELD-ACCESS', 'new-rule:TS-EXFIL-COMBINATION']));
    // 2. obfuscated loader from a lookalike domain
    const loader = find('resource-added', 'cdn-assets-cloud.test');
    expect(['high', 'critical']).toContain(loader?.severity);
    expect(loader?.signals.map((s) => s.id)).toEqual(expect.arrayContaining(['new-rule:TS-EVAL', 'new-rule:TS-OBFUSCATION']));
    expect(find('new-script-domain', 'cdn-assets-cloud.test')).toBeDefined();
    // 3. exfiltration destination
    expect(find('new-outbound-domain', 'exfil.test')).toBeDefined();
    // 4. tampered payment form
    expect(find('payment-form-changed')?.severity).toBe('critical');
    // 5. CSP and X-Frame-Options removed
    expect(find('security-header-changed', 'content-security-policy')?.severity).toBe('critical');

    // The analytics tag and first-party code did not change and must not be flagged.
    expect(findings.some((f) => f.resourceUrl?.includes('tags.analytics.test'))).toBe(false);
    expect(findings.some((f) => f.resourceUrl?.includes('/assets/app.js'))).toBe(false);
  }, 180_000);

  it('catches an Optimizely-style hijack of the A/B-testing snippet (same URL, new project JavaScript)', async () => {
    shop.setState('snippet-hijack');
    expect(await cli('scan', '--fail-on', 'high')).toBe(1);
    const { findings } = await report();
    const signals = (f: AnalysisReport['findings'][number] | undefined): string[] => f?.signals.map((s) => s.id) ?? [];

    // The vendor snippet keeps its URL but its content changed and gained loader behaviour.
    const snippet = findings.find((f) => f.kind === 'resource-modified' && f.resourceUrl?.includes('cdn.experiments.test:'));
    expect(['high', 'critical']).toContain(snippet?.severity);
    expect(signals(snippet)).toEqual(expect.arrayContaining(['new-rule:TS-EVAL', 'new-rule:TS-SCRIPT-INJECTION']));

    // The payload it injects: wallet swapping (clipboard, fetch/XHR hooks) plus card skimming.
    const payload = findings.find((f) => f.kind === 'resource-added' && f.resourceUrl?.includes('c2.attacker.test') && f.severity === 'critical');
    expect(signals(payload)).toEqual(
      expect.arrayContaining(['new-rule:TS-CLIPBOARD', 'new-rule:TS-NETWORK-API-HOOK', 'new-rule:TS-SENSITIVE-FIELD-ACCESS', 'new-rule:TS-EXFIL-COMBINATION']),
    );
    expect(findings.some((f) => f.kind === 'new-script-domain' && `${f.title} ${f.reason}`.includes('attacker.test'))).toBe(true);
    expect(findings.some((f) => f.kind === 'new-outbound-domain' && `${f.title} ${f.reason}`.includes('attacker.test'))).toBe(true);

    // Nothing else about the shop changed in this scenario.
    expect(findings.filter((f) => ['payment-form-changed', 'security-header-changed'].includes(f.kind))).toEqual([]);
    expect(findings.some((f) => f.resourceUrl?.includes('cdn.payvendor.test'))).toBe(false);
  }, 180_000);
});
