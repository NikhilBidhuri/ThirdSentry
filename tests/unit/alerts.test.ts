import { createHmac } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { stringify } from 'yaml';
import { sendAlerts } from '../../src/alerts/alert-manager.js';
import { buildAlertPayload, selectFindingsForAlert } from '../../src/alerts/alert-payload.js';
import { redactSecrets, resolveEnv } from '../../src/alerts/env.js';
import { signPayload } from '../../src/alerts/webhook.js';
import { slackMessage } from '../../src/alerts/slack.js';
import { createBaseline } from '../../src/baseline/baseline-manager.js';
import { loadConfig, type ResolvedConfig } from '../../src/config/loader.js';
import { compareSite } from '../../src/monitoring/comparison-engine.js';
import { buildFindings } from '../../src/monitoring/finding-engine.js';
import { loadFindingState, type FindingState } from '../../src/monitoring/dedup-state.js';
import type { AnalysisReport } from '../../src/types/report.js';
import type { Finding } from '../../src/types/findings.js';
import { page, scriptResource, site, destination } from '../fixtures/builders.js';
import { MockHttp, MockSmtp } from '../fixtures/mock-servers.js';
import { tempDir } from '../helpers.js';
import { analyzeResources } from '../../src/analysis/script-analysis.js';
import { SKIMMER } from '../fixtures/scripts.js';

const http = new MockHttp();
const smtp = new MockSmtp();

beforeAll(async () => {
  await http.start();
  await smtp.start();
});
afterAll(async () => {
  await http.stop();
  await smtp.stop();
});
beforeEach(() => {
  http.requests.length = 0;
  smtp.messages.length = 0;
  http.responder = () => ({ status: 200, body: '[]' });
});

function findings(): Finding[] {
  const before = scriptResource('https://cdn.vendor.example/pay.js', 'pay()', { pages: ['/checkout'] });
  const afterSrc = `pay();${SKIMMER}`;
  const after = scriptResource('https://cdn.vendor.example/pay.js', afterSrc, { pages: ['/checkout'] });
  analyzeResources([before, after], new Map([[before.hashes.sha256 as string, Buffer.from('pay()')], [after.hashes.sha256 as string, Buffer.from(afterSrc)]]), { rules: {}, analysis: { enabled: true, maxScriptBytes: 1e7 } });
  const pages = [page('/checkout', { sensitive: true })];
  const base = createBaseline(site([before], { pages }), { scanId: 's1' });
  const s = site([after], { pages, destinations: [destination('cdn.vendor.example', { pages: ['/checkout'] }), destination('drop.evil.example', { pages: ['/checkout'], methods: ['POST'] })] });
  return buildFindings(compareSite(s, base).changes, { site: s });
}

function report(fs: Finding[]): AnalysisReport {
  return {
    schemaVersion: 1,
    kind: 'thirdsentry-report',
    generatedAt: '2026-01-01T00:00:00.000Z',
    toolVersion: '0.1.0',
    scanId: 'scan-1',
    scanPath: 'x',
    scanStatus: 'complete',
    scanStartedAt: '2026-01-01T00:00:00.000Z',
    scanFinishedAt: '2026-01-01T00:01:00.000Z',
    scanSummary: { sites: 1, pages: 1, pagesComplete: 1, pagesPartial: 0, pagesFailed: 0, resources: 1, firstPartyResources: 0, thirdPartyResources: 1, resourcesWithoutContent: 0, thirdPartyDomains: 1, blockedConnections: 0 },
    scanIssues: [],
    sites: [],
    findings: fs,
    findingCounts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
    highestSeverity: 'high',
    coverageLimitations: [],
    headline: 'Changes need attention',
  };
}

async function project(alerts: Record<string, unknown>): Promise<ResolvedConfig> {
  const dir = await tempDir('alerts-');
  await writeFile(join(dir, 'thirdsentry.yml'), stringify({ version: 1, sites: [{ name: 'shop', url: 'https://shop.example/' }], alerts: { retries: 1, timeoutMs: 3000, ...alerts } }));
  return loadConfig({ cwd: dir });
}

describe('alert payload', () => {
  it('never includes code excerpts and keeps hashes and explanations', () => {
    const fs = findings();
    const payload = buildAlertPayload(report(fs), fs, { maxFindings: 10, reportLocation: 'r.html' });
    const text = JSON.stringify(payload);
    expect(text).not.toContain('querySelectorAll');
    expect(text).not.toContain('btoa(JSON.stringify');
    const modified = payload.findings.find((f) => f.title.includes('changed'));
    expect(modified?.previousHash).toMatch(/^[0-9a-f]{64}$/);
    expect(modified?.why).toMatch(/score \d+/);
    expect(modified?.evidence.find((e) => e.label === 'Behaviour matches')?.value).toContain('TS-SENSITIVE-FIELD-ACCESS');
  });

  it('selects only unsuppressed findings above the threshold that were not alerted yet (per channel)', () => {
    const fs = findings();
    const now = new Date('2026-01-01T12:00:00Z');
    const cfg = { minSeverity: 'info' as const, repeatAfterHours: 0 };
    const state: FindingState = { version: 2, findings: {} };
    const all = selectFindingsForAlert(report(fs), state, cfg, now, 'slack');
    expect(all.length).toBe(fs.length);
    const first = fs[0] as Finding;
    state.findings[first.id] = { firstSeen: 'x', lastSeen: 'x', timesSeen: 1, severity: first.severity, alerts: { slack: { at: '2026-01-01T00:00:00Z', severity: first.severity } } };
    expect(selectFindingsForAlert(report(fs), state, cfg, now, 'slack').map((f) => f.id)).not.toContain(first.id);
    // Delivered through Slack only: the webhook still gets it.
    expect(selectFindingsForAlert(report(fs), state, cfg, now, 'webhook').map((f) => f.id)).toContain(first.id);
    expect(selectFindingsForAlert(report(fs), state, { minSeverity: 'info', repeatAfterHours: 1 }, new Date('2026-01-02'), 'slack').map((f) => f.id)).toContain(first.id);
    state.findings[first.id] = { firstSeen: 'x', lastSeen: 'x', timesSeen: 1, severity: first.severity, alerts: { slack: { at: '2026-01-01T00:00:00Z', severity: 'info' } } };
    expect(selectFindingsForAlert(report(fs), state, cfg, now, 'slack').map((f) => f.id)).toContain(first.id);
    const suppressed = fs.map((f) => ({ ...f, suppressed: { reason: 'x' } }));
    expect(selectFindingsForAlert(report(suppressed), { version: 2, findings: {} }, cfg, now, 'slack')).toEqual([]);
  });

  it('builds Slack Block Kit messages within Slack limits and escapes markup', () => {
    const fs = findings().map((f) => ({ ...f, title: `<!channel> ${f.title}`, reason: 'x'.repeat(5000) }));
    const msg = slackMessage(buildAlertPayload(report(fs), fs, { maxFindings: 50, reportLocation: 'r' })).body;
    expect(msg.blocks.length).toBeLessThanOrEqual(50);
    for (const b of msg.blocks) expect(((b as { text?: { text: string } }).text?.text ?? '').length).toBeLessThanOrEqual(3000);
    expect(JSON.stringify(msg)).not.toContain('<!channel>');
  });
});

describe('environment interpolation', () => {
  it('resolves variables and reports missing ones without revealing values', () => {
    expect(resolveEnv('https://hooks/${A}/${B}', { A: '1', B: '2' }, 'x')).toBe('https://hooks/1/2');
    expect(() => resolveEnv('${MISSING_X}', {}, 'alerts.slack.webhookUrl')).toThrow(/MISSING_X/);
    expect(redactSecrets('failed for https://hooks.slack.com/T000/SECRET123', ['https://hooks.slack.com/T000/SECRET123'])).toBe('failed for [REDACTED]');
  });
});

describe('alert channels against local mock servers', () => {
  it('delivers a signed generic webhook', async () => {
    const resolved = await project({ minSeverity: 'info', webhook: { enabled: true, url: '${HOOK_URL}', secret: '${HOOK_SECRET}', allowInsecureHttp: true } });
    const result = await sendAlerts(resolved, report(findings()), { env: { HOOK_URL: http.url('/hook'), HOOK_SECRET: 'topsecret' }, retryDelayMs: 1 });
    expect(result.results).toEqual([expect.objectContaining({ channel: 'webhook', ok: true })]);
    const req = http.requests[0];
    const ts = Number(req?.headers['x-thirdsentry-timestamp']);
    const expected = `sha256=${createHmac('sha256', 'topsecret').update(`${ts}.${req?.body ?? ''}`).digest('hex')}`;
    expect(req?.headers['x-thirdsentry-signature']).toBe(expected);
    expect(signPayload(req?.body ?? '', 'topsecret', ts)).toBe(expected);
    expect(JSON.parse(req?.body ?? '{}')).toMatchObject({ kind: 'thirdsentry-alert', scanId: 'scan-1' });
  });

  it('does not alert twice for the same finding', async () => {
    const resolved = await project({ minSeverity: 'info', webhook: { enabled: true, url: '${HOOK_URL}', allowInsecureHttp: true } });
    const env = { HOOK_URL: http.url('/hook') };
    await sendAlerts(resolved, report(findings()), { env, retryDelayMs: 1 });
    const second = await sendAlerts(resolved, report(findings()), { env, retryDelayMs: 1 });
    expect(second.selected).toBe(0);
    expect(http.requests).toHaveLength(1);
    const state = await loadFindingState(resolved.paths);
    expect(Object.values(state.findings).every((e) => e.alerts?.webhook && !e.alerts.slack)).toBe(true);
  });

  it('retries transient failures and reports permanent ones without throwing or leaking secrets', async () => {
    let calls = 0;
    http.responder = () => (++calls === 1 ? { status: 503 } : { status: 200 });
    const resolved = await project({ minSeverity: 'info', webhook: { enabled: true, url: '${HOOK_URL}', allowInsecureHttp: true } });
    const ok = await sendAlerts(resolved, report(findings()), { env: { HOOK_URL: http.url('/retry') }, retryDelayMs: 1 });
    expect(ok.results[0]).toMatchObject({ ok: true, attempts: 2 });

    const resolved2 = await project({ minSeverity: 'info', slack: { enabled: true, webhookUrl: '${SLACK_URL}' } });
    const failed = await sendAlerts(resolved2, report(findings()), { env: { SLACK_URL: 'http://127.0.0.1:1/services/T0/B0/SECRETTOKEN' }, retryDelayMs: 1 });
    expect(failed.results[0]?.ok).toBe(false);
    expect(failed.results[0]?.error).toMatch(/https/);
    expect(failed.results[0]?.error ?? '').not.toContain('SECRETTOKEN');
  });

  it('reports a missing environment variable as a channel failure', async () => {
    const resolved = await project({ minSeverity: 'info', slack: { enabled: true } });
    const result = await sendAlerts(resolved, report(findings()), { env: {}, retryDelayMs: 1 });
    // A configuration error cannot succeed on a retry.
    expect(result.results[0]).toMatchObject({ channel: 'slack', ok: false, attempts: 1 });
    expect(result.results[0]?.error).toMatch(/THIRDSENTRY_SLACK_WEBHOOK/);
  });

  it('creates GitHub issues once per finding', async () => {
    const created: string[] = [];
    http.responder = (req) => {
      if (req.method === 'GET') return { status: 200, body: JSON.stringify(created.map((b) => ({ body: b }))) };
      created.push((JSON.parse(req.body) as { body: string }).body);
      return { status: 201, body: '{}' };
    };
    const resolved = await project({ minSeverity: 'info', github: { enabled: true, apiUrl: http.url('/'), repository: 'acme/shop', token: '${GH_TOKEN}' } });
    const fs = findings();
    const first = await sendAlerts(resolved, report(fs), { env: { GH_TOKEN: 'ghp_test' }, retryDelayMs: 1 });
    expect(first.results[0]).toMatchObject({ channel: 'github', ok: true, delivered: fs.length });
    expect(created).toHaveLength(fs.length);
    expect(created[0]).toMatch(/<!-- thirdsentry-finding: TS-[0-9a-f]{12} -->/);
    const post = http.requests.find((r) => r.method === 'POST');
    expect(post?.url).toBe('/repos/acme/shop/issues');
    expect(post?.headers.authorization).toBe('Bearer ghp_test');
    // A new run (e.g. fresh state) must not duplicate open issues.
    const resolved2 = await project({ minSeverity: 'info', github: { enabled: true, apiUrl: http.url('/'), repository: 'acme/shop', token: '${GH_TOKEN}' } });
    const second = await sendAlerts(resolved2, report(fs), { env: { GH_TOKEN: 'ghp_test' }, retryDelayMs: 1 });
    expect(second.results[0]?.error).toBeUndefined();
    expect(second.results[0]?.detail).toMatch(/0 issue\(s\) created/);
    expect(created).toHaveLength(fs.length);
  });

  it('sends e-mail over SMTP and refuses to send without TLS when TLS is required', async () => {
    const env = { SMTP_HOST: '127.0.0.1', SMTP_PORT: String(smtp.port), SMTP_FROM: 'thirdsentry@example.com', SMTP_TO: 'sec@example.com,dev@example.com' };
    const email = { enabled: true, host: '${SMTP_HOST}', port: '${SMTP_PORT}', from: '${SMTP_FROM}', to: '${SMTP_TO}' };
    const plain = await project({ minSeverity: 'info', email: { ...email, requireTLS: false } });
    const sent = await sendAlerts(plain, report(findings()), { env, retryDelayMs: 1 });
    expect(sent.results[0]).toMatchObject({ channel: 'email', ok: true });
    expect(smtp.messages).toHaveLength(1);
    expect(smtp.messages[0]?.to).toHaveLength(2);
    expect(smtp.messages[0]?.data).toMatch(/Subject: \[ThirdSentry\]/);

    const strict = await project({ minSeverity: 'info', email });
    const refused = await sendAlerts(strict, report(findings()), { env, retryDelayMs: 1 });
    expect(refused.results[0]?.ok).toBe(false);
    expect(smtp.messages).toHaveLength(1);
  });
});
