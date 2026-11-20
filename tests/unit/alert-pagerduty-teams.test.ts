import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { stringify } from 'yaml';
import { findingsToResolve, literalSecretWarnings, sendAlerts } from '../../src/alerts/alert-manager.js';
import { buildAlertPayload, toAlertFinding } from '../../src/alerts/alert-payload.js';
import { dedupKey, pagerDutySeverity, PAGERDUTY_LIMITS, triggerEvent } from '../../src/alerts/pagerduty.js';
import { TEAMS_LIMITS, teamsMessage, teamsText } from '../../src/alerts/teams.js';
import { loadConfig, type ResolvedConfig } from '../../src/config/loader.js';
import { loadFindingState } from '../../src/monitoring/dedup-state.js';
import type { Finding, Severity } from '../../src/types/findings.js';
import type { AnalysisReport } from '../../src/types/report.js';
import { MockHttp } from '../fixtures/mock-servers.js';
import { tempDir } from '../helpers.js';

const http = new MockHttp();
beforeAll(() => http.start());
afterAll(() => http.stop());
beforeEach(() => {
  http.requests.length = 0;
  http.responder = () => ({ status: 202, body: '{"status":"success"}' });
});

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const ROUTING_KEY = 'R0UT1NGKEY0123456789abcdef012345';

function finding(i: number, extra: Partial<Finding> = {}): Finding {
  return {
    id: `TS-${i.toString(16).padStart(12, '0')}`,
    kind: 'resource-modified',
    title: `Script ${i} changed`,
    site: 'shop',
    page: '/',
    pages: ['/'],
    resourceUrl: `https://cdn.vendor.example/s${i}.js`,
    previousHash: 'a'.repeat(64),
    currentHash: 'b'.repeat(64),
    detectedAt: '2026-01-01T00:00:00.000Z',
    severity: SEVERITIES[i % SEVERITIES.length] as Severity,
    confidence: 'high',
    category: 'review',
    score: 50,
    signals: [{ id: 'modified', description: 'Content changed', weight: 50 }],
    reason: `The content of script ${i} changed.`,
    evidence: [{ label: 'URL', value: `https://cdn.vendor.example/s${i}.js` }, { label: 'Excerpt', value: 'SECRET-SCRIPT-BODY' }],
    recommendedAction: 'Review the change, then run "thirdsentry baseline --approve <finding-id>".',
    ...extra,
  };
}

function report(fs: Finding[], extra: Partial<AnalysisReport> = {}): AnalysisReport {
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
    scanSummary: {} as never,
    scanIssues: [],
    sites: [{ name: 'shop', url: 'https://shop.example/', status: 'complete' } as never],
    findings: fs,
    findingCounts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
    highestSeverity: 'high',
    coverageLimitations: [],
    headline: 'Changes need attention',
    ...extra,
  };
}

async function project(alerts: Record<string, unknown>): Promise<ResolvedConfig> {
  const dir = await tempDir('alert-pd-teams-');
  await writeFile(join(dir, 'thirdsentry.yml'), stringify({ version: 1, sites: [{ name: 'shop', url: 'https://shop.example/' }], alerts: { retries: 1, timeoutMs: 3000, minSeverity: 'low', ...alerts } }));
  return loadConfig({ cwd: dir });
}

const PD = { enabled: true, routingKey: '${PD_KEY}', apiUrl: '', minSeverity: 'low', allowInsecureHttp: true };
const TEAMS = { enabled: true, webhookUrl: '${TEAMS_HOOK}', allowInsecureHttp: true };
const env = (): NodeJS.ProcessEnv => ({ PD_KEY: ROUTING_KEY, TEAMS_HOOK: http.url('/teams/secret-token-xyz'), PD_URL: http.url('/v2/enqueue') });
const pd = (extra: Record<string, unknown> = {}) => ({ ...PD, apiUrl: '${PD_URL}', ...extra });
interface PdEvent {
  routing_key: string;
  event_action: string;
  dedup_key: string;
  payload: { summary: string; severity: string; custom_details: Record<string, unknown> };
}
interface Card {
  type: string;
  version: string;
  actions?: unknown;
  body: Array<{ type: string }>;
}
const pdRequests = () => http.requests.filter((r) => r.url.startsWith('/v2/enqueue')).map((r) => JSON.parse(r.body) as PdEvent);
const teamsRequests = () => http.requests.filter((r) => r.url.startsWith('/teams'));

describe('PagerDuty events', () => {
  it('sends one trigger event per finding with the documented fields', async () => {
    const resolved = await project({ pagerduty: pd() });
    const fs = [finding(0), finding(1), finding(2), finding(3)];
    const result = await sendAlerts(resolved, report(fs), { env: env(), retryDelayMs: 1 });
    expect(result.results[0]).toMatchObject({ channel: 'pagerduty', ok: true, delivered: 4, pending: 0 });
    const events = pdRequests();
    expect(events).toHaveLength(4);
    const byKey = new Map(events.map((e) => [e.dedup_key, e]));
    for (const f of fs) {
      const e = byKey.get(`thirdsentry:${f.id}`);
      expect(e).toBeDefined();
      expect(e).toMatchObject({ routing_key: ROUTING_KEY, event_action: 'trigger', client: 'ThirdSentry' });
      expect(e?.payload).toMatchObject({ source: 'shop', group: 'shop', class: 'review', component: 'cdn.vendor.example' });
      expect(e?.payload.summary).toContain(f.title);
      expect(e?.payload.custom_details).toMatchObject({ finding_id: f.id, site: 'shop', confidence: 'high' });
    }
    const raw = http.requests.map((r) => r.body).join('');
    expect(raw).not.toContain('SECRET-SCRIPT-BODY');
    expect(raw).not.toContain('evidence');
  });

  it('maps severities and keeps dedup_key stable across runs', () => {
    expect(['critical', 'high', 'medium', 'low', 'info'].map(pagerDutySeverity)).toEqual(['critical', 'error', 'warning', 'info', 'info']);
    const f = toAlertFinding(finding(5));
    const a = triggerEvent(f, ROUTING_KEY, 'https://ci.example/run/1', 'scan-1', '2026-01-01T00:00:00.000Z');
    const b = triggerEvent(f, ROUTING_KEY, 'https://ci.example/run/2', 'scan-2', '2027-01-01T00:00:00.000Z');
    expect(a.dedup_key).toBe(b.dedup_key);
    expect(a.dedup_key).toBe(dedupKey(f.id));
    expect(dedupKey('TS-x'.repeat(200)).length).toBeLessThanOrEqual(PAGERDUTY_LIMITS.dedupKey);
  });

  it('caps the summary, and links the report only when it is a URL', () => {
    const f = toAlertFinding(finding(1, { title: 'T'.repeat(5000), reason: 'R'.repeat(5000) }));
    const withLink = triggerEvent(f, ROUTING_KEY, 'https://ci.example/run/1', 's', 't') as { payload: { summary: string }; links?: Array<{ href: string }> };
    expect(withLink.payload.summary.length).toBeLessThanOrEqual(1024);
    expect(withLink.links?.[0]?.href).toBe('https://ci.example/run/1');
    const local = triggerEvent(f, ROUTING_KEY, 'C:/reports/report.html', 's', 't') as { links?: unknown };
    expect(local.links).toBeUndefined();
  });

  it('respects maxEventsPerRun and keeps the rest pending for the next runs', async () => {
    const resolved = await project({ pagerduty: pd({ maxEventsPerRun: 2 }) });
    const fs = [1, 2, 3, 4, 5].map((i) => finding(i));
    const first = await sendAlerts(resolved, report(fs), { env: env(), retryDelayMs: 1 });
    expect(first.results[0]).toMatchObject({ delivered: 2, selected: 5, pending: 3 });
    expect(pdRequests()).toHaveLength(2);
    const second = await sendAlerts(resolved, report(fs), { env: env(), retryDelayMs: 1 });
    expect(second.results[0]).toMatchObject({ delivered: 2, selected: 3, pending: 1 });
    const third = await sendAlerts(resolved, report(fs), { env: env(), retryDelayMs: 1 });
    expect(third.results[0]).toMatchObject({ delivered: 1, selected: 1, pending: 0 });
    const keys = pdRequests().map((e) => e.dedup_key);
    expect(new Set(keys).size).toBe(5);
    expect((await sendAlerts(resolved, report(fs), { env: env(), retryDelayMs: 1 })).selected).toBe(0);
  });

  it('retries 429 and 5xx, and does not retry 400', async () => {
    const resolved = await project({ pagerduty: pd() });
    let n = 0;
    http.responder = () => (n++ === 0 ? { status: 429, body: '{"status":"throttle"}' } : { status: 202 });
    const throttled = await sendAlerts(resolved, report([finding(1)]), { env: env(), retryDelayMs: 1 });
    expect(throttled.results[0]).toMatchObject({ ok: true, delivered: 1, attempts: 2 });

    http.requests.length = 0;
    http.responder = () => ({ status: 500 });
    const down = await sendAlerts(resolved, report([finding(2)]), { env: env(), retryDelayMs: 1 });
    expect(down.results[0]).toMatchObject({ ok: false, delivered: 0, pending: 1, attempts: 2 });
    expect(http.requests).toHaveLength(2);

    http.requests.length = 0;
    http.responder = () => ({ status: 400, body: `{"status":"invalid event","message":"Event object is invalid","routing_key":"${ROUTING_KEY}"}` });
    const bad = await sendAlerts(resolved, report([finding(3)]), { env: env(), retryDelayMs: 1 });
    expect(http.requests).toHaveLength(1);
    expect(bad.results[0]).toMatchObject({ ok: false, delivered: 0, attempts: 1 });
    expect(bad.results[0]?.error).toContain('HTTP 400');
    expect(bad.results[0]?.error).toContain('Event object is invalid');
    expect(bad.results[0]?.error).not.toContain(ROUTING_KEY);
    expect(bad.results[0]?.error).toContain('[REDACTED]');
  });

  it('continues past one invalid event (400) but stops on other failures', async () => {
    const resolved = await project({ pagerduty: pd() });
    http.responder = (req) => (req.body.includes('TS-000000000001') ? { status: 400, body: 'bad' } : { status: 202 });
    const result = await sendAlerts(resolved, report([finding(1), finding(2), finding(3)]), { env: env(), retryDelayMs: 1 });
    expect(result.results[0]).toMatchObject({ ok: false, delivered: 2, pending: 1 });
    expect(pdRequests()).toHaveLength(3);
  });

  it('rejects an http apiUrl unless allowInsecureHttp is set, without any request', async () => {
    const resolved = await project({ pagerduty: pd({ allowInsecureHttp: false }) });
    const result = await sendAlerts(resolved, report([finding(1)]), { env: env(), retryDelayMs: 1 });
    expect(result.results[0]).toMatchObject({ ok: false, attempts: 1 });
    expect(result.results[0]?.error).toContain('https://');
    expect(http.requests).toHaveLength(0);
  });

  it('defaults to minSeverity high and warns about a literal routing key', async () => {
    const resolved = await project({ pagerduty: { enabled: true, routingKey: ROUTING_KEY } });
    expect(resolved.config.alerts.pagerduty).toMatchObject({ minSeverity: 'high', autoResolve: false, maxEventsPerRun: 20, apiUrl: 'https://events.pagerduty.com/v2/enqueue' });
    expect(literalSecretWarnings(resolved.config.alerts)).toContain('alerts.pagerduty.routingKey');
    const refs = await project({ pagerduty: { enabled: true }, teams: { enabled: true, webhookUrl: 'https://example.invalid/hook' } });
    expect(literalSecretWarnings(refs.config.alerts)).toEqual(['alerts.teams.webhookUrl']);
  });
});

describe('PagerDuty autoResolve', () => {
  it('resolves findings that are gone from a complete scan, once', async () => {
    const resolved = await project({ pagerduty: pd({ autoResolve: true }) });
    const f1 = finding(1);
    const f2 = finding(2);
    await sendAlerts(resolved, report([f1, f2]), { env: env(), retryDelayMs: 1 });
    http.requests.length = 0;

    const next = await sendAlerts(resolved, report([f1]), { env: env(), retryDelayMs: 1 });
    expect(next.results[0]).toMatchObject({ channel: 'pagerduty', ok: true, delivered: 0, detail: '1 resolved' });
    expect(pdRequests()).toEqual([{ routing_key: ROUTING_KEY, event_action: 'resolve', dedup_key: dedupKey(f2.id) }]);

    http.requests.length = 0;
    await sendAlerts(resolved, report([f1]), { env: env(), retryDelayMs: 1 });
    expect(http.requests).toHaveLength(0);

    // The finding comes back (same ID): it is triggered again.
    await sendAlerts(resolved, report([f1, f2]), { env: env(), retryDelayMs: 1 });
    expect(pdRequests()).toMatchObject([{ event_action: 'trigger', dedup_key: dedupKey(f2.id) }]);
  });

  it('never resolves on a partial scan, a non-complete site or with autoResolve off', async () => {
    const resolved = await project({ pagerduty: pd({ autoResolve: true }) });
    const f1 = finding(1);
    await sendAlerts(resolved, report([f1]), { env: env(), retryDelayMs: 1 });
    const state = await loadFindingState(resolved.paths);
    http.requests.length = 0;
    expect(findingsToResolve(resolved.config.alerts, report([], { scanStatus: 'partial' }), state)).toEqual([]);
    expect(findingsToResolve(resolved.config.alerts, report([], { sites: [{ name: 'shop', status: 'partial' } as never] }), state)).toEqual([]);
    expect(findingsToResolve(resolved.config.alerts, report([], { sites: [{ name: 'other', status: 'complete' } as never] }), state)).toEqual([]);
    await sendAlerts(resolved, report([], { scanStatus: 'partial' }), { env: env(), retryDelayMs: 1 });
    expect(http.requests).toHaveLength(0);
    expect(findingsToResolve(resolved.config.alerts, report([]), state)).toEqual([f1.id]);
    const off = await project({ pagerduty: pd() });
    expect(findingsToResolve(off.config.alerts, report([]), state)).toEqual([]);
  });

  it('a failed resolve stays open and is retried on the next run', async () => {
    const resolved = await project({ pagerduty: pd({ autoResolve: true }) });
    await sendAlerts(resolved, report([finding(1)]), { env: env(), retryDelayMs: 1 });
    http.responder = () => ({ status: 500 });
    const failed = await sendAlerts(resolved, report([]), { env: env(), retryDelayMs: 1 });
    expect(failed.results[0]).toMatchObject({ ok: false });
    http.requests.length = 0;
    http.responder = () => ({ status: 202 });
    const retried = await sendAlerts(resolved, report([]), { env: env(), retryDelayMs: 1 });
    expect(retried.results[0]).toMatchObject({ ok: true, detail: '1 resolved' });
    expect(pdRequests()).toHaveLength(1);
  });

  it('dry run reports pending resolves without sending', async () => {
    const resolved = await project({ pagerduty: pd({ autoResolve: true }) });
    await sendAlerts(resolved, report([finding(1)]), { env: env(), retryDelayMs: 1 });
    http.requests.length = 0;
    const dry = await sendAlerts(resolved, report([]), { env: env(), dryRun: true });
    expect(dry.results[0]?.detail).toContain('1 would be resolved');
    expect(http.requests).toHaveLength(0);
  });
});

function bodyOf(request: { body: string }): { type: string; attachments: Array<{ contentType: string; content: Card }> } {
  return JSON.parse(request.body) as never;
}

describe('Teams Adaptive Card', () => {
  it('posts a message with an Adaptive Card 1.4 attachment', async () => {
    const resolved = await project({ teams: TEAMS, reportUrl: 'https://ci.example/run/42' });
    const result = await sendAlerts(resolved, report([finding(0), finding(1)]), { env: env(), retryDelayMs: 1 });
    expect(result.results[0]).toMatchObject({ channel: 'teams', ok: true, delivered: 2 });
    const message = bodyOf(teamsRequests()[0] as never);
    expect(message.type).toBe('message');
    const attachment = message.attachments[0];
    expect(attachment?.contentType).toBe('application/vnd.microsoft.card.adaptive');
    const card = attachment?.content as Card;
    expect(card).toMatchObject({ type: 'AdaptiveCard', version: '1.4' });
    expect(card.actions).toEqual([{ type: 'Action.OpenUrl', title: 'Open report', url: 'https://ci.example/run/42' }]);
    const containers = (card.body as Array<{ type: string }>).filter((b) => b.type === 'Container');
    expect(containers).toHaveLength(2);
    const text = JSON.stringify(card.body);
    expect(text).toContain('By severity: critical 1, high 1');
    expect(text).toContain('TS\\\\-000000000000');
    expect(text).toContain('Why:');
    expect(text).toContain('Next:');
    expect(text).not.toContain('SECRET-SCRIPT-BODY');
  });

  it('shows a local report path as text instead of a link action', () => {
    const payload = buildAlertPayload(report([finding(1)]), [finding(1)], { maxFindings: 20, reportLocation: 'C:/reports/report.html' });
    const card = teamsMessage(payload).body as { attachments: Array<{ content: { actions?: unknown } }> };
    expect(card.attachments[0]?.content.actions).toBeUndefined();
  });

  it('keeps the payload under the size limit, renders fewer findings and carries the rest over', async () => {
    const resolved = await project({ teams: TEAMS, maxFindingsPerAlert: 100 });
    const long = 'x'.repeat(2000);
    const fs = Array.from({ length: 100 }, (_, i) => finding(i + 1, { reason: long, recommendedAction: long, title: long }));
    const payload = buildAlertPayload(report(fs), fs, { maxFindings: 100, reportLocation: 'https://ci.example/r' });
    const message = teamsMessage(payload);
    expect(message.bytes).toBeLessThanOrEqual(TEAMS_LIMITS.targetBytes);
    expect(message.rendered.length).toBeGreaterThan(0);
    expect(message.rendered.length).toBeLessThan(100);
    expect(JSON.stringify(message.body)).toContain(`${100 - message.rendered.length} more finding(s)`);

    const first = await sendAlerts(resolved, report(fs), { env: env(), retryDelayMs: 1 });
    const delivered = first.results[0]?.delivered ?? 0;
    expect(delivered).toBe(message.rendered.length);
    expect(first.results[0]?.pending).toBe(100 - delivered);
    expect(Buffer.byteLength(teamsRequests()[0]?.body ?? '')).toBeLessThanOrEqual(TEAMS_LIMITS.maxBytes);
    const second = await sendAlerts(resolved, report(fs), { env: env(), retryDelayMs: 1 });
    expect(second.results[0]?.selected).toBe(100 - delivered);
    expect(second.results[0]?.delivered).toBeGreaterThan(0);
  });

  it('neutralises markdown, links, tags and mentions in finding text', () => {
    const hostile = '[Click here](https://evil.example/login) **urgent** <at>everyone</at> @channel www.evil.example `code` # heading\n- item';
    const out = teamsText(hostile);
    expect(out).not.toContain('](');
    expect(out).not.toMatch(/(^|[^\\])\*\*/);
    expect(out).not.toContain('<at>');
    expect(out).not.toContain('://');
    expect(out).not.toContain('@channel');
    expect(out).not.toMatch(/www\./);
    expect(out).not.toContain('\n');
    expect(out).toContain('\\[Click here\\]');
    const f = finding(1, { title: hostile, reason: hostile, resourceUrl: 'https://evil.example/[x](https://y.example)' });
    const payload = buildAlertPayload(report([f]), [f], { maxFindings: 20, reportLocation: 'https://ci.example/r' });
    const raw = JSON.stringify(teamsMessage(payload).body);
    expect(raw).not.toContain('](https');
    expect(raw).not.toContain('<at>');
  });

  it('rejects http URLs unless allowInsecureHttp is set', async () => {
    const resolved = await project({ teams: { ...TEAMS, allowInsecureHttp: false } });
    const result = await sendAlerts(resolved, report([finding(1)]), { env: env(), retryDelayMs: 1 });
    expect(result.results[0]).toMatchObject({ ok: false, attempts: 1 });
    expect(result.results[0]?.error).toContain('https://');
    expect(http.requests).toHaveLength(0);
  });

  it('retries 5xx/429, not 400, and redacts the webhook URL from errors', async () => {
    const resolved = await project({ teams: TEAMS });
    http.responder = () => ({ status: 429 });
    const throttled = await sendAlerts(resolved, report([finding(1)]), { env: env(), retryDelayMs: 1 });
    expect(throttled.results[0]).toMatchObject({ ok: false, attempts: 2 });
    http.requests.length = 0;
    http.responder = (req) => ({ status: 400, body: `rejected ${req.url}` });
    const bad = await sendAlerts(resolved, report([finding(1)]), { env: env(), retryDelayMs: 1 });
    expect(http.requests).toHaveLength(1);
    expect(bad.results[0]).toMatchObject({ ok: false, attempts: 1 });
    expect(bad.results[0]?.error).not.toContain('secret-token-xyz');
    expect(bad.results[0]?.error).toContain('[REDACTED]');
  });
});

describe('per-channel state with PagerDuty and Teams', () => {
  it('Teams failing does not resend PagerDuty; Teams is retried alone next run', async () => {
    const resolved = await project({ pagerduty: pd(), teams: TEAMS });
    const fs = [finding(1), finding(2)];
    http.responder = (req) => (req.url.startsWith('/teams') ? { status: 503 } : { status: 202 });
    const first = await sendAlerts(resolved, report(fs), { env: env(), retryDelayMs: 1 });
    expect(first.results.find((r) => r.channel === 'pagerduty')).toMatchObject({ ok: true, delivered: 2 });
    expect(first.results.find((r) => r.channel === 'teams')).toMatchObject({ ok: false, delivered: 0, pending: 2 });
    expect(pdRequests()).toHaveLength(2);

    http.requests.length = 0;
    http.responder = () => ({ status: 202 });
    const second = await sendAlerts(resolved, report(fs), { env: env(), retryDelayMs: 1 });
    expect(second.results.find((r) => r.channel === 'teams')).toMatchObject({ ok: true, delivered: 2 });
    expect(second.results.find((r) => r.channel === 'pagerduty')).toMatchObject({ delivered: 0, detail: 'nothing new for this channel' });
    expect(pdRequests()).toHaveLength(0);
    expect(teamsRequests()).toHaveLength(1);
  });

  it('PagerDuty uses its own threshold (high) while Teams uses the global one', async () => {
    const resolved = await project({ minSeverity: 'low', pagerduty: { ...pd(), minSeverity: undefined }, teams: TEAMS });
    const fs = [finding(0), finding(1), finding(2), finding(3)];
    const result = await sendAlerts(resolved, report(fs), { env: env(), retryDelayMs: 1 });
    expect(result.results.find((r) => r.channel === 'pagerduty')?.delivered).toBe(2);
    expect(result.results.find((r) => r.channel === 'teams')?.delivered).toBe(4);
  });

  it('--channel restricts to the named channels', async () => {
    const resolved = await project({ pagerduty: pd(), teams: TEAMS });
    await sendAlerts(resolved, report([finding(1)]), { env: env(), retryDelayMs: 1, channels: ['teams'] });
    expect(pdRequests()).toHaveLength(0);
    expect(teamsRequests()).toHaveLength(1);
  });
});

describe('--test and --dry-run', () => {
  it('dry run sends nothing and describes both channels', async () => {
    const resolved = await project({ pagerduty: pd(), teams: TEAMS });
    const dry = await sendAlerts(resolved, report([finding(1), finding(2)]), { env: env(), dryRun: true });
    expect(http.requests).toHaveLength(0);
    expect(dry.results.map((r) => [r.channel, r.selected])).toEqual([['pagerduty', 2], ['teams', 2]]);
    expect(dry.results[0]?.detail).toBe('2 finding(s) would be sent');
  });

  it('test alert: Teams gets a labelled card, PagerDuty a trigger that is resolved right away', async () => {
    const resolved = await project({ pagerduty: pd(), teams: TEAMS });
    const result = await sendAlerts(resolved, undefined, { env: env(), test: true, retryDelayMs: 1 });
    expect(result.results.map((r) => [r.channel, r.ok])).toEqual([['pagerduty', true], ['teams', true]]);
    const events = pdRequests();
    expect(events.map((e) => e.event_action)).toEqual(['trigger', 'resolve']);
    expect(events[0]?.payload.summary).toContain('TEST');
    expect(events[0]?.payload.severity).toBe('info');
    expect(events[1]?.dedup_key).toBe(events[0]?.dedup_key);
    expect(JSON.stringify(bodyOf(teamsRequests()[0] as never))).toContain('TEST alert');
    expect((await loadFindingState(resolved.paths)).findings).toEqual({});
  });
});
