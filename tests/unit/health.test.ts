import { readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { stringify } from 'yaml';
import { selectFindingsForAlert } from '../../src/alerts/alert-payload.js';
import { loadConfig, type ResolvedConfig } from '../../src/config/loader.js';
import { buildHealthFindings, scanUnhealthyId } from '../../src/health/health-finding.js';
import { emptyHealthState, loadHealthState, recordAlertDelivery, recordScanHealth, type HealthPolicy, type HealthState } from '../../src/health/health-state.js';
import { heartbeatOutcome, sendHeartbeat } from '../../src/health/heartbeat.js';
import { escapeLabelValue, renderMetrics, type MetricsInput } from '../../src/health/metrics.js';
import { pushMetrics } from '../../src/health/metrics-push.js';
import { parseServeAddress, startMetricsServer } from '../../src/health/metrics-server.js';
import { computeStatus } from '../../src/health/status.js';
import { analyzeScan } from '../../src/monitoring/analysis-runner.js';
import { emptyFindingStateForTests } from './health-helpers.js';
import { buildProgram } from '../../src/cli/index.js';
import { HeartbeatSchema } from '../../src/config/schema.js';
import type { ScanResult, SiteResult } from '../../src/types/index.js';
import type { AnalysisReport } from '../../src/types/report.js';
import { scan, site } from '../fixtures/builders.js';
import { MockHttp } from '../fixtures/mock-servers.js';
import { tempDir } from '../helpers.js';

const POLICY: HealthPolicy = { failureThreshold: 3, countIncomplete: true };
let counter = 0;

function result(status: 'complete' | 'partial' | 'failed', minute = counter++): ScanResult {
  const start = new Date(Date.UTC(2026, 0, 1, 0, minute)).toISOString();
  const end = new Date(Date.UTC(2026, 0, 1, 0, minute, 30)).toISOString();
  const s: SiteResult = {
    ...site([]),
    status,
    startedAt: start,
    finishedAt: end,
    issues: status === 'complete' ? [] : [{ level: 'error', code: 'nav-timeout', message: 'Navigation timed out\nsecond line' }],
  };
  return { ...scan([s], `scan-${minute}`), status };
}

function apply(state: HealthState, status: 'complete' | 'partial' | 'failed', policy = POLICY, minute?: number) {
  return recordScanHealth(state, result(status, minute), policy);
}

describe('health state transitions', () => {
  it('counts failed and incomplete scans, remembers the streak start and resets on a complete scan', () => {
    const state = emptyHealthState();
    apply(state, 'complete', POLICY, 1);
    expect(state.sites.shop?.consecutiveFailures).toBe(0);
    apply(state, 'failed', POLICY, 2);
    apply(state, 'partial', POLICY, 3);
    const h = state.sites.shop;
    expect(h?.consecutiveFailures).toBe(2);
    expect(h?.streakStart).toBe(new Date(Date.UTC(2026, 0, 1, 0, 2)).toISOString());
    expect(h?.lastCompleteAt).toBe(new Date(Date.UTC(2026, 0, 1, 0, 1, 30)).toISOString());
    expect(h?.lastError).toBe('nav-timeout: Navigation timed out second line');
    expect(h?.lastDurationSeconds).toBe(30);
    apply(state, 'complete', POLICY, 4);
    expect(state.sites.shop?.consecutiveFailures).toBe(0);
    expect(state.sites.shop?.streakStart).toBeUndefined();
    expect(state.sites.shop?.lastError).toBeUndefined();
  });

  it('can ignore incomplete scans (countIncomplete: false)', () => {
    const state = emptyHealthState();
    const policy = { ...POLICY, countIncomplete: false };
    apply(state, 'partial', policy, 1);
    apply(state, 'partial', policy, 2);
    expect(state.sites.shop?.consecutiveFailures).toBe(0);
    apply(state, 'failed', policy, 3);
    apply(state, 'partial', policy, 4);
    expect(state.sites.shop?.consecutiveFailures).toBe(0);
  });

  it('is idempotent per scan id', () => {
    const state = emptyHealthState();
    const r = result('failed', 5);
    recordScanHealth(state, r, POLICY);
    recordScanHealth(state, r, POLICY);
    expect(state.sites.shop?.consecutiveFailures).toBe(1);
  });

  it('reports a recovery only after an unhealthy streak (threshold reached)', () => {
    const state = emptyHealthState();
    apply(state, 'failed', POLICY, 1);
    apply(state, 'failed', POLICY, 2);
    expect(apply(state, 'complete', POLICY, 3)).toEqual([]);
    for (let i = 4; i <= 6; i++) apply(state, 'failed', POLICY, i);
    const recoveries = apply(state, 'complete', POLICY, 7);
    expect(recoveries).toHaveLength(1);
    expect(recoveries[0]).toMatchObject({ site: 'shop', failures: 3, since: new Date(Date.UTC(2026, 0, 1, 0, 4)).toISOString() });
    expect(state.sites.shop?.lastRecovery?.failures).toBe(3);
  });

  it('records alert delivery per channel', () => {
    const state = emptyHealthState();
    const now = new Date('2026-01-01T00:00:00Z');
    recordAlertDelivery(state, 'slack', false, now, 'HTTP 500');
    recordAlertDelivery(state, 'slack', false, now, 'HTTP 500');
    expect(state.alerts.slack?.consecutiveFailures).toBe(2);
    recordAlertDelivery(state, 'slack', true, now);
    expect(state.alerts.slack).toMatchObject({ consecutiveFailures: 0, lastSuccessAt: now.toISOString() });
  });
});

describe('scan-unhealthy finding', () => {
  const now = new Date('2026-01-02T00:00:00Z');

  it('appears at the threshold with a stable id for the whole outage and escalates at 3x', () => {
    const state = emptyHealthState();
    apply(state, 'failed', POLICY, 1);
    apply(state, 'failed', POLICY, 2);
    expect(buildHealthFindings(state, ['shop'], POLICY, now)).toEqual([]);
    apply(state, 'failed', POLICY, 3);
    const [first] = buildHealthFindings(state, ['shop'], POLICY, now);
    expect(first).toMatchObject({ kind: 'scan-unhealthy', severity: 'high', site: 'shop' });
    expect(first?.id).toBe(scanUnhealthyId('shop', new Date(Date.UTC(2026, 0, 1, 0, 1)).toISOString()));
    apply(state, 'failed', POLICY, 4);
    const [second] = buildHealthFindings(state, ['shop'], POLICY, now);
    expect(second?.id).toBe(first?.id);
    for (let i = 5; i <= 9; i++) apply(state, 'failed', POLICY, i);
    const [third] = buildHealthFindings(state, ['shop'], POLICY, now);
    expect(third?.id).toBe(first?.id);
    expect(third?.severity).toBe('critical');
    // a new outage has a new id
    apply(state, 'complete', POLICY, 10);
    for (let i = 11; i <= 13; i++) apply(state, 'failed', POLICY, i);
    expect(buildHealthFindings(state, ['shop'], POLICY, now)[0]?.id).not.toBe(first?.id);
  });

  it('alerts once per outage and again only on escalation (existing per-channel dedup)', () => {
    const state = emptyHealthState();
    for (let i = 1; i <= 3; i++) apply(state, 'failed', POLICY, i);
    const [f] = buildHealthFindings(state, ['shop'], POLICY, now);
    if (!f) throw new Error('no finding');
    const report = { findings: [f] } as unknown as AnalysisReport;
    const alertState = emptyFindingStateForTests();
    const cfg = { minSeverity: 'medium' as const, repeatAfterHours: 0 };
    expect(selectFindingsForAlert(report, alertState, cfg, now, 'slack')).toHaveLength(1);
    alertState.findings[f.id] = { firstSeen: 'x', lastSeen: 'x', timesSeen: 1, severity: 'high', alerts: { slack: { at: 'x', severity: 'high' } } };
    expect(selectFindingsForAlert(report, alertState, cfg, now, 'slack')).toHaveLength(0);
    for (let i = 4; i <= 9; i++) apply(state, 'failed', POLICY, i);
    const [escalated] = buildHealthFindings(state, ['shop'], POLICY, now);
    expect(escalated?.id).toBe(f.id);
    expect(selectFindingsForAlert({ findings: [escalated] } as unknown as AnalysisReport, alertState, cfg, now, 'slack')).toHaveLength(1);
  });
});

describe('analyzeScan integration', () => {
  let dir: string;
  let resolved: ResolvedConfig;
  beforeAll(async () => {
    dir = await tempDir('health-');
    await writeFile(join(dir, 'thirdsentry.yml'), stringify({ version: 1, sites: [{ name: 'shop', url: 'https://shop.example/', pages: ['/'] }], health: { failureThreshold: 2 } }));
    resolved = await loadConfig({ cwd: dir });
  });

  it('writes health.json, raises scan-unhealthy (no baseline needed) and notes the recovery', async () => {
    const opts = (n: number) => ({ scanPath: join(dir, `s${n}.json`), updateState: true, now: new Date(Date.UTC(2026, 0, 1, 1, n)) });
    const a = await analyzeScan(resolved, result('failed', 1), opts(1));
    expect(a.report.findings.filter((f) => f.kind === 'scan-unhealthy')).toHaveLength(0);
    const b = await analyzeScan(resolved, result('failed', 2), opts(2));
    const unhealthy = b.report.findings.filter((f) => f.kind === 'scan-unhealthy');
    expect(unhealthy).toHaveLength(1);
    expect(unhealthy[0]?.status).toBe('new');
    expect(b.report.health?.sites[0]).toMatchObject({ name: 'shop', consecutiveFailures: 2 });
    const c = await analyzeScan(resolved, result('failed', 3), opts(3));
    expect(c.report.findings.find((f) => f.kind === 'scan-unhealthy')?.status).toBe('recurring');
    expect((await loadHealthState(resolved.paths)).sites.shop?.consecutiveFailures).toBe(3);
    const d = await analyzeScan(resolved, result('complete', 4), opts(4));
    expect(d.report.findings.filter((f) => f.kind === 'scan-unhealthy')).toHaveLength(0);
    expect(d.report.health?.recoveries[0]).toMatchObject({ site: 'shop', failures: 3 });
    expect(d.report.headline).toContain('Recovered: scanning of shop works again after 3 failed scans');
  });

  it('does not touch health state in read-only mode', async () => {
    const before = await loadHealthState(resolved.paths);
    await analyzeScan(resolved, result('failed', 90), { scanPath: join(dir, 'x.json') });
    expect(await loadHealthState(resolved.paths)).toEqual(before);
  });

  it('metrics and status are read-only commands that take no storage lock', async () => {
    const before = await readdir(resolved.paths.state);
    const out: string[] = [];
    const orig = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: string) => (out.push(String(chunk)), true);
    try {
      await buildProgram().parseAsync(['node', 'thirdsentry', '-c', join(dir, 'thirdsentry.yml'), 'metrics']);
    } finally {
      process.stdout.write = orig;
    }
    expect(out.join('')).toContain('thirdsentry_consecutive_failed_scans{site="shop"} 0');
    expect(await readdir(resolved.paths.state)).toEqual(before);
  });
});

describe('heartbeat', () => {
  const http = new MockHttp();
  beforeAll(() => http.start());
  afterAll(() => http.stop());
  beforeEach(() => {
    http.requests.length = 0;
    http.responder = () => ({ status: 200, body: 'OK' });
  });
  const cfg = (extra: Record<string, unknown> = {}) => HeartbeatSchema.parse({ url: http.url('/ping/secret-uuid-1234'), ...extra });

  it('pings the success URL, the /fail convention and an explicit failUrl', async () => {
    expect((await sendHeartbeat(cfg(), 'success')).ok).toBe(true);
    expect(http.requests.at(-1)?.url).toBe('/ping/secret-uuid-1234');
    await sendHeartbeat(cfg(), 'fail');
    expect(http.requests.at(-1)?.url).toBe('/ping/secret-uuid-1234/fail');
    await sendHeartbeat(cfg({ failUrl: http.url('/down?msg=1') }), 'fail');
    expect(http.requests.at(-1)?.url).toBe('/down?msg=1');
    expect(http.requests.at(-1)?.method).toBe('GET');
  });

  it('resolves ${ENV} URLs, and sends nothing on skip or an empty failPath', async () => {
    const r = await sendHeartbeat(HeartbeatSchema.parse({}), 'success', { env: { THIRDSENTRY_HEARTBEAT_URL: http.url('/from-env') } });
    expect(r.ok).toBe(true);
    expect(http.requests.at(-1)?.url).toBe('/from-env');
    const n = http.requests.length;
    expect((await sendHeartbeat(cfg(), 'skip')).sent).toBe(false);
    expect((await sendHeartbeat(cfg({ failPath: '' }), 'fail')).sent).toBe(false);
    expect(http.requests).toHaveLength(n);
  });

  it('maps scan status to the outcome', () => {
    const c = HeartbeatSchema.parse({});
    expect(heartbeatOutcome({ scanStatus: 'complete' }, c)).toBe('success');
    expect(heartbeatOutcome({ scanStatus: 'partial' }, c)).toBe('fail');
    expect(heartbeatOutcome({ scanStatus: 'partial' }, { onIncomplete: 'success' })).toBe('success');
    expect(heartbeatOutcome({ scanStatus: 'partial' }, { onIncomplete: 'skip' })).toBe('skip');
    expect(heartbeatOutcome({ scanStatus: 'failed' }, { onIncomplete: 'success' })).toBe('fail');
    expect(heartbeatOutcome({ scanStatus: 'complete' }, c, true)).toBe('fail');
  });

  it('reports HTTP errors and timeouts without the URL, once, without retrying', async () => {
    http.responder = () => ({ status: 500, body: 'oops /ping/secret-uuid-1234 failed' });
    const r = await sendHeartbeat(cfg(), 'success');
    expect(r.ok).toBe(false);
    expect(r.detail).toContain('HTTP 500');
    expect(r.detail).not.toContain('secret-uuid-1234');
    expect(http.requests).toHaveLength(1);

    const slow = await sendHeartbeat(cfg({ timeoutMs: 500 }), 'success', {
      fetchImpl: ((_url: string | URL | Request, init?: RequestInit) =>
        new Promise((_res, rej) => init?.signal?.addEventListener('abort', () => rej(Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }))))),
    });
    expect(slow.ok).toBe(false);
    expect(slow.detail).toContain('timed out after 500ms');
  });

  it('redacts the URL from transport errors', async () => {
    const r = await sendHeartbeat(cfg(), 'success', {
      fetchImpl: (() => Promise.reject(new Error(`connect failed ${http.url('/ping/secret-uuid-1234')}`))),
    });
    expect(r.ok).toBe(false);
    expect(r.detail).not.toContain('secret-uuid-1234');
    expect(r.detail).toContain('[REDACTED]');
  });

  it('fails soft on an unset variable or invalid URL', async () => {
    const r = await sendHeartbeat(HeartbeatSchema.parse({}), 'success', { env: {} });
    expect(r.ok).toBe(false);
    expect(r.detail).toContain('THIRDSENTRY_HEARTBEAT_URL');
    expect((await sendHeartbeat(HeartbeatSchema.parse({ url: 'ftp://x.example/y' }), 'success')).ok).toBe(false);
  });
});

function metricsInput(): MetricsInput {
  const state = emptyHealthState();
  for (let i = 1; i <= 3; i++) apply(state, 'failed', POLICY, i);
  recordAlertDelivery(state, 'slack', false, new Date(), 'x');
  const report = {
    kind: 'thirdsentry-report',
    schemaVersion: 1,
    generatedAt: '2026-01-01T00:05:00.000Z',
    sites: [{ name: 'shop', baseline: { exists: true } }],
    findings: [
      { site: 'shop', severity: 'high', id: 'a' },
      { site: 'shop', severity: 'high', id: 'b', suppressed: { reason: 'x' } },
      { site: 'other', severity: 'low', id: 'c' },
    ],
  } as unknown as AnalysisReport;
  return { version: '1.2.3', sites: ['shop', 'we"ird\\site\nx'], health: state, report, pendingByChannel: { slack: 2 } };
}

describe('metrics rendering', () => {
  const text = renderMetrics(metricsInput());

  it('is valid exposition text: HELP/TYPE once per family, then samples, newline terminated', () => {
    expect(text.endsWith('\n')).toBe(true);
    const types = [...text.matchAll(/^# TYPE (\S+) gauge$/gm)].map((m) => m[1]);
    expect(new Set(types).size).toBe(types.length);
    const sample = /^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="([^"\\\n]|\\.)*"(,|(?=\})))*\})? [^ ]+$/;
    for (const line of text.trimEnd().split('\n')) {
      if (line.startsWith('#')) expect(line).toMatch(/^# (HELP|TYPE) thirdsentry_[a-z_]+ /);
      else expect(line).toMatch(sample);
    }
    for (const t of types) expect(t).toMatch(/^thirdsentry_/);
  });

  it('exports the documented metrics with bounded labels', () => {
    expect(text).toContain('thirdsentry_info{version="1.2.3"} 1');
    expect(text).toContain('thirdsentry_consecutive_failed_scans{site="shop"} 3');
    expect(text).toContain('thirdsentry_last_scan_timestamp_seconds{site="shop"} ');
    expect(text).not.toContain('thirdsentry_last_complete_scan_timestamp_seconds{');
    expect(text).toContain('thirdsentry_scan_duration_seconds{site="shop"} 30');
    expect(text).toContain('thirdsentry_pages{site="shop",status="complete"} 1');
    expect(text).toContain('thirdsentry_scripts{site="shop",party="third-party"} 0');
    expect(text).toContain('thirdsentry_findings{site="shop",severity="high",suppressed="false"} 1');
    expect(text).toContain('thirdsentry_findings{site="shop",severity="high",suppressed="true"} 1');
    expect(text).toContain('thirdsentry_blocked_connections{site="shop"} 0');
    expect(text).toContain('thirdsentry_baseline_present{site="shop"} 1');
    expect(text).toContain('thirdsentry_alert_delivery_failures{channel="slack"} 1');
    expect(text).toContain('thirdsentry_alert_pending_findings{channel="slack"} 2');
    expect(text).not.toContain('site="other"');
  });

  it('escapes label values', () => {
    expect(escapeLabelValue('a"b\\c\nd')).toBe('a\\"b\\\\c\\nd');
    expect(text).toContain('site="we\\"ird\\\\site\\nx"');
  });
});

describe('metrics exporter', () => {
  it('parses --serve addresses', () => {
    expect(parseServeAddress('9464')).toEqual({ host: '127.0.0.1', port: 9464 });
    expect(parseServeAddress('0.0.0.0:9000')).toEqual({ host: '0.0.0.0', port: 9000 });
    expect(parseServeAddress('[::1]:80')).toEqual({ host: '::1', port: 80 });
    expect(() => parseServeAddress('host:99999')).toThrow();
    expect(() => parseServeAddress('nope')).toThrow();
  });

  it('serves /metrics and /healthz read-only on an ephemeral port', async () => {
    let fail = false;
    const server = await startMetricsServer({
      host: '127.0.0.1',
      port: 0,
      render: () => (fail ? Promise.reject(new Error('/secret/path broke')) : Promise.resolve(renderMetrics(metricsInput()))),
    });
    try {
      const base = `http://127.0.0.1:${server.port}`;
      const m = await fetch(`${base}/metrics`);
      expect(m.status).toBe(200);
      expect(m.headers.get('content-type')).toContain('text/plain; version=0.0.4');
      expect(await m.text()).toContain('thirdsentry_info{version="1.2.3"} 1');
      expect((await fetch(`${base}/healthz`)).status).toBe(200);
      expect((await fetch(`${base}/nope`)).status).toBe(404);
      expect((await fetch(`${base}/metrics`, { method: 'POST', body: 'x' })).status).toBe(405);
      fail = true;
      const bad = await fetch(`${base}/metrics`);
      expect(bad.status).toBe(503);
      expect(await bad.text()).not.toContain('secret');
    } finally {
      await server.close();
    }
  });

  it('pushes to a Pushgateway with PUT and redacts credentials on failure', async () => {
    const http = new MockHttp();
    await http.start();
    try {
      await pushMetrics(http.url('/'), 'x 1\n');
      expect(http.requests[0]).toMatchObject({ method: 'PUT', url: '/metrics/job/thirdsentry', body: 'x 1\n' });
      http.responder = () => ({ status: 500, body: 'boom' });
      await expect(pushMetrics(`http://user:hunter2hunter2@127.0.0.1:${http.port}/`, 'x 1\n')).rejects.toThrow(/HTTP 500/);
      await expect(pushMetrics(`http://user:hunter2hunter2@127.0.0.1:${http.port}/`, 'x 1\n')).rejects.not.toThrow(/hunter2/);
    } finally {
      await http.stop();
    }
  });
});

describe('status', () => {
  const now = new Date('2026-01-01T12:00:00Z');
  const input = (state: HealthState, extra = {}) => ({ now, sites: ['shop'], health: state, baselinePresent: { shop: true }, enabledChannels: ['slack'], policy: POLICY, ...extra });

  it('exits 3 when nothing was scanned yet', () => {
    const s = computeStatus(input(emptyHealthState()));
    expect(s.exitCode).toBe(3);
    expect(s.sites[0]?.state).toBe('unknown');
  });

  it('exits 0 when healthy or degraded, 1 at the failure threshold', () => {
    const state = emptyHealthState();
    apply(state, 'complete', POLICY, 1);
    expect(computeStatus(input(state)).exitCode).toBe(0);
    apply(state, 'failed', POLICY, 2);
    const degraded = computeStatus(input(state));
    expect(degraded.exitCode).toBe(0);
    expect(degraded.sites[0]?.state).toBe('degraded');
    apply(state, 'failed', POLICY, 3);
    apply(state, 'failed', POLICY, 4);
    const bad = computeStatus(input(state));
    expect(bad.exitCode).toBe(1);
    expect(bad.sites[0]).toMatchObject({ state: 'unhealthy', consecutiveFailures: 3 });
  });

  it('flags stale scans with maxAgeHours, failing alert channels and counts open findings', () => {
    const state = emptyHealthState();
    apply(state, 'complete', POLICY, 1);
    expect(computeStatus(input(state, { maxAgeHours: 6 })).exitCode).toBe(1);
    recordAlertDelivery(state, 'slack', false, now, 'x');
    recordAlertDelivery(state, 'slack', false, now, 'x');
    recordAlertDelivery(state, 'slack', false, now, 'x');
    const s = computeStatus(
      input(state, { report: { findings: [{ site: 'shop', severity: 'high' }, { site: 'shop', severity: 'high', suppressed: {} }] } as unknown as AnalysisReport }),
    );
    expect(s.channels[0]?.state).toBe('unhealthy');
    expect(s.exitCode).toBe(1);
    expect(s.sites[0]?.openFindings.high).toBe(1);
  });

  it('degrades a healthy site without a baseline', () => {
    const state = emptyHealthState();
    apply(state, 'complete', POLICY, 1);
    const s = computeStatus(input(state, { baselinePresent: { shop: false } }));
    expect(s.sites[0]?.reasons).toContain('no approved baseline');
    expect(s.exitCode).toBe(0);
  });
});
