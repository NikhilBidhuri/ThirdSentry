import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import net, { type AddressInfo } from 'node:net';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { stringify } from 'yaml';
import { isRetryable, sendAlerts } from '../../src/alerts/alert-manager.js';
import { buildAlertPayload, toAlertFinding } from '../../src/alerts/alert-payload.js';
import { emailHtml, emailText, isRetryableSmtpError, parseRecipients } from '../../src/alerts/email.js';
import { GITHUB_MAX_BODY_CHARS, issueBody } from '../../src/alerts/github-issues.js';
import { AlertDeliveryError, sendHttp, type FetchLike } from '../../src/alerts/http.js';
import { SLACK_LIMITS, slackMessage } from '../../src/alerts/slack.js';
import { printAlertResult } from '../../src/cli/commands/alert.js';
import { loadConfig, type ResolvedConfig } from '../../src/config/loader.js';
import { findingStatePath, loadFindingState } from '../../src/monitoring/dedup-state.js';
import type { Finding, Severity } from '../../src/types/findings.js';
import type { AnalysisReport } from '../../src/types/report.js';
import { ConfigError } from '../../src/utils/errors.js';
import { MockHttp, MockSmtp } from '../fixtures/mock-servers.js';
import { tempDir } from '../helpers.js';

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

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

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
    evidence: [{ label: 'URL', value: `https://cdn.vendor.example/s${i}.js` }],
    recommendedAction: 'Review the change, then run "thirdsentry baseline --approve <finding-id>".',
    ...extra,
  };
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
  const dir = await tempDir('alert-delivery-');
  await writeFile(join(dir, 'thirdsentry.yml'), stringify({ version: 1, sites: [{ name: 'shop', url: 'https://shop.example/' }], alerts: { retries: 1, timeoutMs: 3000, minSeverity: 'low', ...alerts } }));
  return loadConfig({ cwd: dir });
}

/** In-process Slack stand-in (Slack requires https, so it is reached through fetchImpl). */
function fakeSlack(status: () => number = () => 200): { fetchImpl: FetchLike; bodies: Array<{ text: string; blocks: Array<{ type: string; text?: { text: string } }> }> } {
  const bodies: Array<{ text: string; blocks: Array<{ type: string; text?: { text: string } }> }> = [];
  const fetchImpl = ((_url: string | URL | Request, init?: RequestInit) => {
    const s = status();
    if (s === 200) bodies.push(JSON.parse(init?.body as string) as (typeof bodies)[number]);
    return Promise.resolve(new Response(s === 200 ? 'ok' : 'invalid_blocks', { status: s }));
  }) as FetchLike;
  return { fetchImpl, bodies };
}

/** Route Slack to the in-process stand-in and everything else to the real HTTP stack (mock servers). */
function route(slack: { fetchImpl: FetchLike }): FetchLike {
  return ((url: string | URL | Request, init?: RequestInit) => ((typeof url === 'string' ? url : url instanceof URL ? url.href : url.url).startsWith('https://hooks.slack') ? slack.fetchImpl(url, init) : fetch(url, init)));
}

const SLACK = { enabled: true, webhookUrl: 'https://hooks.slack.example/services/T0/B0/SECRET' };

describe('per-channel delivery state', () => {
  it('a failing channel gets its findings on the next run even though another channel succeeded', async () => {
    const resolved = await project({ slack: SLACK, webhook: { enabled: true, url: '${HOOK_URL}', allowInsecureHttp: true } });
    const env = { HOOK_URL: http.url('/hook') };
    const slack = fakeSlack();
    const fs = [finding(1), finding(2)];
    const fetchImpl = route(slack);
    http.responder = () => ({ status: 503 });
    const first = await sendAlerts(resolved, report(fs), { env, fetchImpl, retryDelayMs: 1 });
    expect(first.results.find((r) => r.channel === 'slack')).toMatchObject({ ok: true, delivered: 2 });
    expect(first.results.find((r) => r.channel === 'webhook')).toMatchObject({ ok: false, delivered: 0, pending: 2 });

    http.requests.length = 0;
    http.responder = () => ({ status: 200 });
    const second = await sendAlerts(resolved, report(fs), { env, fetchImpl, retryDelayMs: 1 });
    expect(second.results.find((r) => r.channel === 'webhook')).toMatchObject({ ok: true, delivered: 2 });
    expect(second.results.find((r) => r.channel === 'slack')).toMatchObject({ ok: true, delivered: 0, detail: 'nothing new for this channel' });
    expect(slack.bodies).toHaveLength(1);
    expect(http.requests).toHaveLength(1);

    const third = await sendAlerts(resolved, report(fs), { env, fetchImpl, retryDelayMs: 1 });
    expect(third.selected).toBe(0);
  });

  it('re-alerts on severity escalation per channel', async () => {
    const resolved = await project({ slack: SLACK });
    const slack = fakeSlack();
    await sendAlerts(resolved, report([finding(2, { severity: 'medium' })]), { fetchImpl: slack.fetchImpl, retryDelayMs: 1 });
    const again = await sendAlerts(resolved, report([finding(2, { severity: 'medium' })]), { fetchImpl: slack.fetchImpl, retryDelayMs: 1 });
    expect(again.selected).toBe(0);
    const escalated = await sendAlerts(resolved, report([finding(2, { severity: 'critical' })]), { fetchImpl: slack.fetchImpl, retryDelayMs: 1 });
    expect(escalated.results[0]).toMatchObject({ channel: 'slack', ok: true, delivered: 1 });
  });

  it('GitHub findings skipped by maxIssuesPerRun or a failed create are retried on the next run', async () => {
    const created: string[] = [];
    let failNext = false;
    http.responder = (req) => {
      if (req.method === 'GET') return { status: 200, body: JSON.stringify(created.map((b) => ({ body: b }))) };
      if (failNext) {
        failNext = false;
        return { status: 502 };
      }
      created.push((JSON.parse(req.body) as { body: string }).body);
      return { status: 201, body: '{}' };
    };
    const resolved = await project({ github: { enabled: true, apiUrl: http.url('/'), repository: 'acme/shop', token: '${GH_TOKEN}', maxIssuesPerRun: 2 } });
    const env = { GH_TOKEN: 'ghp_test' };
    const fs = [finding(1), finding(2), finding(3), finding(4), finding(5)];
    const first = await sendAlerts(resolved, report(fs), { env, retryDelayMs: 1 });
    expect(first.results[0]).toMatchObject({ channel: 'github', ok: true, delivered: 2, pending: 3 });

    failNext = true;
    const second = await sendAlerts(resolved, report(fs), { env, retryDelayMs: 1 });
    // The create failed: nothing new delivered, the failure is visible, and nothing is lost.
    expect(second.results[0]).toMatchObject({ channel: 'github', ok: false, pending: 3 });

    const third = await sendAlerts(resolved, report(fs), { env, retryDelayMs: 1 });
    expect(third.results[0]).toMatchObject({ ok: true, delivered: 2, pending: 1 });
    const fourth = await sendAlerts(resolved, report(fs), { env, retryDelayMs: 1 });
    expect(fourth.results[0]).toMatchObject({ ok: true, delivered: 1, pending: 0 });
    expect(new Set(created).size).toBe(5);
    expect(created).toHaveLength(5);
  });

  it('migrates version 1 state: findings alerted before count as delivered to every channel', async () => {
    const resolved = await project({ slack: SLACK, webhook: { enabled: true, url: '${HOOK_URL}', allowInsecureHttp: true } });
    const fs = [finding(1), finding(2)];
    const legacy = {
      version: 1,
      findings: Object.fromEntries(fs.map((f) => [f.id, { firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:00:00Z', timesSeen: 3, severity: f.severity, lastAlertedAt: '2026-01-01T00:00:00Z', lastAlertedSeverity: f.severity }])),
    };
    await mkdir(dirname(findingStatePath(resolved.paths)), { recursive: true });
    await writeFile(findingStatePath(resolved.paths), JSON.stringify(legacy));
    const slack = fakeSlack();
    const result = await sendAlerts(resolved, report(fs), { env: { HOOK_URL: http.url('/hook') }, fetchImpl: route(slack), retryDelayMs: 1 });
    expect(result.selected).toBe(0);
    const state = await loadFindingState(resolved.paths);
    expect(state.version).toBe(2);
    const entry = state.findings[(fs[0] as Finding).id];
    expect(entry?.lastAlertedAt).toBeUndefined();
    expect(Object.keys(entry?.alerts ?? {}).sort()).toEqual(['email', 'github', 'slack', 'webhook']);
  });
});

describe('unreadable state', () => {
  it('is backed up instead of silently reset, and the next alert says the history was reset', async () => {
    const resolved = await project({ slack: SLACK });
    const path = findingStatePath(resolved.paths);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, '{"version": 1, "findings": {tru');
    const state = await loadFindingState(resolved.paths, new Date('2026-02-01T00:00:00Z'));
    expect(state.recovery?.backup).toMatch(/findings\.json\.corrupt-2026-02-01/);
    const files = await readdir(dirname(path));
    expect(files.some((f) => f.startsWith('findings.json.corrupt-'))).toBe(true);
    expect(await readFile(state.recovery?.backup as string, 'utf8')).toContain('{tru');
    // The replacement keeps the recovery marker, whoever loads it next.
    expect((await loadFindingState(resolved.paths)).recovery).toBeDefined();

    const slack = fakeSlack();
    const fs = Array.from({ length: 40 }, (_, i) => finding(i + 1));
    const first = await sendAlerts(resolved, report(fs), { fetchImpl: slack.fetchImpl, retryDelayMs: 1 });
    // One bounded message, with the notice.
    expect(slack.bodies).toHaveLength(1);
    expect(first.results[0]?.delivered).toBeLessThanOrEqual(20);
    expect(JSON.stringify(slack.bodies[0])).toMatch(/alert history was reset/);
    expect((await loadFindingState(resolved.paths)).recovery).toBeUndefined();
    await sendAlerts(resolved, report(fs), { fetchImpl: slack.fetchImpl, retryDelayMs: 1 });
    expect(JSON.stringify(slack.bodies[1])).not.toMatch(/alert history was reset/);
  });

  it('does not treat I/O errors as corruption', async () => {
    const resolved = await project({});
    const path = findingStatePath(resolved.paths);
    await mkdir(path, { recursive: true }); // a directory where the file should be: EISDIR
    await expect(loadFindingState(resolved.paths)).rejects.toThrow(/Cannot read finding state/);
  });
});

describe('Slack limits', () => {
  it('caps rendered findings to Slack limits and marks only rendered findings delivered', async () => {
    const resolved = await project({ slack: SLACK, maxFindingsPerAlert: 100 });
    const slack = fakeSlack();
    const fs = Array.from({ length: 60 }, (_, i) => finding(i + 1, { reason: 'r'.repeat(2000) }));
    const first = await sendAlerts(resolved, report(fs), { fetchImpl: slack.fetchImpl, retryDelayMs: 1 });
    const body = slack.bodies[0];
    expect(body?.blocks.length).toBeLessThanOrEqual(SLACK_LIMITS.blocks);
    for (const b of body?.blocks ?? []) expect((b.text?.text ?? '').length).toBeLessThanOrEqual(SLACK_LIMITS.sectionText);
    const listed = (body?.blocks ?? []).filter((b) => b.type === 'divider').length;
    expect(listed).toBeGreaterThan(0);
    expect(first.results[0]).toMatchObject({ ok: true, delivered: listed, pending: 60 - listed });
    expect(JSON.stringify(body)).toContain(`${60 - listed} more finding(s)`);
    // Most severe first.
    expect(JSON.stringify(body?.blocks[3])).toMatch(/CRITICAL/);

    let total = listed;
    for (let run = 0; run < 10 && total < 60; run++) {
      const next = await sendAlerts(resolved, report(fs), { fetchImpl: slack.fetchImpl, retryDelayMs: 1 });
      total += next.results[0]?.delivered ?? 0;
    }
    expect(total).toBe(60);
  });

  it('renders findings of unknown kinds without missing details', () => {
    const odd = { id: 'TS-00000000abcd', kind: 'page-failed', title: '', site: 'shop', severity: 'high', detectedAt: 'x' } as unknown as Finding;
    const payload = buildAlertPayload(report([odd]), [odd], { maxFindings: 10, reportLocation: 'r' });
    expect(payload.findings[0]).toMatchObject({ title: 'page-failed', pages: [], evidence: [] });
    expect(slackMessage(payload).rendered).toEqual(['TS-00000000abcd']);
    expect(emailText(payload)).toContain('page-failed');
    expect(emailHtml(payload)).toContain('page-failed');
    expect(issueBody(toAlertFinding(odd), payload)).toContain('<!-- thirdsentry-finding: TS-00000000abcd -->');
  });
});

describe('other payload limits', () => {
  it('keeps GitHub issue bodies under the 65,536 character limit and keeps the marker', () => {
    const f = finding(7, { reason: 'x'.repeat(100_000), pages: Array.from({ length: 2000 }, (_, i) => `/page/${i}`) });
    const payload = buildAlertPayload(report([f]), [f], { maxFindings: 10, reportLocation: 'r' });
    const body = issueBody(payload.findings[0] as never, payload);
    expect(body.length).toBeLessThanOrEqual(GITHUB_MAX_BODY_CHARS);
    expect(body.startsWith(`<!-- thirdsentry-finding: ${f.id} -->`)).toBe(true);
    expect(body).toMatch(/truncated/);
  });
});

describe('retries', () => {
  it('does not retry configuration or authentication errors', () => {
    expect(isRetryable(new ConfigError('missing env'))).toBe(false);
    expect(isRetryable(new Error('boom'))).toBe(false);
    expect(isRetryable(new AlertDeliveryError('503'))).toBe(true);
    expect(isRetryableSmtpError(Object.assign(new Error('Invalid login'), { code: 'EAUTH', responseCode: 535 }))).toBe(false);
    expect(isRetryableSmtpError(Object.assign(new Error('Greylisted'), { responseCode: 451 }))).toBe(true);
    expect(isRetryableSmtpError(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }))).toBe(true);
  });

  it('attempts SMTP authentication only once when the server rejects the credentials', async () => {
    let authAttempts = 0;
    const server = net.createServer((socket) => {
      socket.write('220 auth.mock ESMTP\r\n');
      let buffer = '';
      socket.on('data', (chunk: Buffer) => {
        buffer += chunk.toString();
        let nl: number;
        while ((nl = buffer.indexOf('\r\n')) >= 0) {
          const line = buffer.slice(0, nl);
          buffer = buffer.slice(nl + 2);
          const cmd = line.slice(0, 4).toUpperCase();
          if (cmd === 'EHLO') socket.write('250-auth.mock\r\n250 AUTH PLAIN LOGIN\r\n');
          else if (cmd === 'AUTH') {
            authAttempts++;
            socket.write('535 5.7.8 Authentication credentials invalid\r\n');
          } else if (cmd === 'QUIT') socket.end('221 bye\r\n');
          else socket.write('250 OK\r\n');
        }
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    try {
      const port = (server.address() as AddressInfo).port;
      const resolved = await project({
        retries: 3,
        email: { enabled: true, host: '127.0.0.1', port, from: 'ts@example.com', to: 'sec@example.com', requireTLS: false, username: 'user', password: '${SMTP_PASS}' },
      });
      const result = await sendAlerts(resolved, report([finding(1)]), { env: { SMTP_PASS: 'wrong-password' }, retryDelayMs: 1 });
      expect(result.results[0]).toMatchObject({ channel: 'email', ok: false, attempts: 1 });
      expect(result.results[0]?.error).toMatch(/EAUTH/);
      expect(result.results[0]?.error).not.toContain('wrong-password');
      expect(authAttempts).toBe(1);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});

describe('report location', () => {
  it('a configured reportUrl wins over the local report path passed by scan', async () => {
    const resolved = await project({ slack: SLACK, reportUrl: '${REPORT_URL}' });
    const slack = fakeSlack();
    const result = await sendAlerts(resolved, report([finding(1)]), { env: { REPORT_URL: 'https://ci.example/runs/42' }, fetchImpl: slack.fetchImpl, reportLocation: '/home/runner/work/x/report.html', retryDelayMs: 1 });
    expect(result.payload?.reportLocation).toBe('https://ci.example/runs/42');
    expect(JSON.stringify(slack.bodies[0])).not.toContain('/home/runner');
  });

  it('falls back to the local path when reportUrl references an unset variable (the alert is still sent)', async () => {
    const resolved = await project({ slack: SLACK, reportUrl: '${REPORT_URL}' });
    const slack = fakeSlack();
    const result = await sendAlerts(resolved, report([finding(1)]), { env: {}, fetchImpl: slack.fetchImpl, reportLocation: '/tmp/report.html', retryDelayMs: 1 });
    expect(result.payload?.reportLocation).toBe('/tmp/report.html');
    expect(result.results[0]?.ok).toBe(true);
  });
});

describe('e-mail recipients', () => {
  it('parses display names containing commas', async () => {
    expect(parseRecipients(['"Doe, John" <john@example.com>, ops@example.com'])).toEqual([
      { name: 'Doe, John', address: 'john@example.com' },
      { name: '', address: 'ops@example.com' },
    ]);
    expect(() => parseRecipients(['Broken <>'])).toThrow(/invalid address/);

    const resolved = await project({ email: { enabled: true, host: '127.0.0.1', port: smtp.port, from: 'ts@example.com', to: '${SMTP_TO}', requireTLS: false } });
    const result = await sendAlerts(resolved, report([finding(1)]), { env: { SMTP_TO: '"Doe, John" <john@example.com>' }, retryDelayMs: 1 });
    expect(result.results[0]).toMatchObject({ channel: 'email', ok: true });
    expect(smtp.messages[0]?.to).toEqual(['RCPT TO:<john@example.com>']);
  });
});

describe('alert command output', () => {
  it('says that no channel is enabled instead of "0 findings would be sent"', async () => {
    const resolved = await project({});
    const result = await sendAlerts(resolved, report([finding(1)]), { dryRun: true });
    const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      printAlertResult(result);
      const out = write.mock.calls.map((c) => String(c[0])).join('');
      expect(out).toMatch(/no alert channel is enabled/);
      expect(out).not.toMatch(/0 finding\(s\) would be sent/);
    } finally {
      write.mockRestore();
    }
  });
});

describe('alert --test', () => {
  it('sends a labelled synthetic alert through each enabled channel without touching state', async () => {
    const resolved = await project({ slack: SLACK, webhook: { enabled: true, url: '${HOOK_URL}', allowInsecureHttp: true } });
    const slack = fakeSlack();
    const fetchImpl = route(slack);
    const result = await sendAlerts(resolved, undefined, { test: true, env: { HOOK_URL: http.url('/hook') }, fetchImpl, retryDelayMs: 1 });
    expect(result.test).toBe(true);
    expect(result.results.map((r) => [r.channel, r.ok])).toEqual([
      ['slack', true],
      ['webhook', true],
    ]);
    expect(JSON.stringify(slack.bodies[0])).toMatch(/TEST alert/);
    expect(http.requests[0]?.headers['x-thirdsentry-event']).toBe('test');
    expect(JSON.parse(http.requests[0]?.body ?? '{}')).toMatchObject({ test: true });
    const state = await loadFindingState(resolved.paths);
    expect(state.findings).toEqual({});
    await expect(readdir(resolved.paths.state)).rejects.toThrow();
  });
});

describe('sendHttp', () => {
  function endless(status: number): FetchLike {
    return (() => {
      let sent = 0;
      const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
          sent += 64 * 1024;
          controller.enqueue(new Uint8Array(64 * 1024).fill(120));
          if (sent > 200 * 1024 * 1024) controller.close(); // safety net for the test itself
        },
      });
      return Promise.resolve(new Response(stream, { status }));
    });
  }

  it('bounds the response body while streaming instead of reading it all', async () => {
    const ok = await sendHttp({ url: 'https://x.example/', timeoutMs: 5000 }, endless(200));
    expect(ok.truncated).toBe(true);
    expect(ok.text.length).toBe(10 * 1024 * 1024);
    const failed = await sendHttp({ url: 'https://x.example/', timeoutMs: 5000 }, endless(500)).catch((e: unknown) => e as AlertDeliveryError);
    expect(failed).toBeInstanceOf(AlertDeliveryError);
    expect((failed as AlertDeliveryError).message.length).toBeLessThan(300);
  });
});
