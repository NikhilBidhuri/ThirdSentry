import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { EgressProxy, formatClientTag, parseClientTag, type EgressProxyOptions } from '../../src/security/egress-proxy.js';
import { NetworkPolicy } from '../../src/security/network-policy.js';
import { applyTrustedProxyEvents, ProxyEventLogWriter, readProxyEventLog } from '../../src/security/proxy-event-log.js';
import type { ScanEvidence } from '../../src/types/evidence.js';

const cleanups: Array<() => Promise<void> | void> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()?.();
});

async function rawUpstream(response: string): Promise<number> {
  const server = net.createServer((s) => {
    s.on('error', () => undefined);
    s.once('data', () => s.end(response, 'latin1'));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  cleanups.push(() => new Promise<void>((r) => server.close(() => r())));
  return (server.address() as AddressInfo).port;
}

function makeProxy(port: number, extra: Partial<EgressProxyOptions> = {}): EgressProxy {
  const proxy = new EgressProxy({
    policy: new NetworkPolicy({
      allowedPorts: [port],
      allowedPrivateHosts: ['up.test'],
      blockedHosts: [],
      resolverOverrides: { 'up.test': '127.0.0.1', 'meta.test': '169.254.169.254' },
    }),
    maxBytesPerConnection: 1_000_000,
    connectTimeoutMs: 2000,
    idleTimeoutMs: 2000,
    maxConnections: 20,
    maxRecordedEvents: 100,
    ...extra,
  });
  cleanups.push(() => proxy.stop());
  return proxy;
}

function rawGet(proxyPort: number, url: string, headers = ''): Promise<string> {
  return new Promise((resolve) => {
    const c = net.connect(proxyPort, '127.0.0.1', () => c.write(`GET ${url} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n${headers}\r\n`));
    let data = '';
    c.on('data', (d: Buffer) => (data += d.toString('latin1')));
    c.on('close', () => resolve(data));
    c.on('error', () => resolve(data));
    setTimeout(() => {
      c.destroy();
      resolve(`TIMEOUT:${data}`);
    }, 4000);
  });
}

describe('EgressProxy survives hostile upstream responses', () => {
  const cases: Record<string, { response: string; status: string }> = {
    'status 099': { response: 'HTTP/1.1 099 X\r\nContent-Length: 2\r\n\r\nok', status: '502' },
    'status 999': { response: 'HTTP/1.1 999 X\r\nContent-Length: 2\r\n\r\nok', status: '502' },
    'control char in reason phrase': { response: 'HTTP/1.1 200 O\x01K\r\nContent-Length: 2\r\n\r\nok', status: '' },
    'latin1 reason phrase': { response: 'HTTP/1.1 200 \xe9\xe9\r\nContent-Length: 2\r\n\r\nok', status: '' },
    'invalid header value': { response: 'HTTP/1.1 200 OK\r\nX-Evil: a\x01b\r\nContent-Length: 2\r\n\r\nok', status: '' },
    '101 upgrade': { response: 'HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: Upgrade\r\n\r\nhello', status: '502' },
  };
  for (const [name, { response, status }] of Object.entries(cases)) {
    it(`does not crash on ${name} and keeps serving`, async () => {
      const upPort = await rawUpstream(response);
      const proxy = makeProxy(upPort);
      const { port } = await proxy.start();
      let uncaught: unknown;
      const onUncaught = (e: unknown): void => {
        uncaught = e;
      };
      process.on('uncaughtException', onUncaught);
      cleanups.push(() => void process.off('uncaughtException', onUncaught));
      const out = await rawGet(port, `http://up.test:${upPort}/`);
      expect(out.startsWith('TIMEOUT')).toBe(false);
      if (status) expect(out.split('\r\n')[0]).toContain(status);
      expect(uncaught).toBeUndefined();
      const again = await rawGet(port, 'http://meta.test:1/');
      expect(again.split('\r\n')[0]).toContain('403');
    });
  }
});

describe('EgressProxy event accounting', () => {
  it('caps events per site, not globally, and reports dropped counts per site', async () => {
    const upstream = http.createServer((_q, r) => r.end('ok'));
    await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
    cleanups.push(() => new Promise<void>((r) => upstream.close(() => r())));
    const upPort = (upstream.address() as AddressInfo).port;
    const proxy = makeProxy(upPort, { maxRecordedEvents: 3 });
    const { port } = await proxy.start();
    const tagA = `Proxy-Authorization: ${formatClientTag({ runId: 'r1', site: 'a' })}\r\n`;
    const tagB = `Proxy-Authorization: ${formatClientTag({ runId: 'r1', site: 'b' })}\r\n`;
    for (let i = 0; i < 5; i++) await rawGet(port, `http://up.test:${upPort}/`, tagA);
    await rawGet(port, `http://up.test:${upPort}/`, tagB);
    await rawGet(port, 'http://meta.test:1/', tagB);
    const a = proxy.drainEvents({ runId: 'r1', site: 'a' });
    const b = proxy.drainEvents({ runId: 'r1', site: 'b' });
    expect(a.events).toHaveLength(3);
    expect(a.dropped).toBe(2);
    expect(b.dropped).toBe(0);
    expect(b.events.map((e) => e.allowed)).toEqual([false, true]);
  });

  it('rejects malformed tags and keeps well-formed ones', () => {
    expect(parseClientTag(formatClientTag({ runId: 'run-1', site: 'shop.example' }))).toEqual({ runId: 'run-1', site: 'shop.example' });
    expect(parseClientTag(`Basic ${Buffer.from('no-dot:x').toString('base64')}`)).toBeUndefined();
    expect(parseClientTag(`Basic ${Buffer.from('a/b.c:x').toString('base64')}`)).toBeUndefined();
    expect(() => formatClientTag({ runId: '../x', site: 's' })).toThrow();
  });

  it('writes tagged events to the trusted log and the analyzer applies them over scanner-reported ones', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ts-events-'));
    cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
    const writer = new ProxyEventLogWriter({ dir });
    writer.init();
    const proxy = makeProxy(1, { eventSink: writer });
    const { port } = await proxy.start();
    const tag = `Proxy-Authorization: ${formatClientTag({ runId: 'run1', site: 'shop' })}\r\n`;
    expect((await rawGet(port, 'http://meta.test:1/', tag)).split('\r\n')[0]).toContain('403');
    await rawGet(port, 'http://meta.test:1/');
    const file = join(dir, 'run1.ndjson');
    expect(readFileSync(file, 'utf8').trim().split('\n')).toHaveLength(1);
    const trusted = await readProxyEventLog(file, 1_000_000);
    const evidence = {
      issues: [],
      sites: [
        { name: 'shop', issues: [], pages: [], proxyEvents: [{ timestamp: 't', host: 'forged', port: 1, method: 'GET', allowed: true }], proxyEventsDropped: 0 },
        { name: 'other', issues: [], pages: [], proxyEvents: [], proxyEventsDropped: 0 },
      ],
    } as unknown as ScanEvidence;
    const out = applyTrustedProxyEvents(evidence, trusted);
    expect(out.sites[0]?.proxyEvents).toHaveLength(1);
    expect(out.sites[0]?.proxyEvents[0]).toMatchObject({ host: 'meta.test', allowed: false });
    expect(out.sites[1]?.proxyEvents).toEqual([]);
    const missing = applyTrustedProxyEvents(evidence, await readProxyEventLog(join(dir, 'nope.ndjson'), 1000));
    expect(missing.issues.some((i) => i.code === 'proxy-events-missing')).toBe(true);
  });
});

describe('NetworkPolicy DNS timeout', () => {
  it('refuses the destination when DNS does not answer in time', async () => {
    const policy = new NetworkPolicy(
      { allowedPorts: [80], allowedPrivateHosts: [], blockedHosts: [], resolverOverrides: {}, dnsTimeoutMs: 50 },
      () => new Promise(() => undefined),
    );
    const d = await policy.resolveDestination('hang.example.com', 80);
    expect(d.allowed).toBe(false);
  });
});
