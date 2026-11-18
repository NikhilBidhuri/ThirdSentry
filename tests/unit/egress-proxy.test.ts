import http from 'node:http';
import net, { type AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EgressProxy, parseAuthority } from '../../src/security/egress-proxy.js';
import { NetworkPolicy } from '../../src/security/network-policy.js';

let upstream: http.Server;
let upstreamPort = 0;
let proxy: EgressProxy;
let proxyPort = 0;

beforeAll(async () => {
  upstream = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(req.url === '/big' ? 'x'.repeat(2 * 1024 * 1024) : `hello ${req.headers.host ?? ''}`);
  });
  await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
  upstreamPort = (upstream.address() as AddressInfo).port;
  proxy = new EgressProxy({
    policy: new NetworkPolicy({
      allowedPorts: [upstreamPort],
      allowedPrivateHosts: ['allowed.test'],
      blockedHosts: [],
      resolverOverrides: { 'allowed.test': '127.0.0.1', 'internal.test': '127.0.0.1', 'meta.test': '169.254.169.254' },
    }),
    maxBytesPerConnection: 1024 * 1024,
    connectTimeoutMs: 2000,
    idleTimeoutMs: 5000,
    maxConnections: 50,
    maxRecordedEvents: 100,
  });
  proxyPort = (await proxy.start()).port;
});

afterAll(async () => {
  await proxy.stop();
  await new Promise<void>((r) => upstream.close(() => r()));
});

function proxiedGet(url: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: proxyPort, path: url, method: 'GET', headers: { host: new URL(url).host } }, (res) => {
      let body = '';
      res.on('data', (c: Buffer) => (body += c.toString()));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
}

function connect(authority: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, '127.0.0.1', () => {
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
    });
    let data = '';
    socket.on('data', (c: Buffer) => {
      data += c.toString();
      if (data.includes('\r\n\r\n')) {
        socket.destroy();
        resolve(data.split('\r\n')[0] ?? '');
      }
    });
    socket.on('error', reject);
  });
}

describe('EgressProxy', () => {
  it('forwards plain HTTP to allowed hosts using the validated address', async () => {
    const res = await proxiedGet(`http://allowed.test:${upstreamPort}/`);
    expect(res.status).toBe(200);
    expect(res.body).toBe(`hello allowed.test:${upstreamPort}`);
  });

  it('blocks plain HTTP to hosts resolving to private addresses', async () => {
    const res = await proxiedGet(`http://internal.test:${upstreamPort}/`);
    expect(res.status).toBe(403);
  });

  it('blocks metadata addresses even via overrides', async () => {
    expect((await proxiedGet(`http://meta.test:${upstreamPort}/`)).status).toBe(403);
  });

  it('allows CONNECT tunnels to allowed destinations', async () => {
    expect(await connect(`allowed.test:${upstreamPort}`)).toContain('200');
  });

  it('refuses CONNECT to private IP literals and disallowed ports', async () => {
    expect(await connect(`127.0.0.1:${upstreamPort}`)).toContain('403');
    expect(await connect('allowed.test:22')).toContain('403');
    expect(await connect('[::1]:443')).toContain('403');
  });

  it('cuts connections that exceed the byte limit', async () => {
    const res = await proxiedGet(`http://allowed.test:${upstreamPort}/big`).catch(() => ({ status: -1, body: '' }));
    expect(res.body.length).toBeLessThan(2 * 1024 * 1024);
  });

  it('records allowed and blocked connection events', () => {
    const { events } = proxy.getEvents();
    expect(events.some((e) => e.host === 'internal.test' && !e.allowed)).toBe(true);
    expect(events.some((e) => e.host === 'allowed.test' && e.allowed)).toBe(true);
  });

  it('parses CONNECT authorities', () => {
    expect(parseAuthority('example.com:443')).toEqual({ host: 'example.com', port: 443 });
    expect(parseAuthority('[2001:db8::1]:443')).toEqual({ host: '2001:db8::1', port: 443 });
    expect(parseAuthority('example.com')).toBeUndefined();
    expect(parseAuthority('a:99999')).toBeUndefined();
  });
});
