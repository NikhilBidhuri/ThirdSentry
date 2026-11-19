import { describe, expect, it } from 'vitest';
import { NetworkPolicy, type Resolver } from '../../src/security/network-policy.js';

const base = { allowedPorts: [80, 443], allowedPrivateHosts: [], blockedHosts: [], resolverOverrides: {} };

function resolverFrom(map: Record<string, string[]>): Resolver {
  return (host) => {
    const addrs = map[host];
    if (!addrs) return Promise.reject(Object.assign(new Error('not found'), { code: 'ENOTFOUND' }));
    return Promise.resolve(addrs.map((address) => ({ address, family: address.includes(':') ? 6 : 4 })));
  };
}

describe('NetworkPolicy', () => {
  it('returns the validated address to connect to (prevents re-resolution)', async () => {
    const policy = new NetworkPolicy(base, resolverFrom({ 'cdn.example.com': ['93.184.216.34'] }));
    const d = await policy.resolveDestination('cdn.example.com', 443);
    expect(d).toMatchObject({ allowed: true, address: '93.184.216.34', port: 443 });
  });

  it('refuses hosts resolving to private addresses (DNS rebinding target)', async () => {
    const policy = new NetworkPolicy(base, resolverFrom({ 'rebind.example.com': ['10.0.0.5'] }));
    const d = await policy.resolveDestination('rebind.example.com', 443);
    expect(d.allowed).toBe(false);
    if (!d.allowed) expect(d.code).toBe('ip-blocked');
  });

  it('refuses when ANY resolved address is private (mixed records)', async () => {
    const policy = new NetworkPolicy(base, resolverFrom({ 'mixed.example.com': ['93.184.216.34', '127.0.0.1'] }));
    expect((await policy.resolveDestination('mixed.example.com', 443)).allowed).toBe(false);
  });

  it('re-resolves on every call so a later rebinding is caught', async () => {
    let answer = '93.184.216.34';
    const policy = new NetworkPolicy(base, () => Promise.resolve([{ address: answer, family: 4 }]));
    expect((await policy.resolveDestination('flip.example.com', 443)).allowed).toBe(true);
    answer = '169.254.169.254';
    expect((await policy.resolveDestination('flip.example.com', 443)).allowed).toBe(false);
  });

  it('blocks disallowed ports', async () => {
    const policy = new NetworkPolicy(base, resolverFrom({ 'a.example.com': ['93.184.216.34'] }));
    const d = await policy.resolveDestination('a.example.com', 22);
    expect(d).toMatchObject({ allowed: false, code: 'port-not-allowed' });
  });

  it('always blocks cloud metadata hostnames', async () => {
    const policy = new NetworkPolicy({ ...base, allowedPrivateHosts: ['*'] }, resolverFrom({}));
    expect((await policy.resolveDestination('metadata.google.internal', 80)).allowed).toBe(false);
    expect((await policy.resolveDestination('METADATA.GOOGLE.INTERNAL.', 80)).allowed).toBe(false);
  });

  it('blocks localhost names', async () => {
    const policy = new NetworkPolicy(base, resolverFrom({ localhost: ['127.0.0.1'] }));
    expect((await policy.resolveDestination('localhost', 80)).allowed).toBe(false);
    expect((await policy.resolveDestination('app.localhost', 80)).allowed).toBe(false);
  });

  it('allows private addresses only for explicitly allowed hosts, never metadata', async () => {
    const policy = new NetworkPolicy(
      { ...base, allowedPrivateHosts: ['staging.internal.example'] },
      resolverFrom({ 'staging.internal.example': ['10.1.1.1'], 'other.internal.example': ['10.1.1.2'], 'evil.internal.example': ['169.254.169.254'] }),
    );
    expect((await policy.resolveDestination('staging.internal.example', 443)).allowed).toBe(true);
    expect((await policy.resolveDestination('other.internal.example', 443)).allowed).toBe(false);
    const metadata = new NetworkPolicy({ ...base, allowedPrivateHosts: ['*'] }, resolverFrom({ 'evil.internal.example': ['169.254.169.254'] }));
    expect((await metadata.resolveDestination('evil.internal.example', 80)).allowed).toBe(false);
  });

  it('validates literal IPs including IPv6-mapped loopback', async () => {
    const policy = new NetworkPolicy(base, resolverFrom({}));
    expect((await policy.resolveDestination('127.0.0.1', 80)).allowed).toBe(false);
    expect((await policy.resolveDestination('[::ffff:127.0.0.1]', 80)).allowed).toBe(false);
    expect((await policy.resolveDestination('93.184.216.34', 80)).allowed).toBe(true);
  });

  it('applies resolver overrides but still validates them', async () => {
    const policy = new NetworkPolicy({ ...base, resolverOverrides: { 'x.test': '127.0.0.1' } }, resolverFrom({}));
    expect((await policy.resolveDestination('x.test', 80)).allowed).toBe(false);
  });

  it('honours blockedHosts patterns', async () => {
    const policy = new NetworkPolicy({ ...base, blockedHosts: ['*.tracker.example'] }, resolverFrom({ 'a.tracker.example': ['93.184.216.34'] }));
    expect((await policy.resolveDestination('a.tracker.example', 443)).allowed).toBe(false);
  });

  it('reports DNS failures', async () => {
    const policy = new NetworkPolicy(base, resolverFrom({}));
    const d = await policy.resolveDestination('missing.example.com', 443);
    expect(d).toMatchObject({ allowed: false, code: 'dns-failure' });
  });
});
