import { describe, expect, it } from 'vitest';
import { checkIpAddress, embeddedIpv4, isPublicIp } from '../../src/security/ip-policy.js';
import { NetworkPolicy } from '../../src/security/network-policy.js';

describe('ip-policy', () => {
  it.each([
    ['127.0.0.1', 'loopback'],
    ['127.255.0.9', 'loopback'],
    ['10.1.2.3', 'private'],
    ['172.16.0.1', 'private'],
    ['172.31.255.255', 'private'],
    ['192.168.1.1', 'private'],
    ['169.254.169.254', 'cloud-metadata'],
    ['169.254.170.2', 'cloud-metadata'],
    ['100.100.100.200', 'cloud-metadata'],
    ['192.0.0.192', 'cloud-metadata'],
    ['169.254.10.10', 'link-local'],
    ['100.64.0.1', 'carrier-grade-nat'],
    ['0.0.0.0', 'unspecified'],
    ['224.0.0.1', 'multicast'],
    ['255.255.255.255', 'reserved'],
    ['198.18.0.1', 'reserved'],
  ])('blocks IPv4 %s (%s)', (ip, reason) => {
    const r = checkIpAddress(ip);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe(reason);
  });

  it.each(['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '11.0.0.1'])('allows public IPv4 %s', (ip) => {
    expect(isPublicIp(ip)).toBe(true);
  });

  it.each([
    ['::1', 'loopback'],
    ['::', 'unspecified'],
    ['fe80::1', 'link-local'],
    ['fe80::1%eth0', 'link-local'],
    ['fc00::1', 'private'],
    ['fd12:3456::1', 'private'],
    ['fd00:ec2::254', 'cloud-metadata'],
    ['ff02::1', 'multicast'],
    ['2001:db8::1', 'documentation'],
  ])('blocks IPv6 %s (%s)', (ip, reason) => {
    const r = checkIpAddress(ip);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe(reason);
  });

  it('allows public IPv6', () => {
    expect(isPublicIp('2606:4700:4700::1111')).toBe(true);
    expect(isPublicIp('2a00:1450:4001:81b::200e')).toBe(true);
  });

  it.each([
    ['::ffff:127.0.0.1', '127.0.0.1'],
    ['::ffff:7f00:1', '127.0.0.1'],
    ['::ffff:169.254.169.254', '169.254.169.254'],
    ['64:ff9b::a9fe:a9fe', '169.254.169.254'],
    ['2002:7f00:0001::', '127.0.0.1'],
    ['::ffff:0:a00:1', '10.0.0.1'],
  ])('evaluates IPv4 embedded in IPv6 %s', (ip, v4) => {
    expect(embeddedIpv4(ip)).toBe(v4);
    expect(checkIpAddress(ip).allowed).toBe(false);
  });

  it('allows IPv6-mapped public IPv4', () => {
    expect(checkIpAddress('::ffff:8.8.8.8').allowed).toBe(true);
  });

  it('rejects invalid addresses', () => {
    expect(checkIpAddress('not-an-ip').allowed).toBe(false);
    expect(checkIpAddress('999.1.1.1').reason).toBe('invalid');
  });

  it.each([
    ['168.63.129.16', 'cloud-metadata'], // Azure WireServer (publicly routable range)
    ['169.254.170.23', 'cloud-metadata'], // EKS Pod Identity agent
    ['fd00:ec2::23', 'cloud-metadata'],
    ['::ffff:168.63.129.16', 'cloud-metadata'],
  ])('treats %s as a cloud metadata endpoint', (ip, reason) => {
    const r = checkIpAddress(ip);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe(reason);
  });

  it('never unlocks the new metadata endpoints through allowedPrivateHosts', async () => {
    const policy = new NetworkPolicy({
      allowedPorts: [80],
      allowedPrivateHosts: ['internal.test', 'pod.test'],
      blockedHosts: [],
      resolverOverrides: { 'internal.test': '168.63.129.16', 'pod.test': '169.254.170.23' },
    });
    expect((await policy.resolveDestination('internal.test', 80)).allowed).toBe(false);
    expect((await policy.resolveDestination('pod.test', 80)).allowed).toBe(false);
  });

  it.each([
    ['3fff::1', 'documentation'], // RFC 9637 documentation range
    ['3fff:fff::1', 'documentation'],
    ['5f00::1', 'reserved'], // SRv6 SIDs, outside 2000::/3
    ['4000::1', 'reserved'],
    ['1000::1', 'reserved'],
    ['e000::1', 'reserved'],
    ['2001:2::1', 'reserved'], // benchmarking
  ])('blocks IPv6 outside global unicast or in special ranges: %s', (ip, reason) => {
    const r = checkIpAddress(ip);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe(reason);
  });

  it('still allows global unicast IPv6 and NAT64 of public IPv4', () => {
    expect(isPublicIp('2001:4860:4860::8888')).toBe(true);
    expect(isPublicIp('2a03:2880:f12f::1')).toBe(true);
    expect(isPublicIp('64:ff9b::1.1.1.1')).toBe(true);
  });
});
