import { BlockList, isIP, isIPv4 } from 'node:net';

/**
 * IP address policy used by every network path that ThirdSentry controls
 * (browser egress proxy, CSP fetcher). Any address that is not a globally
 * routable unicast address is rejected unless explicitly allowed.
 */

export type IpBlockReason =
  | 'loopback'
  | 'private'
  | 'link-local'
  | 'cloud-metadata'
  | 'carrier-grade-nat'
  | 'multicast'
  | 'reserved'
  | 'unspecified'
  | 'documentation'
  | 'invalid';

interface Range {
  readonly cidr: string;
  readonly reason: IpBlockReason;
}

const IPV4_RANGES: readonly Range[] = [
  { cidr: '0.0.0.0/8', reason: 'unspecified' },
  { cidr: '10.0.0.0/8', reason: 'private' },
  { cidr: '100.100.100.200/32', reason: 'cloud-metadata' }, // Alibaba Cloud
  { cidr: '100.64.0.0/10', reason: 'carrier-grade-nat' },
  { cidr: '127.0.0.0/8', reason: 'loopback' },
  { cidr: '169.254.169.254/32', reason: 'cloud-metadata' }, // AWS, GCP, Azure, OpenStack
  { cidr: '169.254.170.2/32', reason: 'cloud-metadata' }, // AWS ECS task metadata
  { cidr: '169.254.170.23/32', reason: 'cloud-metadata' }, // AWS EKS Pod Identity agent
  { cidr: '168.63.129.16/32', reason: 'cloud-metadata' }, // Azure WireServer / host agent (a public address)
  { cidr: '169.254.0.0/16', reason: 'link-local' },
  { cidr: '172.16.0.0/12', reason: 'private' },
  { cidr: '192.0.0.192/32', reason: 'cloud-metadata' }, // Oracle Cloud
  { cidr: '192.0.0.0/24', reason: 'reserved' },
  { cidr: '192.0.2.0/24', reason: 'documentation' },
  { cidr: '192.88.99.0/24', reason: 'reserved' },
  { cidr: '192.168.0.0/16', reason: 'private' },
  { cidr: '198.18.0.0/15', reason: 'reserved' },
  { cidr: '198.51.100.0/24', reason: 'documentation' },
  { cidr: '203.0.113.0/24', reason: 'documentation' },
  { cidr: '224.0.0.0/4', reason: 'multicast' },
  { cidr: '240.0.0.0/4', reason: 'reserved' },
];

const IPV6_RANGES: readonly Range[] = [
  { cidr: '::1/128', reason: 'loopback' },
  { cidr: '::/128', reason: 'unspecified' },
  { cidr: 'fd00:ec2::254/128', reason: 'cloud-metadata' }, // AWS IMDS over IPv6
  { cidr: 'fd00:ec2::23/128', reason: 'cloud-metadata' }, // AWS EKS Pod Identity agent over IPv6
  { cidr: 'fc00::/7', reason: 'private' },
  { cidr: 'fe80::/10', reason: 'link-local' },
  { cidr: 'fec0::/10', reason: 'private' }, // deprecated site-local
  { cidr: 'ff00::/8', reason: 'multicast' },
  { cidr: '100::/64', reason: 'reserved' }, // discard-only
  { cidr: '2001:db8::/32', reason: 'documentation' },
  { cidr: '2001:10::/28', reason: 'reserved' },
  { cidr: '2001:20::/28', reason: 'reserved' },
  { cidr: '2001::/32', reason: 'reserved' }, // Teredo tunnelling (embeds arbitrary IPv4)
  { cidr: '2001:2::/48', reason: 'reserved' }, // benchmarking
  { cidr: '3fff::/20', reason: 'documentation' }, // RFC 9637
  { cidr: '::/96', reason: 'reserved' }, // deprecated IPv4-compatible
];

function buildList(ranges: readonly Range[], family: 'ipv4' | 'ipv6'): Array<{ list: BlockList; reason: IpBlockReason }> {
  return ranges.map((range) => {
    const list = new BlockList();
    const [addr, prefix] = range.cidr.split('/') as [string, string];
    list.addSubnet(addr, Number(prefix), family);
    return { list, reason: range.reason };
  });
}

const V4 = buildList(IPV4_RANGES, 'ipv4');
const V6 = buildList(IPV6_RANGES, 'ipv6');

/**
 * IPv6 is allowlisted: only global unicast (2000::/3) is routable on the
 * internet. Everything outside it (e.g. SRv6 SIDs 5f00::/16, unassigned
 * space) is refused even when no specific range above matches.
 */
const IPV6_GLOBAL_UNICAST = new BlockList();
IPV6_GLOBAL_UNICAST.addSubnet('2000::', 3, 'ipv6');

export interface IpCheckResult {
  readonly allowed: boolean;
  readonly address: string;
  readonly family: 4 | 6 | 0;
  readonly reason?: IpBlockReason;
  /** For IPv6 addresses embedding an IPv4 address, the embedded address that was evaluated. */
  readonly embeddedIpv4?: string;
}

function stripZone(address: string): string {
  const zone = address.indexOf('%');
  return zone >= 0 ? address.slice(0, zone) : address;
}

/** Expand an IPv6 address to 8 groups of 16-bit numbers. Returns undefined when invalid. */
export function ipv6Groups(address: string): number[] | undefined {
  let addr = stripZone(address.toLowerCase());
  const lastColon = addr.lastIndexOf(':');
  const tail = addr.slice(lastColon + 1);
  if (tail.includes('.')) {
    if (!isIPv4(tail)) return undefined;
    const octets = tail.split('.').map(Number) as [number, number, number, number];
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    addr = `${addr.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const parts = addr.split('::');
  if (parts.length > 2) return undefined;
  const head = parts[0] ? parts[0].split(':') : [];
  const rest = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - head.length - rest.length;
  if (parts.length === 1 && missing !== 0) return undefined;
  if (parts.length === 2 && missing < 1) return undefined;
  const filler: string[] = parts.length === 2 ? new Array<string>(missing).fill('0') : [];
  const groups = [...head, ...filler, ...rest].map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? Number.parseInt(g, 16) : NaN));
  if (groups.length !== 8 || groups.some((g) => Number.isNaN(g))) return undefined;
  return groups;
}

function groupsToIpv4(hi: number, lo: number): string {
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}

/**
 * Extract an IPv4 address embedded in an IPv6 address using one of the
 * well-known translation/tunnelling schemes that can be abused to reach
 * IPv4-only internal hosts.
 */
export function embeddedIpv4(address: string): string | undefined {
  const g = ipv6Groups(address);
  if (!g) return undefined;
  const [g0, g1, g2, g3, g4, g5, g6, g7] = g as [number, number, number, number, number, number, number, number];
  // IPv4-mapped ::ffff:a.b.c.d
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff) return groupsToIpv4(g6, g7);
  // IPv4-translated ::ffff:0:a.b.c.d
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0xffff && g5 === 0) return groupsToIpv4(g6, g7);
  // NAT64 well-known prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48
  if (g0 === 0x64 && g1 === 0xff9b && (g2 === 0 || g2 === 1)) return groupsToIpv4(g6, g7);
  // 6to4 2002:aabb:ccdd::/48
  if (g0 === 0x2002) return groupsToIpv4(g1, g2);
  return undefined;
}

function checkV4(address: string): IpBlockReason | undefined {
  for (const entry of V4) if (entry.list.check(address, 'ipv4')) return entry.reason;
  return undefined;
}

function checkV6(address: string): IpBlockReason | undefined {
  const bare = stripZone(address);
  for (const entry of V6) if (entry.list.check(bare, 'ipv6')) return entry.reason;
  if (!IPV6_GLOBAL_UNICAST.check(bare, 'ipv6')) return 'reserved';
  return undefined;
}

/** Decide whether a resolved IP address is a public, globally routable destination. */
export function checkIpAddress(address: string): IpCheckResult {
  const bare = stripZone(address);
  const family = isIP(bare);
  if (family === 4) {
    const reason = checkV4(bare);
    return reason ? { allowed: false, address, family: 4, reason } : { allowed: true, address, family: 4 };
  }
  if (family === 6) {
    const embedded = embeddedIpv4(bare);
    if (embedded) {
      const reason = checkV4(embedded);
      return reason
        ? { allowed: false, address, family: 6, reason, embeddedIpv4: embedded }
        : { allowed: true, address, family: 6, embeddedIpv4: embedded };
    }
    const reason = checkV6(bare);
    return reason ? { allowed: false, address, family: 6, reason } : { allowed: true, address, family: 6 };
  }
  return { allowed: false, address, family: 0, reason: 'invalid' };
}

export function isPublicIp(address: string): boolean {
  return checkIpAddress(address).allowed;
}
