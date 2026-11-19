import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { checkIpAddress, type IpBlockReason } from './ip-policy.js';
import { matchesAnyHost, normalizeHost } from '../utils/patterns.js';

/**
 * Network policy shared by the browser egress proxy and the server-side
 * fetcher (CSP linter). It decides whether a destination host:port may be
 * contacted and returns the *specific* IP address that must be used for the
 * connection. Callers must connect to that address (not re-resolve the
 * hostname) so that DNS rebinding cannot swap the destination after the check.
 */

export interface NetworkPolicyOptions {
  /** Destination TCP ports that may be contacted. */
  readonly allowedPorts: readonly number[];
  /**
   * Host patterns that are explicitly permitted to resolve to private,
   * loopback or link-local addresses (e.g. an internal staging site).
   * Cloud metadata addresses are never permitted.
   */
  readonly allowedPrivateHosts: readonly string[];
  /** Host patterns that are always refused. */
  readonly blockedHosts: readonly string[];
  /**
   * Static hostname → IP mappings. Intended for tests and for pinning
   * hosts in restricted environments. Results are still validated.
   */
  readonly resolverOverrides: Readonly<Record<string, string>>;
}

export type DestinationDecision =
  | { readonly allowed: true; readonly host: string; readonly port: number; readonly address: string; readonly family: 4 | 6 }
  | { readonly allowed: false; readonly host: string; readonly port: number; readonly reason: string; readonly code: BlockCode };

export type BlockCode =
  | 'port-not-allowed'
  | 'host-blocked'
  | 'dns-failure'
  | 'ip-blocked'
  | 'invalid-host';

/** Hostnames that point at cloud/instance metadata services or local machines. */
const ALWAYS_BLOCKED_HOSTS: readonly string[] = [
  'metadata.google.internal',
  'metadata.goog',
  'metadata',
  'instance-data',
  'instance-data.ec2.internal',
  'metadata.azure.com',
];

const LOCAL_HOST_PATTERNS: readonly string[] = ['localhost', '*.localhost'];

export type Resolver = (host: string) => Promise<Array<{ address: string; family: number }>>;

const systemResolver: Resolver = async (host) => lookup(host, { all: true, verbatim: true });

export class NetworkPolicy {
  private readonly options: NetworkPolicyOptions;
  private readonly resolver: Resolver;

  constructor(options: NetworkPolicyOptions, resolver: Resolver = systemResolver) {
    this.options = options;
    this.resolver = resolver;
  }

  get allowedPorts(): readonly number[] {
    return this.options.allowedPorts;
  }

  /** Synchronous checks that do not require DNS. */
  checkHostAndPort(rawHost: string, port: number): DestinationDecision | undefined {
    const host = normalizeHost(rawHost);
    if (!host || host.length > 253 || /[\s/\\@#?]/.test(host)) {
      return { allowed: false, host, port, code: 'invalid-host', reason: 'Invalid hostname' };
    }
    if (!Number.isInteger(port) || !this.options.allowedPorts.includes(port)) {
      return { allowed: false, host, port, code: 'port-not-allowed', reason: `Port ${port} is not in security.network.allowedPorts` };
    }
    if (matchesAnyHost(host, ALWAYS_BLOCKED_HOSTS)) {
      return { allowed: false, host, port, code: 'host-blocked', reason: 'Cloud metadata hostnames are always blocked' };
    }
    if (matchesAnyHost(host, this.options.blockedHosts)) {
      return { allowed: false, host, port, code: 'host-blocked', reason: 'Host matches security.network.blockedHosts' };
    }
    if (matchesAnyHost(host, LOCAL_HOST_PATTERNS) && !this.isPrivateAllowed(host)) {
      return { allowed: false, host, port, code: 'host-blocked', reason: 'Local hostnames are blocked' };
    }
    return undefined;
  }

  private isPrivateAllowed(host: string): boolean {
    return matchesAnyHost(host, this.options.allowedPrivateHosts);
  }

  /** Validate a concrete IP address for the given (already normalised) host. */
  validateAddress(host: string, port: number, address: string): DestinationDecision {
    const result = checkIpAddress(address);
    if (result.family === 0) {
      return { allowed: false, host, port, code: 'ip-blocked', reason: `Resolved to an invalid address (${address})` };
    }
    if (result.allowed) return { allowed: true, host, port, address, family: result.family };
    const reason = result.reason as IpBlockReason;
    if (reason !== 'cloud-metadata' && this.isPrivateAllowed(host)) {
      return { allowed: true, host, port, address, family: result.family };
    }
    return {
      allowed: false,
      host,
      port,
      code: 'ip-blocked',
      reason: `Destination resolves to a ${reason} address (${address})${result.embeddedIpv4 ? ` embedding ${result.embeddedIpv4}` : ''}`,
    };
  }

  /**
   * Resolve a hostname once and validate *every* returned address. If any
   * address is disallowed the destination is refused, which prevents
   * attackers from mixing a public and a private record and relying on
   * address selection order.
   */
  async resolveDestination(rawHost: string, port: number): Promise<DestinationDecision> {
    const early = this.checkHostAndPort(rawHost, port);
    if (early) return early;
    const host = normalizeHost(rawHost);

    if (isIP(host)) return this.validateAddress(host, port, host);

    const override = this.options.resolverOverrides[host];
    let addresses: Array<{ address: string; family: number }>;
    if (override !== undefined) {
      addresses = [{ address: override, family: isIP(override) }];
    } else {
      try {
        addresses = await this.resolver(host);
      } catch (error) {
        return {
          allowed: false,
          host,
          port,
          code: 'dns-failure',
          reason: `DNS resolution failed: ${(error as NodeJS.ErrnoException).code ?? 'unknown error'}`,
        };
      }
    }
    if (addresses.length === 0) {
      return { allowed: false, host, port, code: 'dns-failure', reason: 'DNS returned no addresses' };
    }
    let firstAllowed: DestinationDecision | undefined;
    for (const { address } of addresses) {
      const decision = this.validateAddress(host, port, address);
      if (!decision.allowed) return decision;
      firstAllowed ??= decision;
    }
    return firstAllowed as DestinationDecision;
  }
}
