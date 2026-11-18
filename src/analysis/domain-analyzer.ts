import { isIP } from 'node:net';
import type { DomainPolicy } from '../config/schema.js';
import { matchesAnyHost } from '../utils/patterns.js';

/**
 * Domain policy evaluation for script sources and outbound destinations.
 *
 *  - allow: treated as approved everywhere; never reported as "new".
 *  - deny: must never be used; reported on every scan, even if approved in a baseline.
 *  - suspicious: optional reputation hints that raise the risk of findings.
 *
 * Patterns match either the full hostname or the registrable domain, so
 * `example.com` covers `example.com` and `*.example.com` covers subdomains.
 */

export interface DomainVerdict {
  readonly allowed: boolean;
  readonly denied: boolean;
  readonly suspicious: boolean;
  readonly ipLiteral: boolean;
}

export const EMPTY_DOMAIN_POLICY: DomainPolicy = { allow: [], deny: [], suspicious: [] };

function matches(hostname: string, registrable: string | undefined, patterns: readonly string[]): boolean {
  return matchesAnyHost(hostname, patterns) || (registrable !== undefined && matchesAnyHost(registrable, patterns));
}

export function evaluateDomain(hostname: string, registrableDomain: string | undefined, policy: DomainPolicy = EMPTY_DOMAIN_POLICY): DomainVerdict {
  const denied = matches(hostname, registrableDomain, policy.deny);
  return {
    denied,
    allowed: !denied && matches(hostname, registrableDomain, policy.allow),
    suspicious: matches(hostname, registrableDomain, policy.suspicious),
    ipLiteral: isIP(hostname.replace(/^\[|\]$/g, '')) !== 0,
  };
}
