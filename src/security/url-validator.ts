import { isIP } from 'node:net';
import { UrlValidationError } from '../utils/errors.js';
import { normalizeHost } from '../utils/patterns.js';
import type { NetworkPolicy } from './network-policy.js';

/**
 * Validation for user-supplied URLs (site URLs, page paths, csp-lint targets).
 *
 * This is a *first line* of defence that produces helpful errors early. It is
 * not relied upon for SSRF protection on its own: every connection made by the
 * browser goes through the egress proxy, which re-validates the destination
 * and the resolved IP address for each connection (including redirects).
 */

export const ALLOWED_TARGET_SCHEMES = ['http:', 'https:'] as const;

export function effectivePort(url: URL): number {
  if (url.port) return Number(url.port);
  return url.protocol === 'https:' || url.protocol === 'wss:' ? 443 : 80;
}

export function validateTargetUrl(input: string, policy: NetworkPolicy): URL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new UrlValidationError(`"${input}" is not a valid absolute URL`, 'Use a full URL such as https://example.com');
  }
  if (!(ALLOWED_TARGET_SCHEMES as readonly string[]).includes(url.protocol)) {
    throw new UrlValidationError(`URL scheme "${url.protocol}" is not allowed for ${redactUrlCredentials(url)}`, 'Only http: and https: targets can be scanned');
  }
  if (url.username || url.password) {
    throw new UrlValidationError(
      `URL ${redactUrlCredentials(url)} contains embedded credentials`,
      'Remove the user:password@ part. Credentials in URLs would be exposed to the browser and stored in reports.',
    );
  }
  const host = normalizeHost(url.hostname);
  if (!host) throw new UrlValidationError(`URL ${input} has no hostname`);

  const decision = policy.checkHostAndPort(host, effectivePort(url));
  if (decision && !decision.allowed) {
    throw new UrlValidationError(
      `Refusing to scan ${url.origin}: ${decision.reason}`,
      decision.code === 'port-not-allowed'
        ? 'Add the port to security.network.allowedPorts if this is intentional'
        : 'See docs/security.md for network restrictions',
    );
  }
  if (isIP(host)) {
    // WHATWG URL parsing already canonicalises decimal/octal/hex IPv4 forms
    // (e.g. http://2130706433/ -> 127.0.0.1) so this check sees the real address.
    return validateLiteralIp(url, host, policy);
  }
  return url;
}

function validateLiteralIp(url: URL, host: string, policy: NetworkPolicy): URL {
  const decision = policy.validateAddress(host, effectivePort(url), host);
  if (!decision.allowed) {
    throw new UrlValidationError(
      `Refusing to scan ${url.origin}: ${decision.reason}`,
      'Private, loopback, link-local and metadata addresses are blocked. To scan an internal host deliberately, add it to security.network.allowedPrivateHosts.',
    );
  }
  return url;
}

/**
 * Async validation that includes DNS resolution. Used as a pre-flight check so
 * users get a clear configuration error before a browser is started.
 */
export async function validateTargetUrlWithDns(input: string, policy: NetworkPolicy): Promise<URL> {
  const url = validateTargetUrl(input, policy);
  const decision = await policy.resolveDestination(url.hostname, effectivePort(url));
  if (!decision.allowed) {
    throw new UrlValidationError(
      `Refusing to scan ${url.origin}: ${decision.reason}`,
      decision.code === 'ip-blocked'
        ? 'Private, loopback, link-local and metadata addresses are blocked. To scan an internal site deliberately, add its hostname to security.network.allowedPrivateHosts.'
        : decision.code === 'dns-failure'
          ? 'Check the hostname is correct and resolvable from this machine.'
          : undefined,
    );
  }
  return url;
}

/** Resolve a configured page entry ("/checkout" or an absolute URL) against the site URL. */
export function resolvePageUrl(siteUrl: URL, page: string, policy: NetworkPolicy): URL {
  const trimmed = page.trim();
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) return validateTargetUrl(trimmed, policy);
  if (!trimmed.startsWith('/')) {
    throw new UrlValidationError(`Page "${page}" must be an absolute path starting with "/" or a full URL`);
  }
  if (trimmed.startsWith('//')) {
    throw new UrlValidationError(`Page "${page}" is a protocol-relative URL; use a full URL instead`);
  }
  return validateTargetUrl(new URL(trimmed, siteUrl).toString(), policy);
}

export function redactUrlCredentials(url: URL): string {
  if (!url.username && !url.password) return url.toString();
  const copy = new URL(url.toString());
  copy.username = '';
  copy.password = '';
  return copy.toString();
}
