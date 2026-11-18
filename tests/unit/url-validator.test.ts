import { describe, expect, it } from 'vitest';
import { NetworkPolicy } from '../../src/security/network-policy.js';
import { resolvePageUrl, validateTargetUrl } from '../../src/security/url-validator.js';
import { UrlValidationError } from '../../src/utils/errors.js';

const policy = new NetworkPolicy({ allowedPorts: [80, 443], allowedPrivateHosts: [], blockedHosts: [], resolverOverrides: {} });

describe('validateTargetUrl', () => {
  it('accepts http and https URLs', () => {
    expect(validateTargetUrl('https://example.com/shop?x=1', policy).toString()).toBe('https://example.com/shop?x=1');
    expect(validateTargetUrl('http://example.com', policy).hostname).toBe('example.com');
  });

  it.each(['file:///etc/passwd', 'ftp://example.com/', 'javascript:alert(1)', 'data:text/html,hi', 'gopher://x/', 'chrome://settings'])(
    'rejects scheme %s',
    (url) => {
      expect(() => validateTargetUrl(url, policy)).toThrow(UrlValidationError);
    },
  );

  it('rejects embedded credentials', () => {
    expect(() => validateTargetUrl('https://user:pass@example.com/', policy)).toThrow(/credentials/);
  });

  it('rejects malformed URLs', () => {
    expect(() => validateTargetUrl('not a url', policy)).toThrow(UrlValidationError);
    expect(() => validateTargetUrl('/relative', policy)).toThrow(UrlValidationError);
  });

  it.each([
    'http://127.0.0.1/',
    'http://2130706433/', // decimal form of 127.0.0.1
    'http://0x7f000001/', // hex form
    'http://0177.0.0.1/', // octal form
    'http://127.1/', // short form
    'http://[::1]/',
    'http://[::ffff:127.0.0.1]/',
    'http://169.254.169.254/latest/meta-data/',
    'http://10.0.0.1/',
    'http://localhost/',
    'http://metadata.google.internal/',
  ])('rejects internal target %s', (url) => {
    expect(() => validateTargetUrl(url, policy)).toThrow(UrlValidationError);
  });

  it('rejects non-allowed ports', () => {
    expect(() => validateTargetUrl('https://example.com:8443/', policy)).toThrow(/allowedPorts/);
  });
});

describe('resolvePageUrl', () => {
  const site = new URL('https://shop.example.com/');
  it('resolves absolute paths against the site', () => {
    expect(resolvePageUrl(site, '/checkout?step=1', policy).toString()).toBe('https://shop.example.com/checkout?step=1');
  });
  it('rejects relative and protocol-relative entries', () => {
    expect(() => resolvePageUrl(site, 'checkout', policy)).toThrow(UrlValidationError);
    expect(() => resolvePageUrl(site, '//evil.example/', policy)).toThrow(UrlValidationError);
  });
  it('validates absolute page URLs', () => {
    expect(() => resolvePageUrl(site, 'http://127.0.0.1/', policy)).toThrow(UrlValidationError);
  });
});
