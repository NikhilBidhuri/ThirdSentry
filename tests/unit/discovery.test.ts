import { describe, expect, it } from 'vitest';
import { canonicalUrl, externalIdentity, inlineIdentity, resourceKey } from '../../src/discovery/resource-identity.js';
import { classifyExternal, classifyParty, hostInfo, partyContextFor, scriptElementKind } from '../../src/discovery/resource-classifier.js';
import { decodeDataUrl } from '../../src/discovery/candidate.js';
import { redactText, redactUrl, filterResponseHeaders } from '../../src/security/redaction.js';
import { matchesGlob, matchesHostPattern } from '../../src/utils/patterns.js';

describe('resource identity', () => {
  it('keeps query parameters but sorts them and drops fragments', () => {
    expect(canonicalUrl('HTTPS://CDN.Example.com:443/a.js?b=2&a=1#frag')).toBe('https://cdn.example.com/a.js?a=1&b=2');
  });
  it('drops only configured cache-busting parameters', () => {
    expect(canonicalUrl('https://cdn.example.com/a.js?v=123&id=GTM-1', ['v'])).toBe('https://cdn.example.com/a.js?id=GTM-1');
  });
  it('builds identities', () => {
    expect(externalIdentity('https://a.example/x.js?id=1')).toBe('url:https://a.example/x.js?id=1');
    expect(inlineIdentity('/checkout', 'https://s.example/checkout', true, 'html>head>script')).toBe('inline:/checkout|main|html>head>script');
    expect(inlineIdentity('/', 'https://f.example/frame?x=1', false, 'p')).toBe('inline:/|frame:https://f.example/frame|p');
    expect(resourceKey('url:x', null)).toBe('url:x#no-content');
  });
});

describe('classification', () => {
  it('derives registrable domains with the public suffix list', () => {
    expect(hostInfo('https://www.googletagmanager.com/gtm.js')?.registrableDomain).toBe('googletagmanager.com');
    expect(hostInfo('https://shop.example.co.uk/')?.registrableDomain).toBe('example.co.uk');
    expect(hostInfo('https://foo.github.io/')?.registrableDomain).toBe('foo.github.io');
    expect(hostInfo('http://93.184.216.34/')?.registrableDomain).toBe('93.184.216.34');
  });

  it('classifies first and third parties', () => {
    const ctx = partyContextFor('https://www.shop.example.com/', ['shopcdn.net']);
    expect(classifyParty(hostInfo('https://static.shop.example.com/a.js'), ctx)).toBe('first-party');
    expect(classifyParty(hostInfo('https://assets.shopcdn.net/a.js'), ctx)).toBe('first-party');
    expect(classifyParty(hostInfo('https://www.google-analytics.com/a.js'), ctx)).toBe('third-party');
  });

  it('recognises executable script element types', () => {
    expect(scriptElementKind(undefined)).toBe('classic');
    expect(scriptElementKind('text/javascript')).toBe('classic');
    expect(scriptElementKind('module')).toBe('module');
    expect(scriptElementKind('application/ld+json')).toBe('data');
    expect(scriptElementKind('text/template')).toBe('data');
    expect(scriptElementKind('importmap')).toBe('importmap');
  });

  it('classifies external resources', () => {
    const base = { requestResourceType: 'script', source: 'page-network' };
    expect(classifyExternal({ ...base, url: 'https://a/x.wasm' })).toBe('wasm');
    expect(classifyExternal({ ...base, url: 'https://a/x', contentType: 'application/wasm' })).toBe('wasm');
    expect(classifyExternal({ ...base, url: 'https://a/w.js', fetchDest: 'worker' })).toBe('dedicated-worker');
    expect(classifyExternal({ ...base, url: 'https://a/sw.js', source: 'service-worker-probe' })).toBe('service-worker');
    expect(classifyExternal({ ...base, url: 'https://a/m.js', fetchMode: 'cors', fetchDest: 'script' })).toBe('module');
    expect(classifyExternal({ ...base, url: 'https://a/c.js', fetchMode: 'no-cors', fetchDest: 'script' })).toBe('script');
    expect(classifyExternal({ ...base, url: 'https://a/lazy.mjs' })).toBe('module');
    expect(classifyExternal({ ...base, url: 'https://a/l.js', looksLikeModule: () => true })).toBe('module');
    expect(classifyExternal({ ...base, url: 'https://a/l.js', domKind: 'classic', looksLikeModule: () => true })).toBe('script');
    expect(classifyExternal({ url: 'https://a/x.js', requestResourceType: 'fetch', source: 'page-network' })).toBe('fetched-script');
  });

  it('decodes data URLs with size limits', () => {
    const d = decodeDataUrl('data:text/javascript;base64,' + Buffer.from('alert(1)').toString('base64'), 100);
    expect(d && 'body' in d ? d.body.toString() : '').toBe('alert(1)');
    expect(decodeDataUrl('data:,' + 'a'.repeat(50), 10)).toEqual({ tooLarge: true });
  });
});

describe('redaction', () => {
  it('redacts sensitive query values but keeps parameter names', () => {
    const out = redactUrl('https://collect.example/p?token=abc&page=home&email=a%40b.c&sid=1#x');
    expect(out).toContain('token=%5BREDACTED%5D');
    expect(out).toContain('email=%5BREDACTED%5D');
    expect(out).toContain('page=home');
    expect(out).not.toContain('#x');
  });
  it('strips credentials', () => {
    expect(redactUrl('https://u:p@a.example/')).toBe('https://a.example/');
  });
  it('omits data URL payloads', () => {
    expect(redactUrl('data:text/javascript;base64,AAAA')).toContain('[data URL omitted]');
  });
  it('stores only allowlisted headers', () => {
    const h = filterResponseHeaders({ 'Content-Type': 'text/javascript', 'Set-Cookie': 'sid=1', Authorization: 'x', ETag: '"1"' });
    expect(h).toEqual({ 'content-type': 'text/javascript', etag: '"1"' });
  });
  it('removes bearer tokens and JWTs from free text', () => {
    expect(redactText('Authorization: Bearer abcdefghijkl123')).not.toContain('abcdefghijkl123');
    expect(redactText('t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')).toContain('[REDACTED]');
  });
});

describe('patterns', () => {
  it('matches host patterns', () => {
    expect(matchesHostPattern('a.example.com', '*.example.com')).toBe(true);
    expect(matchesHostPattern('example.com', '*.example.com')).toBe(false);
    expect(matchesHostPattern('Example.COM.', 'example.com')).toBe(true);
    expect(matchesHostPattern('badexample.com', '*.example.com')).toBe(false);
  });
  it('matches globs without regex injection', () => {
    expect(matchesGlob('https://a.example/x.js', 'https://*.example/*')).toBe(true);
    expect(matchesGlob('https://a.example/x.js', 'https://a.example/x.j?')).toBe(true);
    expect(matchesGlob('aXb', 'a.b')).toBe(false);
  });
});
