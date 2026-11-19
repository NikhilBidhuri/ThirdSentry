import { describe, expect, it } from 'vitest';
import { analyzePolicies, scriptProfile } from '../../src/csp/csp-analyzer.js';
import { effectiveDirective, parsePolicies, parsePolicy, parseSource } from '../../src/csp/csp-parser.js';

const ids = (enforce: string[], reportOnly: string[] = []): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const f of analyzePolicies(parsePolicies(enforce, reportOnly)).findings) out[f.id] = f.level;
  return out;
};

const STRICT = "script-src 'nonce-r4nd0mR4nd0mR4nd0m22' 'strict-dynamic'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; report-to csp; require-trusted-types-for 'script'; default-src 'self'";

describe('CSP parser', () => {
  it('classifies source expressions', () => {
    expect(parseSource("'self'")).toMatchObject({ kind: 'keyword', value: 'self' });
    expect(parseSource("'SELF'")).toMatchObject({ kind: 'keyword', value: 'self' });
    expect(parseSource("'nonce-abc123=='")).toMatchObject({ kind: 'nonce', value: 'abc123==' });
    expect(parseSource("'sha256-AbC+/=='")).toMatchObject({ kind: 'hash' });
    expect(parseSource('https:')).toMatchObject({ kind: 'scheme', value: 'https:' });
    expect(parseSource('*')).toMatchObject({ kind: 'wildcard' });
    expect(parseSource('*.example.com')).toMatchObject({ kind: 'host', host: '*.example.com' });
    expect(parseSource('https://cdn.example.com:443/path/')).toMatchObject({ kind: 'host', host: 'cdn.example.com', scheme: 'https:' });
    expect(parseSource("'unknown-keyword'")).toMatchObject({ kind: 'invalid' });
    // An unquoted keyword is parsed as a hostname, which is what browsers do too.
    expect(parseSource('self')).toMatchObject({ kind: 'host', host: 'self' });
  });

  it('splits multiple headers and comma-separated policies, first directive wins', () => {
    const policies = parsePolicies(["default-src 'self', script-src 'none'", "script-src https://a.example; script-src *"], ["default-src 'none'"]);
    expect(policies.map((p) => p.disposition)).toEqual(['enforce', 'enforce', 'enforce', 'report']);
    expect(policies[2]?.directives.get('script-src')?.values).toEqual(['https://a.example']);
    expect(policies[2]?.duplicateDirectives).toEqual(['script-src']);
  });

  it('implements directive fallback correctly', () => {
    const p = parsePolicy("default-src 'self'; script-src 'nonce-x'; child-src https://c.example", 'enforce', 0);
    expect(effectiveDirective(p, 'script-src-elem')?.name).toBe('script-src');
    expect(effectiveDirective(p, 'worker-src')?.name).toBe('child-src');
    expect(effectiveDirective(p, 'img-src')?.name).toBe('default-src');
    expect(effectiveDirective(p, 'object-src')?.name).toBe('default-src');
    // Document directives never fall back to default-src.
    expect(effectiveDirective(p, 'base-uri')).toBeUndefined();
    expect(effectiveDirective(p, 'form-action')).toBeUndefined();
  });
});

describe('CSP analyzer', () => {
  it('reports missing and report-only policies as errors', () => {
    expect(ids([])['no-policy']).toBe('error');
    const ro = ids([], [STRICT]);
    expect(ro['report-only']).toBe('error');
  });

  it('accepts a strict nonce-based policy and does not treat strict-dynamic as insecure', () => {
    const found = ids([STRICT]);
    const errors = Object.entries(found).filter(([, level]) => level === 'error');
    expect(errors).toEqual([]);
    expect(found['strict-dynamic-ok']).toBe('info');
    expect(analyzePolicies(parsePolicies([STRICT])).scriptsRestricted).toBe(true);
  });

  it('flags unsafe-inline only when it is actually honoured', () => {
    expect(ids(["script-src 'self' 'unsafe-inline'; object-src 'none'"])['unsafe-inline']).toBe('error');
    const neutralised = ids(["script-src 'nonce-abcdefghijklmnop1234' 'unsafe-inline'; object-src 'none'"]);
    expect(neutralised['unsafe-inline']).toBeUndefined();
    expect(neutralised['unsafe-inline-neutralised']).toBe('info');
  });

  it('flags wildcard, scheme-only and data: script sources', () => {
    expect(ids(['script-src *'])['wildcard-script-source']).toBe('error');
    expect(ids(['script-src https:'])['wildcard-script-source']).toBe('error');
    expect(ids(["script-src 'self' data:"])['data-script-source']).toBe('error');
  });

  it('ignores host allowlists under strict-dynamic (CSP3)', () => {
    const p = scriptProfile(parsePolicy("script-src 'nonce-abcdefghijklmnop1234' 'strict-dynamic' https: *", 'enforce', 0));
    expect(p.allowsAnyHost).toBe(false);
    expect(p.honouredSources).toEqual([]);
  });

  it('flags strict-dynamic without nonce or hash', () => {
    expect(ids(["script-src 'strict-dynamic' https://a.example"])['strict-dynamic-without-nonce']).toBe('error');
  });

  it('checks object-src, base-uri, form-action, reporting and default-src', () => {
    const found = ids(["script-src 'self'"]);
    expect(found['object-src']).toBe('error');
    expect(found['missing-base-uri']).toBe('warning');
    expect(found['missing-form-action']).toBe('warning');
    expect(found['missing-reporting']).toBe('warning');
    expect(found['missing-default-src']).toBe('warning');
    expect(found['allowlist-only']).toBe('warning');
    // base-uri is critical for nonce-based policies.
    expect(ids(["script-src 'nonce-abcdefghijklmnop1234'"])['missing-base-uri']).toBe('error');
    // object-src via default-src 'none' is fine.
    expect(ids(["default-src 'none'; script-src 'self'"])['object-src']).toBeUndefined();
  });

  it('detects risky third-party allowances and broad allowlists', () => {
    expect(ids(["script-src 'self' https://ajax.googleapis.com *.cloudfront.net"])['risky-script-hosts']).toBe('warning');
    const many = Array.from({ length: 20 }, (_, i) => `https://cdn${i}.example`).join(' ');
    expect(ids([`script-src ${many}`])['broad-script-allowlist']).toBe('warning');
  });

  it('treats a weakness in one policy as mitigated by another enforced policy', () => {
    const found = analyzePolicies(parsePolicies(["script-src * 'unsafe-inline'", STRICT])).findings;
    const inline = found.find((f) => f.id === 'unsafe-inline');
    expect(inline?.level).toBe('info');
    expect(inline?.detail).toMatch(/Mitigated by enforced policy #2/);
  });

  it('reports invalid sources, duplicates and unknown directives', () => {
    const found = ids(["script-src self; scirpt-src 'none'; object-src 'none'; object-src *"]);
    expect(found['invalid-source']).toBe('error');
    expect(found['unknown-directive']).toBe('warning');
    expect(found['duplicate-directive']).toBe('warning');
  });

  it('flags short nonces', () => {
    expect(ids(["script-src 'nonce-abc'"])['weak-nonce']).toBe('warning');
  });
});
