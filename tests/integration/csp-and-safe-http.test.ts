import { utimes, mkdir, writeFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { lintUrl } from '../../src/csp/csp-lint.js';
import { NetworkPolicy } from '../../src/security/network-policy.js';
import { SafeFetchError, safeFetch } from '../../src/security/safe-http.js';
import { applyRetention } from '../../src/storage/filesystem-store.js';
import { storagePaths } from '../../src/storage/paths.js';
import { FixtureServer } from '../fixtures/server.js';
import { tempDir } from '../helpers.js';

const server = new FixtureServer();
let policy: NetworkPolicy;
let counter = 0;

beforeAll(async () => {
  await server.start();
  policy = new NetworkPolicy({
    allowedPorts: [server.port],
    allowedPrivateHosts: ['csp.test'],
    blockedHosts: [],
    resolverOverrides: { 'csp.test': '127.0.0.1', 'internal.test': '127.0.0.1', 'meta.test': '169.254.169.254' },
  });
  server.html('csp.test', '/strict', '<p>ok</p>', {
    'content-security-policy': "script-src 'nonce-STATICSTATICSTATIC1' 'strict-dynamic'; object-src 'none'; base-uri 'none'",
  });
  server.html('csp.test', '/multi', '<p>ok</p>', {
    'content-security-policy': ["default-src 'self'; script-src 'self' 'unsafe-inline'", "object-src 'none'"],
    'content-security-policy-report-only': "script-src 'none'",
  });
  server.set('csp.test', '/to-internal', { redirect: 'http://internal.test:{port}/secret' });
  server.set('csp.test', '/to-metadata', { redirect: 'http://meta.test:{port}/latest/meta-data/' });
  server.set('csp.test', '/hop', { redirect: 'http://csp.test:{port}/strict' });
  server.set('csp.test', '/big', { headers: { 'content-type': 'text/plain' }, body: 'x'.repeat(100_000) });
  server.set('internal.test', '/secret', { body: 'internal secret' });
});
afterAll(async () => {
  await server.stop();
});

describe('safe HTTP client (SSRF protection for server-side fetches)', () => {
  it('fetches allowed hosts and follows validated redirects', async () => {
    const res = await safeFetch(server.url('csp.test', '/hop'), policy);
    expect(res.status).toBe(200);
    expect(res.redirects).toEqual([server.url('csp.test', '/hop')]);
  });

  it('refuses redirects to internal or metadata addresses', async () => {
    await expect(safeFetch(server.url('csp.test', '/to-internal'), policy)).rejects.toBeInstanceOf(SafeFetchError);
    await expect(safeFetch(server.url('csp.test', '/to-metadata'), policy)).rejects.toThrow(/Blocked|refus/i);
    expect(server.hits.some((h) => h.startsWith('internal.test'))).toBe(false);
  });

  it('refuses direct private targets and unsupported schemes', async () => {
    await expect(safeFetch(`http://127.0.0.1:${server.port}/`, policy)).rejects.toThrow();
    await expect(safeFetch('file:///etc/passwd', policy)).rejects.toThrow(/scheme/);
  });

  it('caps response bodies', async () => {
    const res = await safeFetch(server.url('csp.test', '/big'), policy, { maxBytes: 1000 });
    expect(res.body.length).toBe(1000);
    expect(res.truncated).toBe(true);
  });
});

describe('csp-lint against a live server', () => {
  it('detects a static nonce across two responses', async () => {
    const t = await lintUrl(server.url('csp.test', '/strict'), policy);
    expect(t.findings[0]?.id).toBe('static-nonce');
    expect(t.findings.find((f) => f.id === 'strict-dynamic-ok')?.level).toBe('info');
  });

  it('does not flag nonces that change per response', async () => {
    server.routes.set('csp.test/dynamic', { headers: { 'content-type': 'text/html' }, body: '' });
    const original = server.routes.get('csp.test/dynamic');
    const handler = new Proxy(original ?? {}, {
      get: (target, prop) => (prop === 'headers' ? { 'content-type': 'text/html', 'content-security-policy': `script-src 'nonce-dynamicnonce${String(++counter).padStart(6, '0')}' 'strict-dynamic'; object-src 'none'; base-uri 'none'` } : (target as Record<string | symbol, unknown>)[prop]),
    });
    server.routes.set('csp.test/dynamic', handler);
    const t = await lintUrl(server.url('csp.test', '/dynamic'), policy);
    expect(t.findings.some((f) => f.id === 'static-nonce')).toBe(false);
  });

  it('analyses multiple CSP headers and report-only policies together', async () => {
    const t = await lintUrl(server.url('csp.test', '/multi'), policy);
    expect(t.policies.map((p) => p.disposition)).toEqual(['enforce', 'enforce', 'report']);
    expect(t.findings.find((f) => f.id === 'unsafe-inline' && f.policyIndex === 0)?.level).toBe('error');
    // object-src is missing from policy #1 but enforced by policy #2.
    expect(t.findings.find((f) => f.id === 'object-src' && f.policyIndex === 0)?.level).toBe('info');
  });

  it('reports unreachable targets as errors instead of throwing', async () => {
    const t = await lintUrl(`http://internal.test:${server.port}/`, policy);
    expect(t.error).toMatch(/Blocked|private|loopback/i);
  });
});

describe('retention', () => {
  it('removes old scans, screenshots and unreferenced content but keeps baseline-referenced content', async () => {
    const paths = storagePaths(await tempDir('retention-'));
    const old = new Date('2020-01-01');
    await mkdir(paths.scans, { recursive: true });
    for (let i = 0; i < 5; i++) await writeFile(join(paths.scans, `scan-${i}.json`), '{}');
    await utimes(join(paths.scans, 'scan-0.json'), old, old);
    const keepSha = 'a'.repeat(64);
    const dropSha = 'b'.repeat(64);
    for (const sha of [keepSha, dropSha]) {
      await mkdir(join(paths.content, sha.slice(0, 2)), { recursive: true });
      await writeFile(join(paths.content, sha.slice(0, 2), sha), 'code');
      await utimes(join(paths.content, sha.slice(0, 2), sha), old, old);
    }
    const dry = await applyRetention(paths, { maxScans: 3, maxAgeDays: 30, keepContent: new Set([keepSha]), dryRun: true });
    expect(dry).toMatchObject({ removedScans: 2, removedContent: 1, keptReferencedContent: 1, dryRun: true });
    expect(await readdir(paths.scans)).toHaveLength(5);
    const real = await applyRetention(paths, { maxScans: 3, maxAgeDays: 30, keepContent: new Set([keepSha]) });
    expect(real.removedScans).toBe(2);
    expect(await readdir(paths.scans)).toHaveLength(3);
    expect(await readdir(join(paths.content, 'aa'))).toEqual([keepSha]);
    expect(await readdir(join(paths.content, 'bb'))).toEqual([]);
  });
});
