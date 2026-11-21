import { createHash } from 'node:crypto';
import { access, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadLibraryDb, vulnDbDir } from '../../src/analysis/libraries/vulndb.js';
import { updateVulnDb } from '../../src/analysis/libraries/vulndb-update.js';
import { NetworkPolicy } from '../../src/security/network-policy.js';
import { ThirdSentryError } from '../../src/utils/errors.js';
import { FixtureServer } from '../fixtures/server.js';
import { tempDir } from '../helpers.js';

const server = new FixtureServer();
let policy: NetworkPolicy;

const VALID = JSON.stringify({
  acme: {
    vulnerabilities: [{ below: '2.0.0', severity: 'high', identifiers: { CVE: ['CVE-2024-0001'], summary: 'bad' }, info: ['https://example.com/advisory'] }],
    extractors: { filename: ['acme-(§§version§§)(\\.min)?\\.js'], filecontent: ['/\\*! Acme v(§§version§§)'] },
  },
});

async function exists(path: string): Promise<boolean> {
  return access(path).then(
    () => true,
    () => false,
  );
}

beforeAll(async () => {
  await server.start();
  policy = new NetworkPolicy({
    allowedPorts: [server.port],
    allowedPrivateHosts: ['db.test'],
    blockedHosts: [],
    resolverOverrides: { 'db.test': '127.0.0.1', 'internal.test': '127.0.0.1', 'meta.test': '169.254.169.254' },
  });
  server.set('db.test', '/jsrepository.json', { headers: { 'content-type': 'application/json' }, body: VALID });
  server.set('db.test', '/bad.json', { headers: { 'content-type': 'application/json' }, body: '{ not json' });
  server.set('db.test', '/schema.json', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ acme: { vulnerabilities: [{ below: '1.0', severity: 'apocalyptic' }] } }) });
  server.set('db.test', '/empty-db.json', { headers: { 'content-type': 'application/json' }, body: '{}' });
  server.set('db.test', '/huge.json', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ acme: { vulnerabilities: [], pad: 'x'.repeat(200_000) } }) });
  server.set('db.test', '/missing', { status: 404, body: 'nope' });
  server.set('db.test', '/to-internal', { redirect: 'http://internal.test:{port}/jsrepository.json' });
  server.set('db.test', '/to-metadata', { redirect: 'http://meta.test:{port}/latest/' });
  server.set('internal.test', '/jsrepository.json', { headers: { 'content-type': 'application/json' }, body: VALID });
});
afterAll(async () => {
  await server.stop();
});

describe('vulndb update', () => {
  it('downloads, validates and atomically installs the database with metadata', async () => {
    const cache = await tempDir('vulndb-');
    const now = new Date('2026-05-01T12:00:00.000Z');
    const url = server.url('db.test', '/jsrepository.json');
    const result = await updateVulnDb(cache, policy, { url, now });
    expect(result.meta).toMatchObject({ sourceUrl: url, fetchedAt: now.toISOString(), libraries: 1, advisories: 1, bytes: Buffer.byteLength(VALID) });
    expect(result.meta.sha256).toBe(createHash('sha256').update(VALID).digest('hex'));
    expect(await readFile(join(vulnDbDir(cache), 'jsrepository.json'), 'utf8')).toBe(VALID);
    const meta = JSON.parse(await readFile(join(vulnDbDir(cache), 'meta.json'), 'utf8')) as { sha256: string };
    expect(meta.sha256).toBe(result.meta.sha256);
    const db = await loadLibraryDb(cache, { now: new Date('2026-05-03T12:00:00.000Z'), maxAgeDays: 30 });
    expect(db.info).toMatchObject({ source: 'cache', ageDays: 2, stale: false, advisories: 1, sha256: result.meta.sha256 });
    expect(db.libraries.get('acme')?.advisories[0]?.id).toBe('CVE-2024-0001');
  });

  it('refuses invalid JSON, schema violations, empty databases, HTTP errors, and installs nothing', async () => {
    const cache = await tempDir('vulndb-');
    for (const [path, message] of [
      ['/bad.json', /not valid JSON/],
      ['/schema.json', /not a valid retire\.js repository/],
      ['/empty-db.json', /no libraries or advisories/],
      ['/missing', /HTTP 404/],
    ] as const) {
      await expect(updateVulnDb(cache, policy, { url: server.url('db.test', path) })).rejects.toThrow(message);
    }
    expect(await exists(join(vulnDbDir(cache), 'jsrepository.json'))).toBe(false);
  });

  it('enforces the size cap and does not install a truncated download', async () => {
    const cache = await tempDir('vulndb-');
    await expect(updateVulnDb(cache, policy, { url: server.url('db.test', '/huge.json'), maxBytes: 10_000 })).rejects.toThrow(/larger than/);
    expect(await exists(join(vulnDbDir(cache), 'jsrepository.json'))).toBe(false);
  });

  it('refuses redirects to private and metadata addresses', async () => {
    const cache = await tempDir('vulndb-');
    await expect(updateVulnDb(cache, policy, { url: server.url('db.test', '/to-internal') })).rejects.toBeInstanceOf(ThirdSentryError);
    await expect(updateVulnDb(cache, policy, { url: server.url('db.test', '/to-metadata') })).rejects.toThrow(/Blocked|refus|Could not download/i);
    expect(server.hits.some((h) => h.startsWith('internal.test'))).toBe(false);
    expect(await exists(join(vulnDbDir(cache), 'jsrepository.json'))).toBe(false);
  });

  it('refuses a direct private target and unsupported schemes', async () => {
    const cache = await tempDir('vulndb-');
    await expect(updateVulnDb(cache, policy, { url: `http://127.0.0.1:${server.port}/jsrepository.json` })).rejects.toThrow();
    await expect(updateVulnDb(cache, policy, { url: 'file:///etc/passwd' })).rejects.toThrow(/scheme/);
  });

  it('keeps the previous database when an update fails', async () => {
    const cache = await tempDir('vulndb-');
    await updateVulnDb(cache, policy, { url: server.url('db.test', '/jsrepository.json') });
    await expect(updateVulnDb(cache, policy, { url: server.url('db.test', '/bad.json') })).rejects.toThrow();
    expect(await readFile(join(vulnDbDir(cache), 'jsrepository.json'), 'utf8')).toBe(VALID);
  });
});
