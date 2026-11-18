import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { stringify } from 'yaml';
import { loadConfig, type ResolvedConfig } from '../src/config/loader.js';
import { ALLOWED_TEST_HOSTS, FIXTURE_HOSTS } from './fixtures/server.js';

/** Create a temporary project directory with a scriptdrift.yml for the fixture server. */
export async function makeProject(port: number, overrides: Record<string, unknown> = {}): Promise<{ dir: string; resolved: ResolvedConfig; cleanup: () => Promise<void> }> {
  const base = join(process.cwd(), 'tests', '.tmp');
  await mkdir(base, { recursive: true });
  const dir = await mkdtemp(join(base, 'proj-'));
  const config = {
    version: 1,
    sites: [
      {
        name: 'shop',
        url: `http://shop.test:${port}/`,
        pages: ['/'],
        sensitivePages: ['/checkout'],
      },
    ],
    defaults: { scan: { timeout: 15_000, waitUntil: 'networkidle', networkIdleTimeout: 3_000, settleMs: 500 } },
    security: {
      network: {
        allowedPorts: [port],
        allowedPrivateHosts: [...ALLOWED_TEST_HOSTS],
        resolverOverrides: Object.fromEntries(FIXTURE_HOSTS.map((h) => [h, '127.0.0.1'])),
      },
      isolation: { mode: 'none' },
    },
    ...overrides,
  };
  await writeFile(join(dir, 'scriptdrift.yml'), stringify(config));
  const resolved = await loadConfig({ cwd: dir });
  return { dir, resolved, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

export async function tempDir(prefix = 'tmp-'): Promise<string> {
  const base = join(tmpdir(), 'scriptdrift-tests');
  await mkdir(base, { recursive: true });
  return mkdtemp(join(base, prefix));
}
