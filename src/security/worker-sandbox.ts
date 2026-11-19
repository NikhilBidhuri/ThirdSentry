import { fork } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { CollectRequest } from '../browser/collector.js';
import { ScanEvidenceSchema, type ScanEvidence } from '../types/evidence.js';
import { EvidenceValidationError, ThirdSentryError } from '../utils/errors.js';
import { readJsonFile } from '../utils/fs.js';
import { getLogger } from '../utils/logger.js';
import { formatZodIssues } from '../config/loader.js';

/**
 * Runs the browser worker in a separate Node.js process.
 *
 * Isolation properties (process mode):
 *  - The child receives an *allowlisted* environment. Alert credentials,
 *    Git/GitHub tokens, cloud credentials and anything else in the parent
 *    environment are not inherited.
 *  - HOME/TEMP point at a disposable directory that is deleted afterwards.
 *  - The child is given only the collection request (sites, limits, network
 *    policy). It is not told where baselines, reports or state live.
 *  - Its output is size-limited and schema-validated before use.
 *  - It is killed if it exceeds the scan time budget.
 *
 * Process mode does NOT provide filesystem isolation: the worker runs as the
 * same OS user. For stronger isolation run the browser worker in the
 * dedicated container described in docs/docker.md.
 */

const ENV_ALLOWLIST = [
  'PATH',
  'Path',
  'PATHEXT',
  'SystemRoot',
  'SYSTEMROOT',
  'windir',
  'ComSpec',
  'LANG',
  'LC_ALL',
  'TZ',
  'FONTCONFIG_PATH',
  'PLAYWRIGHT_BROWSERS_PATH',
  'PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS',
];

export function defaultPlaywrightBrowsersPath(env: NodeJS.ProcessEnv = process.env, platform = process.platform): string {
  if (env.PLAYWRIGHT_BROWSERS_PATH) return env.PLAYWRIGHT_BROWSERS_PATH;
  if (platform === 'win32') return join(env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local'), 'ms-playwright');
  if (platform === 'darwin') return join(homedir(), 'Library', 'Caches', 'ms-playwright');
  return join(env.XDG_CACHE_HOME ?? join(homedir(), '.cache'), 'ms-playwright');
}

/** Build the minimal environment passed to the browser worker. */
export function buildWorkerEnv(sandboxDir: string, parentEnv: NodeJS.ProcessEnv = process.env, logLevel = 'info'): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of ENV_ALLOWLIST) {
    const value = parentEnv[key];
    if (value !== undefined) env[key] = value;
  }
  env.PLAYWRIGHT_BROWSERS_PATH = defaultPlaywrightBrowsersPath(parentEnv);
  const home = join(sandboxDir, 'home');
  const tmp = join(sandboxDir, 'tmp');
  env.HOME = home;
  env.USERPROFILE = home;
  env.TMPDIR = tmp;
  env.TMP = tmp;
  env.TEMP = tmp;
  env.XDG_CONFIG_HOME = join(home, '.config');
  env.XDG_CACHE_HOME = join(home, '.cache');
  env.XDG_DATA_HOME = join(home, '.local', 'share');
  if (process.platform === 'win32') {
    env.LOCALAPPDATA = join(home, 'AppData', 'Local');
    env.APPDATA = join(home, 'AppData', 'Roaming');
  }
  env.THIRDSENTRY_WORKER = '1';
  env.THIRDSENTRY_LOG_LEVEL = logLevel;
  return env;
}

/** Locate the compiled worker entry point (the child must run JavaScript). */
export function resolveWorkerEntry(): string {
  const here = fileURLToPath(import.meta.url);
  if (here.endsWith('.js')) return join(dirname(here), '..', 'browser', 'worker-entry.js');
  // Running from TypeScript sources (tests/dev): use the build output.
  const built = resolve(dirname(here), '..', '..', 'dist', 'browser', 'worker-entry.js');
  if (!existsSync(built)) {
    throw new ThirdSentryError('Compiled browser worker not found', {
      hint: 'Run "npm run build" first, or set security.isolation.mode: none for debugging.',
    });
  }
  return built;
}

export interface SandboxOptions {
  readonly maxEvidenceBytes: number;
  readonly timeoutMs: number;
  readonly logLevel?: string;
}

export async function runIsolatedCollection(request: CollectRequest, options: SandboxOptions): Promise<ScanEvidence> {
  const log = getLogger('worker-sandbox');
  const entry = resolveWorkerEntry();
  const sandboxDir = await mkdtemp(join(tmpdir(), 'thirdsentry-worker-'));
  try {
    await mkdir(join(sandboxDir, 'home'), { recursive: true });
    await mkdir(join(sandboxDir, 'tmp'), { recursive: true });
    const requestPath = join(sandboxDir, 'request.json');
    const outputPath = join(sandboxDir, 'evidence.json');
    await writeFile(requestPath, JSON.stringify(request));

    const env = buildWorkerEnv(sandboxDir, process.env, options.logLevel);
    log.debug({ entry, sandboxDir }, 'starting isolated browser worker');
    const child = fork(entry, [requestPath, outputPath], {
      cwd: sandboxDir,
      env,
      execArgv: ['--max-old-space-size=2048'],
      stdio: ['ignore', 'ignore', 'inherit', 'ipc'],
      serialization: 'json',
    });

    const exitCode = await new Promise<number | null>((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        log.error({ timeoutMs: options.timeoutMs }, 'browser worker exceeded its time budget; killing it');
        child.kill('SIGKILL');
      }, options.timeoutMs);
      child.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once('exit', (code) => {
        clearTimeout(timer);
        resolvePromise(code);
      });
    });
    if (exitCode !== 0) {
      throw new ThirdSentryError(`Browser worker exited with code ${String(exitCode)}`, {
        hint: 'Run with --verbose for worker logs. If Chromium cannot start its sandbox, see docs/troubleshooting.md.',
      });
    }
    let raw: unknown;
    try {
      raw = await readJsonFile(outputPath, options.maxEvidenceBytes);
    } catch (error) {
      throw new EvidenceValidationError(`Could not read browser worker evidence: ${(error as Error).message}`, error);
    }
    return validateEvidence(raw);
  } finally {
    await rm(sandboxDir, { recursive: true, force: true, maxRetries: 3 }).catch(() => undefined);
  }
}

/** Validate untrusted evidence produced by a browser worker. */
export function validateEvidence(raw: unknown): ScanEvidence {
  const parsed = ScanEvidenceSchema.safeParse(raw);
  if (!parsed.success) {
    throw new EvidenceValidationError(`Browser worker evidence failed validation:\n${formatZodIssues(parsed.error)}`);
  }
  return parsed.data;
}
