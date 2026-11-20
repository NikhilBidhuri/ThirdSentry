import { execFile, fork, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { CollectRequest } from '../browser/collector.js';
import { ScanEvidenceSchema, type ScanEvidence } from '../types/evidence.js';
import { EvidenceValidationError, ThirdSentryError } from '../utils/errors.js';
import { assembleEvidence } from './evidence-assembly.js';
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
 *  - Its output (one part file per page) is size-limited and schema-validated
 *    part by part before use. If the worker crashes or times out, completed
 *    pages/sites are kept and the rest is marked failed.
 *  - On timeout it gets SIGTERM and a grace period, then the whole process
 *    tree (including browsers) is killed.
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
  /** Time between SIGTERM and killing the process tree (default 5000). */
  readonly killGraceMs?: number;
}

/** Kill a process and all of its descendants (browsers started by the worker). */
export function killProcessTree(pid: number): Promise<void> {
  if (process.platform === 'win32') {
    return new Promise((resolvePromise) => {
      execFile('taskkill', ['/T', '/F', '/PID', String(pid)], { windowsHide: true }, () => resolvePromise());
    });
  }
  try {
    process.kill(-pid, 'SIGKILL'); // the worker is a process-group leader (detached)
  } catch {
    try {
      process.kill(pid, 'SIGKILL');
    } catch {
      /* already gone */
    }
  }
  return Promise.resolve();
}

async function stopChild(child: ChildProcess, graceMs: number): Promise<void> {
  const pid = child.pid;
  if (pid === undefined) return;
  if (process.platform !== 'win32') {
    try {
      process.kill(pid, 'SIGTERM');
    } catch {
      /* already gone */
    }
    await new Promise((r) => setTimeout(r, graceMs));
  }
  await killProcessTree(pid);
}

export async function runIsolatedCollection(request: CollectRequest, options: SandboxOptions): Promise<ScanEvidence> {
  const log = getLogger('worker-sandbox');
  const entry = resolveWorkerEntry();
  const sandboxDir = await mkdtemp(join(tmpdir(), 'thirdsentry-worker-'));
  try {
    await mkdir(join(sandboxDir, 'home'), { recursive: true });
    await mkdir(join(sandboxDir, 'tmp'), { recursive: true });
    const requestPath = join(sandboxDir, 'request.json');
    const outputDir = join(sandboxDir, 'evidence');
    await mkdir(outputDir, { recursive: true });
    await writeFile(requestPath, JSON.stringify(request));

    const env = buildWorkerEnv(sandboxDir, process.env, options.logLevel);
    log.debug({ entry, sandboxDir }, 'starting isolated browser worker');
    const child = fork(entry, [requestPath, outputDir], {
      cwd: sandboxDir,
      env,
      execArgv: ['--max-old-space-size=2048'],
      stdio: ['ignore', 'ignore', 'inherit', 'ipc'],
      serialization: 'json',
      detached: process.platform !== 'win32',
    });

    let timedOut = false;
    const exitCode = await new Promise<number | null>((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        timedOut = true;
        log.error({ timeoutMs: options.timeoutMs }, 'browser worker exceeded its time budget; stopping it');
        void stopChild(child, options.killGraceMs ?? 5_000);
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
    // Whatever the worker left behind (orphaned browsers) goes down with it.
    if (child.pid !== undefined) await killProcessTree(child.pid);

    if (exitCode === 0 && !timedOut) {
      return await assemble(outputDir, request, options);
    }
    const failure = timedOut
      ? `worker exceeded its time budget (${String(options.timeoutMs)} ms) and was killed`
      : `worker exited with code ${String(exitCode)}`;
    try {
      const partial = await assemble(outputDir, request, { ...options, failure });
      log.error({ failure }, 'browser worker did not finish; using the evidence it completed');
      return partial;
    } catch (error) {
      throw new ThirdSentryError(`Browser worker ${failure}`, {
        hint: 'Run with --verbose for worker logs. If Chromium cannot start its sandbox, see docs/troubleshooting.md.',
        cause: error,
      });
    }
  } finally {
    await rm(sandboxDir, { recursive: true, force: true, maxRetries: 3 }).catch(() => undefined);
  }
}

async function assemble(dir: string, request: CollectRequest, options: SandboxOptions & { failure?: string }): Promise<ScanEvidence> {
  try {
    return await assembleEvidence(dir, request, {
      maxBytes: options.maxEvidenceBytes,
      ...(options.failure ? { failure: options.failure } : {}),
    });
  } catch (error) {
    if (error instanceof EvidenceValidationError) throw error;
    throw new EvidenceValidationError(`Could not read browser worker evidence: ${(error as Error).message}`, error);
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
