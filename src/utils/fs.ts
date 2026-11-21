import { copyFile, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';

const RENAME_RETRY_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);

/**
 * Rename with a few retries on Windows, where a concurrent reader or a virus
 * scanner can briefly hold the target open (EPERM/EBUSY).
 */
async function renameWithRetry(from: string, to: string): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      await rename(from, to);
      return;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? '';
      if (process.platform !== 'win32' || !RENAME_RETRY_CODES.has(code) || attempt >= 10) throw error;
      await new Promise((r) => setTimeout(r, 20 * (attempt + 1)));
    }
  }
}

function tempPathFor(path: string): string {
  return `${path}.${randomBytes(6).toString('hex')}.tmp`;
}

/**
 * Write a file atomically and durably: write a temp file in the same
 * directory, fsync it, then rename it over the target. Readers never see
 * partial content, and a crash leaves either the old or the new file.
 */
export async function writeFileAtomic(path: string, data: string | Uint8Array): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = tempPathFor(path);
  try {
    const handle = await open(tmp, 'wx');
    try {
      await handle.writeFile(data);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await renameWithRetry(tmp, path);
  } catch (error) {
    await rm(tmp, { force: true }).catch(() => undefined);
    throw error;
  }
}

/** Copy a file atomically (copy to a temp file next to the target, fsync, then rename). */
export async function copyFileAtomic(source: string, target: string): Promise<void> {
  await mkdir(dirname(target), { recursive: true });
  const tmp = tempPathFor(target);
  try {
    await copyFile(source, tmp);
    const handle = await open(tmp, 'r+');
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
    await renameWithRetry(tmp, target);
  } catch (error) {
    await rm(tmp, { force: true }).catch(() => undefined);
    throw error;
  }
}

/** Serialise JSON with stable (sorted) object keys so files diff cleanly in Git. */
export function stableStringify(value: unknown, indent = 2): string {
  return JSON.stringify(sortKeys(value), null, indent) + '\n';
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortKeys(v);
    }
    return out;
  }
  return value;
}

export async function writeJsonAtomic(path: string, value: unknown): Promise<void> {
  await writeFileAtomic(path, stableStringify(value));
}

/** Read a JSON file with a hard size cap to avoid loading unexpectedly huge files. */
export async function readJsonFile(path: string, maxBytes = 512 * 1024 * 1024): Promise<unknown> {
  const info = await stat(path);
  if (info.size > maxBytes) {
    throw new Error(`File ${path} is ${info.size} bytes which exceeds the ${maxBytes} byte limit`);
  }
  const text = await readFile(path, 'utf8');
  return JSON.parse(text) as unknown;
}

export async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}
