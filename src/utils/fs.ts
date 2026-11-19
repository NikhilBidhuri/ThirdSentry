import { mkdir, readFile, rename, writeFile, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';

/** Write a file atomically (write to temp file then rename) so readers never see partial JSON. */
export async function writeFileAtomic(path: string, data: string | Uint8Array): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  await writeFile(tmp, data);
  await rename(tmp, path);
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
