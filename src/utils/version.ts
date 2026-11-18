import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

let cached: string | undefined;

/** Resolve the package version from package.json (works from src/ and dist/). */
export function toolVersion(): string {
  if (cached) return cached;
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { name?: string; version?: string };
      if (pkg.name === 'scriptdrift' && pkg.version) {
        cached = pkg.version;
        return cached;
      }
    } catch {
      // keep walking up
    }
    dir = dirname(dir);
  }
  cached = '0.0.0';
  return cached;
}
