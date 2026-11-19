import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

interface PackageInfo {
  readonly version: string;
  readonly homepage?: string;
}

let cached: PackageInfo | undefined;

function packageInfo(): PackageInfo {
  if (cached) return cached;
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 5; i++) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { name?: string; version?: string; homepage?: string };
      if (pkg.name === 'thirdsentry' && pkg.version) {
        cached = { version: pkg.version, ...(pkg.homepage ? { homepage: pkg.homepage } : {}) };
        return cached;
      }
    } catch {
      // keep walking up
    }
    dir = dirname(dir);
  }
  cached = { version: '0.0.0' };
  return cached;
}

/** Resolve the package version from package.json (works from src/ and dist/). */
export function toolVersion(): string {
  return packageInfo().version;
}

/** Project homepage from package.json, if one is declared. */
export function projectHomepage(): string | undefined {
  return packageInfo().homepage;
}
