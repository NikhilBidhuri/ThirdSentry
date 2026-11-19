import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Build the project once before the test run: the isolated browser worker is
 * started as a separate Node.js process and must run compiled JavaScript.
 */
export default function setup(): () => void {
  const root = process.cwd();
  const tsc = join(root, 'node_modules', 'typescript', 'bin', 'tsc');
  execFileSync(process.execPath, [tsc, '-p', 'tsconfig.build.json'], { cwd: root, stdio: 'inherit' });
  return () => {
    rmSync(join(root, 'tests', '.tmp'), { recursive: true, force: true });
  };
}
