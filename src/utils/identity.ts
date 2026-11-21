import { execFile } from 'node:child_process';
import { userInfo } from 'node:os';

/**
 * Name recorded as approver when `--approved-by` is not given: the Git
 * user.name of the working directory, else the OS user name. Never throws.
 */
export async function defaultApprover(cwd: string = process.cwd()): Promise<string | undefined> {
  const fromGit = await new Promise<string | undefined>((resolve) => {
    try {
      execFile('git', ['config', '--get', 'user.name'], { cwd, timeout: 3_000, windowsHide: true }, (error, stdout) => {
        resolve(error ? undefined : String(stdout).trim() || undefined);
      });
    } catch {
      resolve(undefined);
    }
  });
  if (fromGit) return fromGit.slice(0, 256);
  try {
    const name = userInfo().username.trim();
    return name ? name.slice(0, 256) : undefined;
  } catch {
    return undefined;
  }
}
