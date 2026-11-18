import { ConfigError } from '../utils/errors.js';

/**
 * `${NAME}` interpolation for alert settings. Only the alert publisher calls
 * this, at send time, so scans never need (or see) alert credentials.
 */

const PLACEHOLDER = /\$\{([A-Z_][A-Z0-9_]*)\}/g;

export function referencedVariables(value: string): string[] {
  return [...value.matchAll(PLACEHOLDER)].map((m) => m[1] as string);
}

export function resolveEnv(value: string, env: NodeJS.ProcessEnv, setting: string): string {
  const missing = referencedVariables(value).filter((name) => !env[name]);
  if (missing.length > 0) {
    throw new ConfigError(`${setting} references environment variable(s) that are not set: ${missing.join(', ')}`, 'Set them in the environment of the alert publisher (never in scriptdrift.yml).');
  }
  return value.replace(PLACEHOLDER, (_m, name: string) => env[name] ?? '');
}

/** True when a secret-bearing setting contains a literal value instead of an ${ENV} reference. */
export function isLiteralSecret(value: string | undefined): boolean {
  return value !== undefined && referencedVariables(value).length === 0;
}

/** Remove every resolved secret value from a message before it is logged or printed. */
export function redactSecrets(message: string, secrets: ReadonlyArray<string | undefined>): string {
  let out = message;
  for (const secret of secrets) {
    if (secret && secret.length >= 6) out = out.split(secret).join('[REDACTED]');
  }
  return out;
}
