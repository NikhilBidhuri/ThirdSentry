import { SEVERITIES, type Severity } from '../config/schema.js';
import { ConfigError } from '../utils/errors.js';

export type FailOn = Severity | 'none';

export function parseFailOn(value: string | undefined, fallback: FailOn): FailOn {
  if (value === undefined) return fallback;
  const v = value.trim().toLowerCase();
  if (v === 'none' || (SEVERITIES as readonly string[]).includes(v)) return v as FailOn;
  throw new ConfigError(`Invalid --fail-on value "${value}"`, `Use one of: ${[...SEVERITIES, 'none'].join(', ')}`);
}
