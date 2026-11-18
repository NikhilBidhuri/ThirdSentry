import { ExitCode, type ExitCodeValue } from './exit-codes.js';

/** Base class for all expected (user-facing) ScriptDrift errors. */
export class ScriptDriftError extends Error {
  readonly exitCode: ExitCodeValue;
  readonly hint: string | undefined;

  constructor(message: string, options: { exitCode?: ExitCodeValue; hint?: string; cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = new.target.name;
    this.exitCode = options.exitCode ?? ExitCode.InternalError;
    this.hint = options.hint;
  }
}

export class ConfigError extends ScriptDriftError {
  constructor(message: string, hint?: string) {
    super(message, { exitCode: ExitCode.ConfigError, ...(hint === undefined ? {} : { hint }) });
  }
}

export class UrlValidationError extends ScriptDriftError {
  constructor(message: string, hint?: string) {
    super(message, { exitCode: ExitCode.ConfigError, ...(hint === undefined ? {} : { hint }) });
  }
}

export class EvidenceValidationError extends ScriptDriftError {
  constructor(message: string, cause?: unknown) {
    super(message, { exitCode: ExitCode.InternalError, cause });
  }
}

export class BaselineError extends ScriptDriftError {
  constructor(message: string, hint?: string) {
    super(message, { exitCode: ExitCode.ConfigError, ...(hint === undefined ? {} : { hint }) });
  }
}

/** Convert anything thrown into a printable message without leaking stack traces to users by default. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}
