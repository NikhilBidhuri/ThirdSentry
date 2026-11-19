/**
 * Process exit codes. Kept stable so CI systems (e.g. GitHub Actions) can
 * distinguish "findings above threshold" from "the scan itself is unreliable".
 */
export const ExitCode = {
  /** Scan completed and no finding met the --fail-on threshold. */
  Ok: 0,
  /** Scan completed and at least one finding met the --fail-on threshold. */
  FindingsThresholdExceeded: 1,
  /** Invalid configuration, CLI usage or input files. */
  ConfigError: 2,
  /** One or more pages could not be scanned completely. Results are partial. */
  ScanIncomplete: 3,
  /** Unexpected internal error. */
  InternalError: 4,
} as const;

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];
