import { pino, type Logger } from 'pino';

/**
 * Structured logger. Logs go to stderr so that stdout stays reserved for
 * machine-readable output (`--json`). Known secret-bearing fields are redacted.
 */
const REDACT_PATHS = [
  'password',
  'pass',
  'token',
  'secret',
  'webhookUrl',
  'authorization',
  'cookie',
  '*.password',
  '*.pass',
  '*.token',
  '*.secret',
  '*.webhookUrl',
  '*.authorization',
  '*.cookie',
  'headers.authorization',
  'headers.cookie',
  'headers["set-cookie"]',
];

let rootLogger: Logger = createLogger('info');

export function createLogger(level: string): Logger {
  return pino(
    {
      name: 'thirdsentry',
      level,
      redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
      base: null,
      timestamp: pino.stdTimeFunctions.isoTime,
    },
    pino.destination({ fd: 2, sync: true }),
  );
}

export function configureLogger(options: { verbose?: boolean; quiet?: boolean; level?: string }): Logger {
  const level = options.level ?? (options.verbose ? 'debug' : options.quiet ? 'warn' : 'info');
  rootLogger = createLogger(level);
  return rootLogger;
}

export function getLogger(component?: string): Logger {
  return component ? rootLogger.child({ component }) : rootLogger;
}
