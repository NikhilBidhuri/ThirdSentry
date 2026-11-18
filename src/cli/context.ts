import type { Command } from 'commander';
import { configureLogger } from '../utils/logger.js';

export interface GlobalOptions {
  readonly config?: string;
  readonly verbose?: boolean;
  readonly json?: boolean;
  readonly quiet?: boolean;
}

/** Read global options from the root program and configure logging accordingly. */
export function globalOptions(command: Command): GlobalOptions {
  let root: Command = command;
  while (root.parent) root = root.parent;
  const opts = root.opts<GlobalOptions>();
  configureLogger({ verbose: opts.verbose === true, quiet: opts.json === true || opts.quiet === true });
  return opts;
}

export function logLevelFor(opts: GlobalOptions): string {
  if (opts.verbose) return 'debug';
  if (opts.json || opts.quiet) return 'warn';
  return 'info';
}
