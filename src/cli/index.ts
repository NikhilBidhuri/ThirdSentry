import { Command, CommanderError } from 'commander';
import { ThirdSentryError, errorMessage } from '../utils/errors.js';
import { ExitCode } from '../utils/exit-codes.js';
import { toolVersion } from '../utils/version.js';
import { registerInit } from './commands/init.js';
import { registerScan } from './commands/scan.js';
import { registerBaseline } from './commands/baseline.js';
import { registerDiff } from './commands/diff.js';
import { registerReport } from './commands/report.js';
import { registerAlert } from './commands/alert.js';
import { registerPipeline } from './commands/pipeline.js';
import { registerCspLint } from './commands/csp-lint.js';
import { registerInventory } from './commands/inventory.js';
import { registerCleanup } from './commands/cleanup.js';
import { color } from './output.js';
import { lockStorageFor, releaseStorageLock } from './context.js';

export function buildProgram(): Command {
  const program = new Command('thirdsentry');
  program
    .description('Watch the code you don\'t control: detect unexpected changes in third-party JavaScript.')
    .version(toolVersion(), '-V, --version')
    .option('-c, --config <path>', 'path to thirdsentry.yml')
    .option('-v, --verbose', 'verbose logging')
    .option('--json', 'machine-readable JSON output on stdout')
    .option('-q, --quiet', 'only log warnings and errors')
    .option('--lock-timeout <seconds>', 'wait up to this long for another ThirdSentry command using the same storage directory (default 0: fail immediately)')
    .showHelpAfterError()
    .exitOverride();
  // Single writer: every command that writes the storage directory holds the
  // storage lock for its whole run (released in main()).
  program.hook('preAction', async (_root, actionCommand) => {
    await lockStorageFor(actionCommand);
  });
  registerInit(program);
  registerScan(program);
  registerBaseline(program);
  registerDiff(program);
  registerReport(program);
  registerAlert(program);
  registerCspLint(program);
  registerInventory(program);
  registerCleanup(program);
  registerPipeline(program);
  return program;
}

export async function main(argv: readonly string[]): Promise<number> {
  const program = buildProgram();
  try {
    await program.parseAsync([...argv]);
    return typeof process.exitCode === 'number' ? process.exitCode : ExitCode.Ok;
  } catch (error) {
    if (error instanceof CommanderError) {
      if (error.code === 'commander.helpDisplayed' || error.code === 'commander.version' || error.code === 'commander.help') return ExitCode.Ok;
      return ExitCode.ConfigError;
    }
    if (error instanceof ThirdSentryError) {
      process.stderr.write(`${color.red('Error:')} ${error.message}\n`);
      if (error.hint) process.stderr.write(`${color.yellow('Hint:')} ${error.hint}\n`);
      return error.exitCode;
    }
    process.stderr.write(`${color.red('Unexpected error:')} ${errorMessage(error)}\n`);
    if (process.argv.includes('--verbose') || process.argv.includes('-v')) {
      process.stderr.write(`${error instanceof Error ? (error.stack ?? '') : ''}\n`);
    } else {
      process.stderr.write('Run with --verbose for details.\n');
    }
    return ExitCode.InternalError;
  } finally {
    await releaseStorageLock();
  }
}
