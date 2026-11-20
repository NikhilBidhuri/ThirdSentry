/**
 * Entry point of the isolated browser worker process.
 *
 *   node worker-entry.js <request.json> <evidence-dir>
 *
 * Reads a CollectRequest, runs the browser collection and writes the raw
 * evidence incrementally (one file per page) into <evidence-dir>. It has no access to alert credentials or storage locations.
 */
import { readFile } from 'node:fs/promises';
import { runCollection, type CollectRequest } from './collector.js';
import { DirectorySink } from './evidence-sink.js';
import { configureLogger, getLogger } from '../utils/logger.js';

async function main(): Promise<void> {
  const [requestPath, outputPath] = process.argv.slice(2);
  if (!requestPath || !outputPath) {
    process.stderr.write('usage: worker-entry <request.json> <evidence-dir>\n');
    process.exit(2);
  }
  configureLogger({ level: process.env.THIRDSENTRY_LOG_LEVEL ?? 'info' });
  const request = JSON.parse(await readFile(requestPath, 'utf8')) as CollectRequest;
  await runCollection(request, new DirectorySink(outputPath));
}

main().then(
  () => process.exit(0),
  (error: unknown) => {
    getLogger('worker').error({ err: error instanceof Error ? error.message : String(error) }, 'browser worker failed');
    process.exit(1);
  },
);
