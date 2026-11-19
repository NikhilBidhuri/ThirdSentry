/**
 * Entry point of the isolated browser worker process.
 *
 *   node worker-entry.js <request.json> <evidence.json>
 *
 * Reads a CollectRequest, runs the browser collection and writes the raw
 * evidence. It has no access to alert credentials or storage locations.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { collectEvidence, type CollectRequest } from './collector.js';
import { configureLogger, getLogger } from '../utils/logger.js';

async function main(): Promise<void> {
  const [requestPath, outputPath] = process.argv.slice(2);
  if (!requestPath || !outputPath) {
    process.stderr.write('usage: worker-entry <request.json> <evidence.json>\n');
    process.exit(2);
  }
  configureLogger({ level: process.env.THIRDSENTRY_LOG_LEVEL ?? 'info' });
  const request = JSON.parse(await readFile(requestPath, 'utf8')) as CollectRequest;
  const evidence = await collectEvidence(request);
  await writeFile(outputPath, JSON.stringify(evidence));
}

main().then(
  () => process.exit(0),
  (error: unknown) => {
    getLogger('worker').error({ err: error instanceof Error ? error.message : String(error) }, 'browser worker failed');
    process.exit(1);
  },
);
