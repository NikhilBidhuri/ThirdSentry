import { resolve } from 'node:path';
import type { Command } from 'commander';
import { loadConfig } from '../../config/loader.js';
import { collectMetricsInput, renderMetrics } from '../../health/metrics.js';
import { pushMetrics } from '../../health/metrics-push.js';
import { isLoopbackHost, parseServeAddress, startMetricsServer } from '../../health/metrics-server.js';
import { writeFileAtomic } from '../../utils/fs.js';
import { getLogger } from '../../utils/logger.js';
import { globalOptions } from '../context.js';
import { color } from '../output.js';

interface MetricsOptions {
  textfile?: string;
  serve?: string;
  push?: string;
}

export function registerMetrics(program: Command): void {
  program
    .command('metrics')
    .description('Render Prometheus metrics from the latest report, scan health and alert state (read-only)')
    .option('--textfile <path>', 'write the metrics atomically to this file (node_exporter textfile collector; use a .prom name)')
    .option('--serve <host:port>', 'serve /metrics and /healthz over HTTP, read-only, no authentication (default host 127.0.0.1)')
    .option('--push <url>', 'push the metrics to a Prometheus Pushgateway (job "thirdsentry" unless the URL has /metrics/job/...)')
    .action(async (opts: MetricsOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const render = async (): Promise<string> => renderMetrics(await collectMetricsInput(resolved));
      if (opts.serve) {
        const { host, port } = parseServeAddress(opts.serve);
        if (!isLoopbackHost(host)) {
          process.stderr.write(`${color.yellow(`Warning: serving metrics on ${host} without authentication or TLS; restrict access with a firewall or reverse proxy.`)}\n`);
        }
        const server = await startMetricsServer({ host, port, render });
        getLogger('metrics').info({ listen: `${server.host}:${server.port}` }, 'metrics exporter ready (GET /metrics, /healthz)');
        await new Promise<void>((done) => {
          const stop = (): void => {
            void server.close().then(() => done());
          };
          process.once('SIGTERM', stop);
          process.once('SIGINT', stop);
        });
        return;
      }
      const body = await render();
      if (opts.textfile) await writeFileAtomic(resolve(opts.textfile), body);
      if (opts.push) await pushMetrics(opts.push, body);
      if (!opts.textfile && !opts.push) process.stdout.write(body);
    });
}
