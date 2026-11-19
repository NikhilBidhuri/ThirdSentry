import { resolve } from 'node:path';
import type { Command } from 'commander';
import { collectEvidence } from '../../browser/collector.js';
import { createNetworkPolicy, loadConfig, selectSites } from '../../config/loader.js';
import { analyzeScan, exceedsThreshold, saveReportJson } from '../../monitoring/analysis-runner.js';
import { buildCollectRequest, persistScan } from '../../monitoring/scan-manager.js';
import { parseFormats, writeReports } from '../../reporting/index.js';
import { EgressProxy } from '../../security/egress-proxy.js';
import { validateEvidence } from '../../security/worker-sandbox.js';
import { ConfigError } from '../../utils/errors.js';
import { ExitCode } from '../../utils/exit-codes.js';
import { readJsonFile, writeFileAtomic } from '../../utils/fs.js';
import { getLogger } from '../../utils/logger.js';
import { globalOptions } from '../context.js';
import { parseFailOn } from '../fail-on.js';
import { printReport } from '../findings-output.js';
import { color, print, printJson } from '../output.js';
import { printScanSummary } from './scan.js';

/**
 * Split pipeline used by the container deployment (docs/docker.md):
 *
 *   egress-proxy  (only component with internet access, enforces the network policy)
 *   collect       (browser worker; no secrets, no baselines, network only via the proxy)
 *   analyze       (no network; baselines read-only; writes scan results and reports)
 *   alert         (only component with alert credentials)
 */

interface CollectOptions {
  out: string;
  site?: string;
  proxy?: string;
  chromiumSandbox?: boolean;
}

interface AnalyzeOptions {
  evidence: string;
  format?: string;
  output?: string;
  failOn?: string;
}

function parseListen(value: string): { host: string; port: number } {
  const m = /^(?:\[([^\]]+)\]|([^:]+)):(\d{1,5})$/.exec(value);
  const port = Number(m?.[3]);
  if (!m || !Number.isInteger(port) || port < 1 || port > 65535) throw new ConfigError(`Invalid --listen value "${value}"`, 'Use host:port, e.g. 0.0.0.0:3128');
  return { host: m[1] ?? m[2] ?? '127.0.0.1', port };
}

export function registerPipeline(program: Command): void {
  program
    .command('collect')
    .description('[container pipeline] Run only the browser collection and write untrusted evidence to a file')
    .requiredOption('--out <file>', 'evidence output file')
    .option('-s, --site <names>', 'only these sites')
    .option('--proxy <url>', 'external egress proxy URL (e.g. http://egress-proxy:3128)')
    .option('--no-chromium-sandbox', 'disable Chromium\'s renderer sandbox (only inside an isolated container)')
    .action(async (opts: CollectOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const sites = selectSites(resolved, opts.site);
      if (sites.length === 0) throw new ConfigError('No enabled sites to scan');
      const base = buildCollectRequest(resolved, sites);
      const request = {
        ...base,
        isolation: 'container' as const,
        chromiumSandbox: opts.chromiumSandbox !== false && base.chromiumSandbox,
        network: { ...base.network, ...(opts.proxy ? { externalProxy: opts.proxy } : {}) },
      };
      const evidence = await collectEvidence(request);
      const out = resolve(opts.out);
      await writeFileAtomic(out, JSON.stringify(evidence));
      if (g.json) printJson({ evidence: out, scanId: evidence.scanId });
      else print(color.green(`Evidence for scan ${evidence.scanId} written to ${out}`));
    });

  program
    .command('analyze')
    .description('[container pipeline] Validate collected evidence, compare with baselines and write reports (no network, no alerts)')
    .requiredOption('--evidence <file>', 'evidence file produced by "collect"')
    .option('-f, --format <formats>', 'report formats: json, sarif, html')
    .option('-o, --output <dir>', 'directory for reports')
    .option('--fail-on <severity>', 'exit with code 1 if a finding is at least this severe')
    .action(async (opts: AnalyzeOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const failOn = parseFailOn(opts.failOn, resolved.config.failOn);
      const formats = parseFormats(opts.format, resolved.config.reporting.formats);
      // Evidence is untrusted: size-limited read + strict schema validation.
      const evidence = validateEvidence(await readJsonFile(resolve(opts.evidence), resolved.config.limits.maxEvidenceBytes));
      const run = await persistScan(resolved, evidence);
      const { report } = await analyzeScan(resolved, run.result, { scanPath: run.scanPath, updateState: true });
      await saveReportJson(resolved, report);
      const written = await writeReports(resolved, report, run.result, formats, opts.output);
      if (g.json) printJson({ scan: run.result.scanId, report, reports: written });
      else {
        printScanSummary(run.result, g.verbose === true);
        printReport(report, g.verbose === true);
        for (const [format, path] of Object.entries(written)) print(color.gray(`${format.toUpperCase()} report: ${path}`));
      }
      if (exceedsThreshold(report, failOn)) process.exitCode = ExitCode.FindingsThresholdExceeded;
      else if (run.result.status !== 'complete') process.exitCode = ExitCode.ScanIncomplete;
    });

  program
    .command('egress-proxy')
    .description('[container pipeline] Run the egress proxy that enforces the network policy for browser traffic')
    .option('--listen <host:port>', 'address to listen on', '0.0.0.0:3128')
    .action(async (opts: { listen: string }, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const listen = parseListen(opts.listen);
      const net = resolved.config.security.network;
      const proxy = new EgressProxy({
        policy: createNetworkPolicy(resolved.config),
        maxBytesPerConnection: resolved.config.limits.maxBytesPerConnection,
        connectTimeoutMs: net.connectTimeoutMs,
        idleTimeoutMs: net.idleTimeoutMs,
        maxConnections: 1024,
        maxRecordedEvents: 0,
        listenHost: listen.host,
        listenPort: listen.port,
      });
      const address = await proxy.start();
      getLogger('egress-proxy').info({ listen: `${address.host}:${address.port}` }, 'egress proxy ready');
      await new Promise<void>((resolveStop) => {
        const stop = (): void => {
          void proxy.stop().then(() => resolveStop());
        };
        process.once('SIGTERM', stop);
        process.once('SIGINT', stop);
      });
    });
}
