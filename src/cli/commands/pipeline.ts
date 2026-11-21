import { resolve } from 'node:path';
import type { Command } from 'commander';
import { createNetworkPolicy, loadConfig, selectSites } from '../../config/loader.js';
import { analysisExitCode, analyzeScan, missingBaselineNotice, publishReports } from '../../monitoring/analysis-runner.js';
import { buildCollectRequest, persistScan } from '../../monitoring/scan-manager.js';
import { parseFormats } from '../../reporting/index.js';
import { EgressProxy, isValidRunId } from '../../security/egress-proxy.js';
import { applyTrustedProxyEvents, DEFAULT_MAX_BYTES_PER_RUN, PROXY_EVENTS_PER_SITE, ProxyEventLogWriter, readProxyEventLog } from '../../security/proxy-event-log.js';
import { validateEvidence } from '../../security/worker-sandbox.js';
import { ConfigError } from '../../utils/errors.js';
import { readJsonFile } from '../../utils/fs.js';
import { getLogger } from '../../utils/logger.js';
import { globalOptions } from '../context.js';
import { parseFailOn } from '../fail-on.js';
import { printReport } from '../findings-output.js';
import { color, print, printJson } from '../output.js';
import { printScanSummary } from './scan.js';

/**
 * Split pipeline used by the container deployment (docs/docker.md):
 *
 *   egress-proxy  (only component with internet access, enforces the network policy,
 *                  records connection events per run/site in --events-dir)
 *   collect       (browser worker; no secrets, no baselines, network only via the proxy;
 *                  tags its proxy connections with <run-id>.<site>)
 *   analyze       (no network; baselines read-only; replaces the scanner's untrusted
 *                  connection events with the proxy's record; writes scan results and reports)
 *   alert         (only component with alert credentials)
 */

interface CollectOptions {
  out: string;
  site?: string;
  proxy?: string;
  runId?: string;
  chromiumSandbox?: boolean;
}

interface AnalyzeOptions {
  evidence: string;
  proxyEvents?: string;
  format?: string;
  output?: string;
  failOn?: string;
  allowMissingBaseline?: boolean;
}

function parseRunId(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (!isValidRunId(value)) throw new ConfigError(`Invalid --run-id "${value}"`, 'Use 1-64 letters, digits, "_" or "-"');
  return value;
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
    .option('--run-id <id>', 'run id used to tag connections to the external proxy (default: the scan id)')
    .option('--no-chromium-sandbox', 'disable Chromium\'s renderer sandbox (only inside an isolated container)')
    .action(async (opts: CollectOptions, command: Command) => {
      const g = globalOptions(command);
      const runId = parseRunId(opts.runId);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const sites = selectSites(resolved, opts.site);
      if (sites.length === 0) throw new ConfigError('No enabled sites to scan');
      const base = buildCollectRequest(resolved, sites);
      const request = {
        ...base,
        isolation: 'container' as const,
        chromiumSandbox: opts.chromiumSandbox !== false && base.chromiumSandbox,
        network: { ...base.network, ...(opts.proxy ? { externalProxy: opts.proxy } : {}) },
        ...(runId ? { proxyRunId: runId } : {}),
      };
      // Loaded lazily: only this command needs the browser stack.
      const { collectEvidence } = await import('../../browser/collector.js');
      const { writeEvidenceJson } = await import('../../browser/evidence-sink.js');
      const evidence = await collectEvidence(request);
      const out = resolve(opts.out);
      // Streamed page by page: a single JSON.stringify of a large scan can exceed V8's string limit.
      await writeEvidenceJson(out, evidence);
      const proxyRunId = opts.proxy ? (runId ?? evidence.scanId) : undefined;
      if (g.json) printJson({ evidence: out, scanId: evidence.scanId, ...(proxyRunId ? { proxyRunId } : {}) });
      else print(color.green(`Evidence for scan ${evidence.scanId} written to ${out}${proxyRunId ? ` (proxy run id ${proxyRunId})` : ''}`));
    });

  program
    .command('analyze')
    .description('[container pipeline] Validate collected evidence, compare with baselines and write reports (no network, no alerts)')
    .requiredOption('--evidence <file>', 'evidence file produced by "collect"')
    .option('--proxy-events <file>', 'egress-proxy event record of this run (<events-dir>/<run-id>.ndjson); replaces the connection events reported by the scanner')
    .option('-f, --format <formats>', 'report formats: json, sarif, html')
    .option('-o, --output <dir>', 'directory for reports')
    .option('--fail-on <severity>', 'exit with code 1 if a finding is at least this severe')
    .option('--allow-missing-baseline', 'exit 0 instead of 3 when a scanned site has no approved baseline yet')
    .action(async (opts: AnalyzeOptions, command: Command) => {
      const g = globalOptions(command);
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const failOn = parseFailOn(opts.failOn, resolved.config.failOn);
      const formats = parseFormats(opts.format, resolved.config.reporting.formats);
      // Evidence is untrusted: size-limited read + strict schema validation.
      let evidence = validateEvidence(await readJsonFile(resolve(opts.evidence), resolved.config.limits.maxEvidenceBytes));
      if (opts.proxyEvents) {
        // The proxy is trusted, the scanner is not: the scanner's connection events are discarded.
        const trusted = await readProxyEventLog(resolve(opts.proxyEvents), DEFAULT_MAX_BYTES_PER_RUN + 1024 * 1024);
        evidence = applyTrustedProxyEvents(evidence, trusted);
      } else if (evidence.isolation === 'container') {
        evidence = {
          ...evidence,
          issues: [
            ...evidence.issues,
            {
              level: 'warning',
              code: 'proxy-events-not-provided',
              message: 'analyze ran without --proxy-events: blocked-connection evidence comes from the scanner itself, which is not trusted.',
            },
          ],
        };
      }
      const run = await persistScan(resolved, evidence);
      const { report } = await analyzeScan(resolved, run.result, { scanPath: run.scanPath, updateState: true });
      const { scanReportDir: _scanDir, perScan: _perScan, ...written } = await publishReports(resolved, report, run.result, formats, {
        ...(opts.output ? { outputDir: opts.output } : {}),
        alwaysJson: true,
      });
      if (g.json) printJson({ scan: run.result.scanId, report, reports: written });
      else {
        printScanSummary(run.result, g.verbose === true);
        printReport(report, g.verbose === true);
        for (const [format, path] of Object.entries(written)) print(color.gray(`${format.toUpperCase()} report: ${path}`));
      }
      const allowMissingBaseline = opts.allowMissingBaseline === true;
      const notice = missingBaselineNotice(report, allowMissingBaseline);
      if (notice) process.stderr.write(`${notice}
`);
      process.exitCode = analysisExitCode(report, { failOn, allowMissingBaseline });
    });

  program
    .command('egress-proxy')
    .description('[container pipeline] Run the egress proxy that enforces the network policy for browser traffic')
    .option('--listen <host:port>', 'address to listen on', '0.0.0.0:3128')
    .option('--events-dir <dir>', 'record events of tagged (<run-id>.<site>) connections as <dir>/<run-id>.ndjson')
    .action(async (opts: { listen: string; eventsDir?: string }, command: Command) => {
      const g = globalOptions(command);
      // The configuration is read once, here: restart the proxy after changing thirdsentry.yml.
      const resolved = await loadConfig({ ...(g.config ? { configPath: g.config } : {}) });
      const listen = parseListen(opts.listen);
      const net = resolved.config.security.network;
      let eventLog: ProxyEventLogWriter | undefined;
      if (opts.eventsDir) {
        eventLog = new ProxyEventLogWriter({ dir: resolve(opts.eventsDir) });
        try {
          eventLog.init();
        } catch (error) {
          throw new ConfigError(
            `Proxy event directory ${opts.eventsDir} is not writable: ${(error as Error).message}`,
            'Mount the proxy-events volume read-write into the egress-proxy container',
          );
        }
      }
      const proxy = new EgressProxy({
        policy: createNetworkPolicy(resolved.config),
        maxBytesPerConnection: resolved.config.limits.maxBytesPerConnection,
        connectTimeoutMs: net.connectTimeoutMs,
        idleTimeoutMs: net.idleTimeoutMs,
        maxConnections: 1024,
        // Per site and kind. Without --events-dir nothing is retained (blocked connections are still logged).
        maxRecordedEvents: eventLog ? PROXY_EVENTS_PER_SITE : 0,
        ...(eventLog ? { eventSink: eventLog } : {}),
        listenHost: listen.host,
        listenPort: listen.port,
      });
      const address = await proxy.start();
      getLogger('egress-proxy').info({ listen: `${address.host}:${address.port}`, eventsDir: opts.eventsDir ?? null }, 'egress proxy ready');
      await new Promise<void>((resolveStop) => {
        const stop = (): void => {
          eventLog?.close();
          void proxy.stop().then(() => resolveStop());
        };
        process.once('SIGTERM', stop);
        process.once('SIGINT', stop);
      });
    });
}
