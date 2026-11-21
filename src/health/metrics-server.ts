import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { ConfigError } from '../utils/errors.js';

/**
 * Tiny read-only HTTP exporter: GET/HEAD /metrics and /healthz, nothing else.
 * It renders from the files on disk on every request and never writes. There
 * is no authentication and no TLS: bind it to loopback (the default) and put a
 * reverse proxy in front of it if it must be reachable elsewhere.
 */

export interface MetricsServerOptions {
  readonly host: string;
  readonly port: number;
  /** Render the exposition text. Throwing makes /metrics and /healthz answer 503. */
  readonly render: () => Promise<string>;
}

export interface RunningMetricsServer {
  readonly host: string;
  readonly port: number;
  close(): Promise<void>;
}

export const DEFAULT_SERVE_HOST = '127.0.0.1';

/** Parse `--serve`: "9464", ":9464", "host:port" or "[v6]:port". */
export function parseServeAddress(value: string): { host: string; port: number } {
  const v = value.trim();
  const invalid = new ConfigError(`Invalid --serve value "${value}"`, 'Use host:port, e.g. 127.0.0.1:9464 (or just a port)');
  let host = DEFAULT_SERVE_HOST;
  let portText: string | undefined;
  if (/^\d{1,5}$/.test(v)) portText = v;
  else {
    const m = /^(?:\[([^\]]+)\]|([^:[\]]*)):(\d{1,5})$/.exec(v);
    if (!m) throw invalid;
    host = m[1] ?? (m[2] || DEFAULT_SERVE_HOST);
    portText = m[3];
  }
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw invalid;
  return { host, port };
}

export function isLoopbackHost(host: string): boolean {
  return host === 'localhost' || host === '::1' || host.startsWith('127.');
}

export async function startMetricsServer(options: MetricsServerOptions): Promise<RunningMetricsServer> {
  const server = http.createServer((req, res) => {
    void (async () => {
      const path = (req.url ?? '/').split('?')[0];
      const method = req.method ?? 'GET';
      if (method !== 'GET' && method !== 'HEAD') {
        res.writeHead(405, { allow: 'GET, HEAD', 'content-type': 'text/plain; charset=utf-8' }).end('method not allowed\n');
        return;
      }
      if (path !== '/metrics' && path !== '/healthz') {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }).end('not found: use /metrics or /healthz\n');
        return;
      }
      try {
        const body = await options.render();
        if (path === '/healthz') {
          res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }).end(method === 'HEAD' ? undefined : 'ok\n');
        } else {
          res
            .writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(body) })
            .end(method === 'HEAD' ? undefined : body);
        }
      } catch {
        // No details to the client: they may include file paths.
        res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' }).end('unavailable\n');
      }
    })();
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port, options.host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  return {
    host: options.host,
    port: address.port,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
