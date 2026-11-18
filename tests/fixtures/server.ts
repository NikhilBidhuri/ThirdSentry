import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * Local multi-host fixture web server for integration tests.
 *
 * One HTTP server answers for several fake hostnames (shop.test,
 * cdn.vendor-a.test, ...); requests are dispatched on the Host header. The
 * browser reaches these hosts through the ScriptDrift egress proxy using
 * `security.network.resolverOverrides`, so no real DNS or internet access is
 * needed and no production website is ever contacted.
 *
 * Routes can be changed at runtime to simulate a vendor changing its script.
 */

export interface Route {
  status?: number;
  headers?: Record<string, string | string[]>;
  body?: string | Buffer;
  /** Delay before responding (ms). */
  delayMs?: number;
  /** Redirect target (sets 302 + Location). */
  redirect?: string;
}

export type RouteTable = Map<string, Route>; // key: "host/path"

export class FixtureServer {
  readonly routes: RouteTable = new Map();
  readonly hits: string[] = [];
  private server: http.Server | undefined;
  port = 0;

  set(host: string, path: string, route: Route): void {
    this.routes.set(`${host}${path}`, route);
  }

  js(host: string, path: string, body: string, extraHeaders: Record<string, string> = {}): void {
    this.set(host, path, { headers: { 'content-type': 'application/javascript', ...extraHeaders }, body });
  }

  html(host: string, path: string, body: string, extraHeaders: Record<string, string | string[]> = {}): void {
    this.set(host, path, { headers: { 'content-type': 'text/html; charset=utf-8', ...extraHeaders }, body });
  }

  url(host: string, path = '/'): string {
    return `http://${host}:${this.port}${path}`;
  }

  async start(): Promise<void> {
    this.server = http.createServer((req, res) => this.handle(req, res));
    this.server.keepAliveTimeout = 1000;
    await new Promise<void>((resolve) => this.server?.listen(0, '127.0.0.1', resolve));
    this.port = (this.server.address() as AddressInfo).port;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    const host = (req.headers.host ?? '').split(':')[0] ?? '';
    const path = (req.url ?? '/').split('?')[0] ?? '/';
    this.hits.push(`${host}${req.url ?? ''}`);
    const route = this.routes.get(`${host}${path}`);
    if (!route) {
      res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
      return;
    }
    const respond = (): void => {
      if (route.redirect) {
        res.writeHead(302, { location: route.redirect.replace('{port}', String(this.port)) }).end();
        return;
      }
      const body = typeof route.body === 'string' ? route.body.replaceAll('{port}', String(this.port)) : route.body;
      res.writeHead(route.status ?? 200, { 'cache-control': 'no-store', ...route.headers });
      res.end(body);
    };
    if (route.delayMs) setTimeout(respond, route.delayMs);
    else respond();
  }
}

/** Smallest valid WebAssembly module (magic + version). */
export const EMPTY_WASM = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

export const FIXTURE_HOSTS = [
  'shop.test',
  'cdn.vendor-a.test',
  'analytics.vendor-b.test',
  'collect.vendor-c.test',
  'frame.vendor-d.test',
  'exfil.vendor-e.test',
  'internal.test',
] as const;

/** Hosts allowed to resolve to loopback in tests. internal.test is deliberately NOT allowed. */
export const ALLOWED_TEST_HOSTS = FIXTURE_HOSTS.filter((h) => h !== 'internal.test');
