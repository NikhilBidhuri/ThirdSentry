import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import net, { type Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import { getLogger } from '../utils/logger.js';
import type { DestinationDecision, NetworkPolicy } from './network-policy.js';

/**
 * A minimal HTTP/HTTPS forward proxy that enforces the ScriptDrift network
 * policy for *every* connection the browser makes.
 *
 * Why a proxy rather than request interception?
 *  - Playwright request interception sees URLs, not the IP address the browser
 *    eventually connects to. Validating a hostname and then letting the browser
 *    resolve it again is vulnerable to DNS rebinding (time-of-check/time-of-use).
 *  - This proxy resolves the hostname once, validates every resolved address,
 *    and then opens the TCP connection to *that validated address*. The
 *    browser never performs its own DNS resolution for proxied traffic.
 *  - Each redirect hop is a new request/connection and is therefore
 *    re-validated automatically.
 *
 * HTTPS and WebSocket traffic arrives as CONNECT tunnels. TLS is end-to-end
 * between the browser and the destination; the proxy does not decrypt it.
 *
 * Limitations: traffic that does not honour the proxy (e.g. non-proxied
 * WebRTC/UDP, QUIC) must be disabled at browser launch and blocked at the
 * container network layer. See docs/security.md.
 */

export interface ProxyConnectionEvent {
  readonly timestamp: string;
  readonly host: string;
  readonly port: number;
  readonly method: string; // CONNECT or HTTP method
  readonly allowed: boolean;
  readonly reason?: string;
  readonly code?: string;
  readonly address?: string;
}

export interface EgressProxyOptions {
  readonly policy: NetworkPolicy;
  /** Maximum bytes transferred (both directions) per connection before it is cut. */
  readonly maxBytesPerConnection: number;
  readonly connectTimeoutMs: number;
  readonly idleTimeoutMs: number;
  readonly maxConnections: number;
  /** Maximum number of connection events retained for evidence. */
  readonly maxRecordedEvents: number;
  /** Interface to listen on. Defaults to 127.0.0.1. */
  readonly listenHost?: string;
  readonly listenPort?: number;
}

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

export class EgressProxy {
  private readonly options: EgressProxyOptions;
  private readonly server: http.Server;
  private readonly sockets = new Set<Duplex>();
  private readonly events: ProxyConnectionEvent[] = [];
  private droppedEvents = 0;
  private readonly log = getLogger('egress-proxy');
  private address: { host: string; port: number } | undefined;

  constructor(options: EgressProxyOptions) {
    this.options = options;
    this.server = http.createServer((req, res) => {
      void this.handleHttp(req, res);
    });
    this.server.maxConnections = options.maxConnections;
    this.server.on('connect', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
      void this.handleConnect(req, socket, head);
    });
    this.server.on('upgrade', (_req: IncomingMessage, socket: Duplex) => {
      // Chromium/Firefox/WebKit tunnel WebSockets with CONNECT when a proxy is set.
      socket.end('HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n');
    });
    this.server.on('connection', (socket: Socket) => this.track(socket));
    this.server.on('clientError', (_err, socket) => {
      socket.destroy();
    });
  }

  async start(): Promise<{ url: string; host: string; port: number }> {
    const host = this.options.listenHost ?? '127.0.0.1';
    await new Promise<void>((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.options.listenPort ?? 0, host, () => {
        this.server.off('error', reject);
        resolve();
      });
    });
    const addr = this.server.address();
    if (!addr || typeof addr === 'string') throw new Error('Egress proxy failed to bind');
    this.address = { host, port: addr.port };
    this.log.debug({ host, port: addr.port }, 'egress proxy listening');
    return { url: `http://${host}:${addr.port}`, host, port: addr.port };
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    if (!this.address) return;
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    this.address = undefined;
  }

  /** Connection events recorded so far (allowed and blocked). */
  getEvents(): { events: readonly ProxyConnectionEvent[]; dropped: number } {
    return { events: [...this.events], dropped: this.droppedEvents };
  }

  private track(socket: Duplex): void {
    this.sockets.add(socket);
    socket.once('close', () => this.sockets.delete(socket));
  }

  private record(event: ProxyConnectionEvent): void {
    // Blocked attempts are always logged, even when event retention is capped (standalone proxy).
    if (!event.allowed) this.log.info({ host: event.host, port: event.port, reason: event.reason }, 'blocked outbound connection');
    if (this.events.length >= this.options.maxRecordedEvents) {
      this.droppedEvents++;
      return;
    }
    this.events.push(event);
  }

  private recordDecision(method: string, decision: DestinationDecision): void {
    this.record({
      timestamp: new Date().toISOString(),
      host: decision.host,
      port: decision.port,
      method,
      allowed: decision.allowed,
      ...(decision.allowed ? { address: decision.address } : { reason: decision.reason, code: decision.code }),
    });
  }

  private async handleConnect(req: IncomingMessage, client: Duplex, head: Buffer): Promise<void> {
    this.track(client);
    client.on('error', () => client.destroy());
    const target = parseAuthority(req.url ?? '');
    if (!target) {
      client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      return;
    }
    const decision = await this.options.policy.resolveDestination(target.host, target.port);
    this.recordDecision('CONNECT', decision);
    if (!decision.allowed) {
      client.end(`HTTP/1.1 403 Forbidden\r\nX-ScriptDrift-Blocked: ${sanitizeHeader(decision.code)}\r\nConnection: close\r\n\r\n`);
      return;
    }
    const upstream = net.connect({ host: decision.address, port: decision.port, family: decision.family });
    this.track(upstream);
    const connectTimer = setTimeout(() => {
      upstream.destroy(new Error('connect timeout'));
    }, this.options.connectTimeoutMs);
    upstream.once('connect', () => {
      clearTimeout(connectTimer);
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) upstream.write(head);
      this.pipeWithLimits(client, upstream);
    });
    upstream.once('error', () => {
      clearTimeout(connectTimer);
      if (client.writable) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
      client.destroy();
    });
  }

  private pipeWithLimits(a: Duplex, b: Socket): void {
    let transferred = 0;
    const max = this.options.maxBytesPerConnection;
    const count = (chunk: Buffer): void => {
      transferred += chunk.length;
      if (transferred > max) {
        this.log.warn({ max }, 'connection exceeded byte limit; closing');
        a.destroy();
        b.destroy();
      }
    };
    a.on('data', count);
    b.on('data', count);
    b.setTimeout(this.options.idleTimeoutMs, () => {
      a.destroy();
      b.destroy();
    });
    a.on('error', () => b.destroy());
    b.on('error', () => a.destroy());
    a.on('close', () => b.destroy());
    b.on('close', () => a.destroy());
    a.pipe(b);
    b.pipe(a);
  }

  private async handleHttp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let url: URL;
    try {
      url = new URL(req.url ?? '');
    } catch {
      res.writeHead(400, { connection: 'close' }).end('Bad request');
      return;
    }
    if (url.protocol !== 'http:') {
      res.writeHead(400, { connection: 'close' }).end('Only http: is supported without CONNECT');
      return;
    }
    const port = url.port ? Number(url.port) : 80;
    const decision = await this.options.policy.resolveDestination(url.hostname, port);
    this.recordDecision(req.method ?? 'GET', decision);
    if (!decision.allowed) {
      res.writeHead(403, { 'x-scriptdrift-blocked': sanitizeHeader(decision.code), connection: 'close' }).end();
      return;
    }
    const headers: http.OutgoingHttpHeaders = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (!HOP_BY_HOP.has(key.toLowerCase()) && value !== undefined) headers[key] = value;
    }
    headers.host = url.host;
    let transferred = 0;
    const max = this.options.maxBytesPerConnection;
    const upstream = http.request({
      host: decision.address,
      family: decision.family,
      port,
      method: req.method,
      path: `${url.pathname}${url.search}`,
      headers,
      setHost: false,
      timeout: this.options.connectTimeoutMs,
    });
    upstream.on('timeout', () => upstream.destroy(new Error('upstream timeout')));
    upstream.on('response', (upRes) => {
      const outHeaders: http.OutgoingHttpHeaders = {};
      for (const [key, value] of Object.entries(upRes.headers)) {
        if (!HOP_BY_HOP.has(key.toLowerCase()) && value !== undefined) outHeaders[key] = value;
      }
      res.writeHead(upRes.statusCode ?? 502, upRes.statusMessage, outHeaders);
      upRes.on('data', (chunk: Buffer) => {
        transferred += chunk.length;
        if (transferred > max) {
          upRes.destroy();
          res.destroy();
        }
      });
      upRes.pipe(res);
    });
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502, { connection: 'close' });
      res.end();
    });
    req.on('data', (chunk: Buffer) => {
      transferred += chunk.length;
      if (transferred > max) {
        upstream.destroy();
        res.destroy();
      }
    });
    req.pipe(upstream);
  }
}

/** Parse a CONNECT authority ("host:port" or "[v6]:port"). */
export function parseAuthority(authority: string): { host: string; port: number } | undefined {
  const match = /^(?:\[([0-9a-fA-F:.%]+)\]|([^:\s/[\]]+)):(\d{1,5})$/.exec(authority.trim());
  if (!match) return undefined;
  const host = match[1] ?? match[2];
  const port = Number(match[3]);
  if (!host || port < 1 || port > 65535) return undefined;
  return { host, port };
}

function sanitizeHeader(value: string): string {
  return value.replace(/[^a-z0-9-]/gi, '');
}
