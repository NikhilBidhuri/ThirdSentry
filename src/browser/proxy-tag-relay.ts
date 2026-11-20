import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import net, { type Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import { formatClientTag, parseAuthority } from '../security/egress-proxy.js';
import { getLogger } from '../utils/logger.js';

/**
 * Local relay used by `collect` in the container pipeline. The browser talks
 * to this relay, which forwards every request and CONNECT tunnel unchanged to
 * the external egress proxy, adding a `Proxy-Authorization` header that tags
 * the connection with `<runId>.<site>`. The egress proxy (trusted) files its
 * connection events under that tag, so the analyzer can attribute them per
 * site without trusting the scanner's own report.
 *
 * Browsers only send proxy credentials after a 407 challenge; the relay sends
 * the tag on every request instead, so the egress proxy never has to
 * challenge (and never authenticates). The relay enforces nothing: policy,
 * byte caps and timeouts are applied by the egress proxy.
 */

const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

export interface ProxyTagRelayOptions {
  /** External egress proxy URL, e.g. http://egress-proxy:3128 */
  readonly upstream: string;
  readonly runId: string;
}

export class ProxyTagRelay {
  private readonly upstreamHost: string;
  private readonly upstreamPort: number;
  private readonly runId: string;
  private readonly server: http.Server;
  private readonly agent = new http.Agent({ keepAlive: true, maxSockets: 64 });
  private readonly sockets = new Set<Duplex>();
  private readonly log = getLogger('proxy-tag-relay');
  private tag: string | undefined;
  private listening = false;

  constructor(options: ProxyTagRelayOptions) {
    const url = new URL(options.upstream);
    if (url.protocol !== 'http:') throw new Error(`External proxy must be an http:// URL (got ${url.protocol})`);
    this.upstreamHost = url.hostname.replace(/^\[|\]$/g, '');
    this.upstreamPort = url.port ? Number(url.port) : 80;
    this.runId = options.runId;
    formatClientTag({ runId: this.runId, site: 'probe' }); // validates the run id early
    this.server = http.createServer((req, res) => this.forwardHttp(req, res));
    this.server.on('connect', (req: IncomingMessage, socket: Duplex, head: Buffer) => this.forwardConnect(req, socket, head));
    this.server.on('upgrade', (_req: IncomingMessage, socket: Duplex) => {
      socket.on('error', () => socket.destroy());
      socket.end('HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n');
    });
    this.server.on('connection', (socket: Socket) => {
      socket.on('error', () => socket.destroy());
      this.track(socket);
    });
    this.server.on('clientError', (_err, socket) => socket.destroy());
  }

  /** Tag all following connections with this site. */
  setSite(site: string): void {
    this.tag = formatClientTag({ runId: this.runId, site });
  }

  async start(): Promise<{ url: string }> {
    await new Promise<void>((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(0, '127.0.0.1', () => {
        this.server.off('error', reject);
        resolve();
      });
    });
    this.server.on('error', (error) => this.log.error({ err: error.message }, 'proxy tag relay error'));
    this.listening = true;
    const addr = this.server.address();
    if (!addr || typeof addr === 'string') throw new Error('Proxy tag relay failed to bind');
    return { url: `http://127.0.0.1:${addr.port}` };
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    this.agent.destroy();
    if (!this.listening) return;
    this.listening = false;
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private track(socket: Duplex): void {
    this.sockets.add(socket);
    socket.once('close', () => this.sockets.delete(socket));
  }

  private forwardHttp(req: IncomingMessage, res: ServerResponse): void {
    const headers: http.OutgoingHttpHeaders = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (!HOP_BY_HOP.has(key.toLowerCase()) && value !== undefined) headers[key] = value;
    }
    if (this.tag) headers['proxy-authorization'] = this.tag;
    const fail = (): void => {
      if (res.headersSent) res.destroy();
      else res.writeHead(502, { connection: 'close' }).end();
    };
    const up = http.request({
      host: this.upstreamHost,
      port: this.upstreamPort,
      method: req.method,
      path: req.url ?? '/',
      headers,
      setHost: false,
      agent: this.agent,
    });
    req.on('error', () => up.destroy());
    res.on('close', () => {
      if (!res.writableFinished) up.destroy(); // client went away mid-response
    });
    up.on('error', fail);
    up.on('upgrade', (_r: IncomingMessage, socket: Socket) => {
      socket.destroy();
      fail();
    });
    up.on('response', (upRes) => {
      upRes.on('error', () => res.destroy());
      try {
        const out: http.OutgoingHttpHeaders = {};
        for (const [key, value] of Object.entries(upRes.headers)) {
          if (!HOP_BY_HOP.has(key.toLowerCase()) && value !== undefined) out[key] = value;
        }
        res.writeHead(upRes.statusCode ?? 502, out);
      } catch {
        upRes.destroy();
        fail();
        return;
      }
      upRes.pipe(res);
    });
    req.pipe(up);
  }

  private forwardConnect(req: IncomingMessage, client: Duplex, head: Buffer): void {
    this.track(client);
    client.on('error', () => client.destroy());
    const target = parseAuthority(req.url ?? '');
    if (!target) {
      client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      return;
    }
    const authority = target.host.includes(':') ? `[${target.host}]:${target.port}` : `${target.host}:${target.port}`;
    const up = net.connect(this.upstreamPort, this.upstreamHost);
    this.track(up);
    client.once('close', () => up.destroy());
    up.on('error', () => {
      if (client.writable) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
      client.destroy();
    });
    up.once('connect', () => {
      // The egress proxy's own response (200 / 403 / 502) is relayed verbatim.
      up.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n${this.tag ? `Proxy-Authorization: ${this.tag}\r\n` : ''}\r\n`);
      if (head.length > 0) up.write(head);
      up.on('close', () => client.destroy());
      up.pipe(client);
      client.pipe(up);
    });
  }
}
