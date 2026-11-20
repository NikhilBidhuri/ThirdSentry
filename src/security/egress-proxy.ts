import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import net, { type Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import { getLogger } from '../utils/logger.js';
import type { DestinationDecision, NetworkPolicy } from './network-policy.js';

/**
 * A minimal HTTP/HTTPS forward proxy that enforces the ThirdSentry network
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
 * Everything that arrives from a client or an upstream server is hostile:
 * every per-connection callback runs behind an error guard so that no single
 * connection (malformed upstream status line, invalid header, socket error)
 * can take the proxy process down.
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

/**
 * Attribution tag sent by the scanner as the Basic `Proxy-Authorization`
 * user name (`<runId>.<site>`). It is NOT authentication: any password is
 * accepted and requests without a tag are served normally. The tag only
 * decides which run/site an event is filed under.
 */
export interface ProxyClientTag {
  readonly runId: string;
  readonly site: string;
}

/** Receives events of tagged connections (the standalone proxy writes them to disk). */
export interface ProxyEventSink {
  append(tag: ProxyClientTag, event: ProxyConnectionEvent): void;
  /** Called when the per-site cap drops an event; `total` is the site's dropped count so far. */
  dropped(tag: ProxyClientTag, total: number): void;
}

export interface EgressProxyOptions {
  readonly policy: NetworkPolicy;
  /** Maximum bytes transferred (both directions) per connection before it is cut. */
  readonly maxBytesPerConnection: number;
  readonly connectTimeoutMs: number;
  readonly idleTimeoutMs: number;
  readonly maxConnections: number;
  /**
   * Maximum number of connection events retained per site, separately for
   * blocked and for allowed events (so a flood of allowed requests can never
   * push blocked ones out). Further events are counted as dropped.
   */
  readonly maxRecordedEvents: number;
  /** When set, events of tagged connections go to this sink instead of memory. */
  readonly eventSink?: ProxyEventSink;
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

const RUN_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const SITE_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const MAX_BUCKETS = 4_096;

interface Bucket {
  readonly blocked: ProxyConnectionEvent[];
  readonly allowed: ProxyConnectionEvent[];
  blockedCount: number;
  allowedCount: number;
  dropped: number;
}

type Guard = (fn: () => void) => void;

export class EgressProxy {
  private readonly options: EgressProxyOptions;
  private readonly server: http.Server;
  private readonly sockets = new Set<Duplex>();
  /** Per-site accounting; '' is the bucket of untagged connections. */
  private readonly buckets = new Map<string, Bucket>();
  private readonly log = getLogger('egress-proxy');
  private address: { host: string; port: number } | undefined;

  constructor(options: EgressProxyOptions) {
    this.options = options;
    this.server = http.createServer((req, res) => {
      const fail = (error: unknown): void => {
        this.log.warn({ err: describe(error) }, 'proxied HTTP request failed');
        safeDestroy(res);
        safeDestroy(req);
      };
      try {
        this.handleHttp(req, res, guardWith(fail)).catch(fail);
      } catch (error) {
        fail(error);
      }
    });
    this.server.maxConnections = options.maxConnections;
    this.server.on('connect', (req: IncomingMessage, socket: Duplex, head: Buffer) => {
      const fail = (error: unknown): void => {
        this.log.warn({ err: describe(error) }, 'CONNECT tunnel failed');
        safeDestroy(socket);
      };
      try {
        this.handleConnect(req, socket, head, guardWith(fail)).catch(fail);
      } catch (error) {
        fail(error);
      }
    });
    this.server.on('upgrade', (_req: IncomingMessage, socket: Duplex) => {
      // Chromium/Firefox/WebKit tunnel WebSockets with CONNECT when a proxy is set.
      socket.on('error', () => socket.destroy());
      socket.end('HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n');
    });
    this.server.on('connection', (socket: Socket) => {
      socket.on('error', () => socket.destroy());
      this.track(socket);
    });
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
    // A listening-socket error after start (rare) must not become an uncaught exception.
    this.server.on('error', (error) => this.log.error({ err: describe(error) }, 'egress proxy server error'));
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

  /** All connection events currently held in memory (allowed and blocked) and the number dropped. */
  getEvents(): { events: readonly ProxyConnectionEvent[]; dropped: number } {
    const events: ProxyConnectionEvent[] = [];
    let dropped = 0;
    for (const bucket of this.buckets.values()) {
      events.push(...bucket.blocked, ...bucket.allowed);
      dropped += bucket.dropped;
    }
    return { events, dropped };
  }

  /**
   * Return and forget the events of one site: blocked events first, then
   * allowed ones, each capped at `maxRecordedEvents`, plus the exact number of
   * events that did not fit. Without a tag, the untagged bucket is drained
   * (the in-process proxy serves one site at a time).
   */
  drainEvents(tag?: ProxyClientTag): { events: ProxyConnectionEvent[]; dropped: number } {
    const key = tag ? tagKey(tag) : '';
    const bucket = this.buckets.get(key);
    this.buckets.delete(key);
    if (!bucket) return { events: [], dropped: 0 };
    return { events: [...bucket.blocked, ...bucket.allowed], dropped: bucket.dropped };
  }

  private track(socket: Duplex): void {
    this.sockets.add(socket);
    socket.once('close', () => this.sockets.delete(socket));
  }

  private bucketFor(key: string): Bucket {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      if (this.buckets.size >= MAX_BUCKETS) {
        const oldest = this.buckets.keys().next().value;
        if (oldest !== undefined) this.buckets.delete(oldest);
      }
      bucket = { blocked: [], allowed: [], blockedCount: 0, allowedCount: 0, dropped: 0 };
      this.buckets.set(key, bucket);
    }
    return bucket;
  }

  private record(event: ProxyConnectionEvent, tag: ProxyClientTag | undefined): void {
    // Blocked attempts are always logged, whatever happens to event retention.
    if (!event.allowed) {
      this.log.info({ host: event.host, port: event.port, reason: event.reason, ...(tag ? { run: tag.runId, site: tag.site } : {}) }, 'blocked outbound connection');
    }
    const sink = this.options.eventSink;
    if (sink && !tag) {
      this.log.warn({ host: event.host, port: event.port, allowed: event.allowed }, 'connection without a scan tag; event not attributed to any run');
      return;
    }
    const bucket = this.bucketFor(tag ? tagKey(tag) : '');
    const count = event.allowed ? bucket.allowedCount : bucket.blockedCount;
    if (count >= this.options.maxRecordedEvents) {
      bucket.dropped++;
      if (sink && tag) sink.dropped(tag, bucket.dropped);
      return;
    }
    if (event.allowed) bucket.allowedCount++;
    else bucket.blockedCount++;
    if (sink && tag) {
      sink.append(tag, event);
      return;
    }
    (event.allowed ? bucket.allowed : bucket.blocked).push(event);
  }

  private recordDecision(method: string, decision: DestinationDecision, tag: ProxyClientTag | undefined): void {
    this.record(
      {
        timestamp: new Date().toISOString(),
        host: decision.host,
        port: decision.port,
        method,
        allowed: decision.allowed,
        ...(decision.allowed ? { address: decision.address } : { reason: decision.reason, code: decision.code }),
      },
      tag,
    );
  }

  private clientTag(req: IncomingMessage): ProxyClientTag | undefined {
    const header = req.headers['proxy-authorization'];
    if (header === undefined) return undefined;
    const tag = parseClientTag(header);
    if (!tag) this.log.warn('ignoring malformed scan tag in Proxy-Authorization');
    return tag;
  }

  private async handleConnect(req: IncomingMessage, client: Duplex, head: Buffer, guard: Guard): Promise<void> {
    this.track(client);
    // Registered before DNS/connect so that a client that goes away while we
    // resolve or connect never leaves an upstream socket behind.
    const pending: { upstream?: Socket } = {};
    let clientGone = false;
    client.on('error', () => client.destroy());
    client.once('close', () => {
      clientGone = true;
      pending.upstream?.destroy();
    });
    const tag = this.clientTag(req);
    const target = parseAuthority(req.url ?? '');
    if (!target) {
      client.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      return;
    }
    const decision = await this.options.policy.resolveDestination(target.host, target.port);
    this.recordDecision('CONNECT', decision, tag);
    if (clientGone) return;
    if (!decision.allowed) {
      client.end(`HTTP/1.1 403 Forbidden\r\nX-ThirdSentry-Blocked: ${sanitizeHeader(decision.code)}\r\nConnection: close\r\n\r\n`);
      return;
    }
    const up = net.connect({ host: decision.address, port: decision.port, family: decision.family });
    pending.upstream = up;
    this.track(up);
    const connectTimer = setTimeout(() => {
      up.destroy(new Error('connect timeout'));
    }, this.options.connectTimeoutMs);
    up.once('close', () => clearTimeout(connectTimer));
    up.once('connect', () =>
      guard(() => {
        clearTimeout(connectTimer);
        if (clientGone) {
          up.destroy();
          return;
        }
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length > 0) up.write(head);
        this.pipeWithLimits(client, up);
      }),
    );
    up.once('error', () =>
      guard(() => {
        clearTimeout(connectTimer);
        if (client.writable) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
        client.destroy();
      }),
    );
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

  private async handleHttp(req: IncomingMessage, res: ServerResponse, guard: Guard): Promise<void> {
    // Registered before DNS/connect: a client that goes away cancels the upstream request.
    const pending: { upstream?: http.ClientRequest } = {};
    let clientGone = false;
    req.on('error', () => res.destroy());
    res.on('error', () => res.destroy());
    res.once('close', () => {
      clientGone = true;
      pending.upstream?.destroy();
    });
    const tag = this.clientTag(req);
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
    this.recordDecision(req.method ?? 'GET', decision, tag);
    if (clientGone) return;
    if (!decision.allowed) {
      res.writeHead(403, { 'x-thirdsentry-blocked': sanitizeHeader(decision.code), connection: 'close' }).end();
      return;
    }
    const headers: http.OutgoingHttpHeaders = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (!HOP_BY_HOP.has(key.toLowerCase()) && value !== undefined) headers[key] = value;
    }
    headers.host = url.host;
    let transferred = 0;
    const max = this.options.maxBytesPerConnection;
    const badGateway = (): void => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      for (const name of res.getHeaderNames()) res.removeHeader(name);
      res.writeHead(502, { connection: 'close' }).end();
    };
    const up = http.request({
      host: decision.address,
      family: decision.family,
      port,
      method: req.method,
      path: `${url.pathname}${url.search}`,
      headers,
      setHost: false,
      timeout: this.options.connectTimeoutMs,
    });
    pending.upstream = up;
    up.on('timeout', () => up.destroy(new Error('upstream timeout')));
    up.on('response', (upRes) =>
      guard(() => {
        upRes.on('error', () => res.destroy());
        const status = upRes.statusCode;
        if (status === undefined || !Number.isInteger(status) || status < 100 || status > 599) {
          this.log.warn({ host: decision.host, status }, 'upstream sent an invalid status code; returning 502');
          upRes.destroy();
          badGateway();
          return;
        }
        // The reason phrase is dropped (Node supplies the standard one): it is
        // free text from the upstream and may contain characters that
        // ServerResponse refuses. Headers that Node would refuse are skipped.
        try {
          for (const [key, value] of Object.entries(upRes.headers)) {
            if (value === undefined || HOP_BY_HOP.has(key.toLowerCase())) continue;
            if (!isValidHeader(key, value)) {
              this.log.debug({ host: decision.host, header: key.slice(0, 64) }, 'dropping invalid upstream response header');
              continue;
            }
            res.setHeader(key, value);
          }
          res.writeHead(status);
        } catch (error) {
          this.log.warn({ host: decision.host, err: describe(error) }, 'could not relay upstream response head; returning 502');
          upRes.destroy();
          badGateway();
          return;
        }
        upRes.on('data', (chunk: Buffer) => {
          transferred += chunk.length;
          if (transferred > max) {
            upRes.destroy();
            res.destroy();
          }
        });
        upRes.pipe(res);
      }),
    );
    // A 101 (or any upgrade) response would turn the connection into an opaque
    // tunnel that bypasses response handling, and without a listener the client
    // hangs. The proxy never upgrades plain HTTP requests.
    up.on('upgrade', (_upRes: IncomingMessage, socket: Socket) =>
      guard(() => {
        socket.destroy();
        this.log.warn({ host: decision.host }, 'upstream attempted a protocol upgrade; returning 502');
        badGateway();
      }),
    );
    up.on('error', () => guard(badGateway));
    req.on('data', (chunk: Buffer) => {
      transferred += chunk.length;
      if (transferred > max) {
        up.destroy();
        res.destroy();
      }
    });
    req.pipe(up);
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

/**
 * Parse the scan tag from a `Proxy-Authorization: Basic base64(<runId>.<site>:<anything>)`
 * header. Returns undefined for anything that is not a well-formed tag.
 */
export function parseClientTag(header: string): ProxyClientTag | undefined {
  if (header.length > 512) return undefined;
  const m = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(header.trim());
  if (!m?.[1]) return undefined;
  const decoded = Buffer.from(m[1], 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  const user = colon >= 0 ? decoded.slice(0, colon) : decoded;
  const dot = user.indexOf('.');
  if (dot <= 0) return undefined;
  const runId = user.slice(0, dot);
  const site = user.slice(dot + 1);
  if (!RUN_ID_RE.test(runId) || !SITE_RE.test(site)) return undefined;
  return { runId, site };
}

/** Build the `Proxy-Authorization` value carrying a scan tag. */
export function formatClientTag(tag: ProxyClientTag): string {
  if (!RUN_ID_RE.test(tag.runId) || !SITE_RE.test(tag.site)) throw new Error(`Invalid proxy tag "${tag.runId}.${tag.site}"`);
  return `Basic ${Buffer.from(`${tag.runId}.${tag.site}:x`).toString('base64')}`;
}

/** Run ids double as file names in the proxy event directory: letters, digits, "_" and "-" only. */
export function isValidRunId(value: string): boolean {
  return RUN_ID_RE.test(value);
}

function tagKey(tag: ProxyClientTag): string {
  return `${tag.runId}.${tag.site}`;
}

function sanitizeHeader(value: string): string {
  return value.replace(/[^a-z0-9-]/gi, '');
}

function isValidHeader(name: string, value: string | string[]): boolean {
  try {
    http.validateHeaderName(name);
    for (const v of Array.isArray(value) ? value : [value]) http.validateHeaderValue(name, v);
    return true;
  } catch {
    return false;
  }
}

/** Wrap per-connection callbacks so that a throw is handled instead of crashing the process. */
function guardWith(onError: (error: unknown) => void): Guard {
  return (fn) => {
    try {
      fn();
    } catch (error) {
      onError(error);
    }
  };
}

function safeDestroy(stream: { destroy(): unknown }): void {
  try {
    stream.destroy();
  } catch {
    // already gone
  }
}

function describe(error: unknown): string {
  if (error instanceof Error) return (error as NodeJS.ErrnoException).code ?? error.message;
  return String(error);
}
