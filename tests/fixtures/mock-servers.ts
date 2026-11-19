import http from 'node:http';
import net, { type AddressInfo } from 'node:net';

/** Local mock HTTP receiver that records requests (for Slack/webhook/GitHub tests). */
export class MockHttp {
  readonly requests: Array<{ method: string; url: string; headers: http.IncomingHttpHeaders; body: string }> = [];
  responder: (req: { method: string; url: string; body: string }) => { status: number; body?: string; headers?: Record<string, string> } = () => ({ status: 200, body: 'ok' });
  private server: http.Server | undefined;
  port = 0;

  async start(): Promise<void> {
    this.server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c.toString()));
      req.on('end', () => {
        const entry = { method: req.method ?? '', url: req.url ?? '', headers: req.headers, body };
        this.requests.push(entry);
        const r = this.responder(entry);
        res.writeHead(r.status, { 'content-type': 'application/json', ...r.headers }).end(r.body ?? '');
      });
    });
    await new Promise<void>((resolve) => this.server?.listen(0, '127.0.0.1', resolve));
    this.port = (this.server.address() as AddressInfo).port;
  }

  url(path = '/'): string {
    return `http://127.0.0.1:${this.port}${path}`;
  }

  async stop(): Promise<void> {
    this.server?.closeAllConnections();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }
}

/** Minimal SMTP server (no TLS, no auth) that records delivered messages. */
export class MockSmtp {
  readonly messages: Array<{ from: string; to: string[]; data: string }> = [];
  private server: net.Server | undefined;
  port = 0;

  async start(): Promise<void> {
    this.server = net.createServer((socket) => {
      let buffer = '';
      let inData = false;
      let current = { from: '', to: [] as string[], data: '' };
      socket.write('220 mock.smtp ESMTP\r\n');
      socket.on('data', (chunk: Buffer) => {
        buffer += chunk.toString();
        for (;;) {
          if (inData) {
            const end = buffer.indexOf('\r\n.\r\n');
            if (end < 0) return;
            current.data = buffer.slice(0, end);
            buffer = buffer.slice(end + 5);
            inData = false;
            this.messages.push(current);
            current = { from: '', to: [], data: '' };
            socket.write('250 OK queued\r\n');
            continue;
          }
          const nl = buffer.indexOf('\r\n');
          if (nl < 0) return;
          const line = buffer.slice(0, nl);
          buffer = buffer.slice(nl + 2);
          const cmd = line.slice(0, 4).toUpperCase();
          if (cmd === 'EHLO' || cmd === 'HELO') socket.write('250-mock.smtp\r\n250 8BITMIME\r\n');
          else if (cmd === 'MAIL') {
            current.from = line;
            socket.write('250 OK\r\n');
          } else if (cmd === 'RCPT') {
            current.to.push(line);
            socket.write('250 OK\r\n');
          } else if (cmd === 'DATA') {
            inData = true;
            socket.write('354 go ahead\r\n');
          } else if (cmd === 'QUIT') {
            socket.end('221 bye\r\n');
            return;
          } else socket.write('250 OK\r\n');
        }
      });
    });
    await new Promise<void>((resolve) => this.server?.listen(0, '127.0.0.1', resolve));
    this.port = (this.server.address() as AddressInfo).port;
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }
}
