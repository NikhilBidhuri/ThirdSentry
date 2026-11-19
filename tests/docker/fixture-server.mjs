// Tiny fixture website for the Docker verification run.
import http from 'node:http';

const pages = {
  '/': `<!doctype html><html><head><script src="/vendor.js"></script><script>window.cfg = {a: 1};</script></head><body>
<script>var s = document.createElement('script'); s.src = '/late.js'; document.head.appendChild(s);</script></body></html>`,
  '/vendor.js': `window.Vendor = { v: process_version };`.replace('process_version', JSON.stringify(process.env.VENDOR_VERSION ?? '1')),
  '/late.js': 'window.late = true;',
};

http
  .createServer((req, res) => {
    const body = pages[req.url ?? '/'];
    if (!body) return res.writeHead(404).end();
    res.writeHead(200, { 'content-type': req.url === '/' ? 'text/html' : 'application/javascript', 'cache-control': 'no-store' }).end(body);
  })
  .listen(8080, '0.0.0.0', () => console.log('fixture listening on 8080'));
