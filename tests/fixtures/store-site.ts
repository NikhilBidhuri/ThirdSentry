import { EMPTY_WASM, type FixtureServer } from './server.js';

/**
 * A small fake online store that loads a realistic mix of first- and
 * third-party JavaScript:
 *
 *  /           parser-inserted vendor library, inline config, ES module with
 *              dynamic import(), runtime-injected analytics tag (which sends a
 *              beacon to a collection endpoint), a dedicated worker, a
 *              WebAssembly module, a blob: script, a third-party iframe with
 *              its own script, and a script from a host that must be blocked.
 *  /checkout   payment page with a vendor widget
 *  /redirect   script whose URL redirects to a versioned file
 *  /slow       never finishes loading within the test timeout
 *  /broken     malformed JavaScript
 *  /error      HTTP 500
 */

export const VENDOR_LIB_V1 = `/* Vendor A widget library v1 */
(function () {
  window.VendorA = { version: 1, init: function () { return 'ready'; } };
})();
`;

export const ANALYTICS_TAG_V1 = `(function () {
  var payload = JSON.stringify({ page: location.pathname });
  navigator.sendBeacon('http://collect.vendor-c.test:{port}/collect', payload);
})();
`;

export function installStoreSite(server: FixtureServer): void {
  const shop = 'shop.test';
  const p = (path: string, host = shop): string => `http://${host}:{port}${path}`;

  server.html(
    shop,
    '/',
    `<!doctype html><html><head><title>Shop</title>
<script src="${p('/lib.js', 'cdn.vendor-a.test')}"></script>
<script>window.shopConfig = { currency: 'EUR', region: 'eu' };</script>
<script type="module" src="/app.mjs"></script>
<script src="${p('/blocked.js', 'internal.test')}"></script>
</head><body>
<h1>Shop</h1>
<iframe src="${p('/frame.html', 'frame.vendor-d.test')}"></iframe>
<script>
  (function () {
    var s = document.createElement('script');
    s.src = '${p('/tag.js', 'analytics.vendor-b.test')}';
    document.head.appendChild(s);
    var w = new Worker('/worker.js');
    w.postMessage('hi');
    var blob = new Blob(['self.blobRan = true;'], { type: 'text/javascript' });
    var bs = document.createElement('script');
    bs.src = URL.createObjectURL(blob);
    document.body.appendChild(bs);
    if (window.WebAssembly && WebAssembly.instantiateStreaming) {
      WebAssembly.instantiateStreaming(fetch('/module.wasm')).catch(function () {});
    }
  })();
</script>
</body></html>`,
  );
  server.js(shop, '/app.mjs', `import('./lazy.mjs').then((m) => m.run());\nexport const app = 1;\n`);
  server.js(shop, '/lazy.mjs', `export function run() { return 'lazy'; }\n`);
  server.js(shop, '/worker.js', `self.onmessage = function (e) { self.postMessage(e.data); };\n`);
  server.set(shop, '/module.wasm', { headers: { 'content-type': 'application/wasm' }, body: EMPTY_WASM });
  server.js('cdn.vendor-a.test', '/lib.js', VENDOR_LIB_V1);
  server.js('analytics.vendor-b.test', '/tag.js', ANALYTICS_TAG_V1);
  server.set('collect.vendor-c.test', '/collect', { status: 204, headers: { 'access-control-allow-origin': '*' } });
  server.js('internal.test', '/blocked.js', 'window.internal = true;');
  server.html('frame.vendor-d.test', '/frame.html', `<!doctype html><html><body><script src="/frame.js"></script></body></html>`);
  server.js('frame.vendor-d.test', '/frame.js', `window.frameScript = true;\n`);

  server.html(
    shop,
    '/checkout',
    `<!doctype html><html><head><title>Checkout</title>
<script src="${p('/lib.js', 'cdn.vendor-a.test')}"></script>
<script src="${p('/pay.js', 'cdn.vendor-a.test')}"></script>
</head><body><form><input name="card" autocomplete="cc-number"></form></body></html>`,
  );
  server.js('cdn.vendor-a.test', '/pay.js', `window.Pay = { mount: function () {} };\n`);

  server.html(
    shop,
    '/redirect',
    `<!doctype html><html><head><script src="${p('/latest.js', 'cdn.vendor-a.test')}"></script></head><body>r</body></html>`,
  );
  server.set('cdn.vendor-a.test', '/latest.js', { redirect: 'http://cdn.vendor-a.test:{port}/v2/lib.js' });
  server.js('cdn.vendor-a.test', '/v2/lib.js', `window.latest = 2;\n`);

  server.html(shop, '/slow', `<!doctype html><html><head><script src="/slow.js"></script></head><body>slow</body></html>`);
  server.set(shop, '/slow.js', { headers: { 'content-type': 'application/javascript' }, body: 'window.slow=1;', delayMs: 60_000 });

  server.html(shop, '/broken', `<!doctype html><html><head><script src="/broken.js"></script></head><body>broken</body></html>`);
  server.js(shop, '/broken.js', `function ( { this is not javascript`);

  server.set(shop, '/error', { status: 500, headers: { 'content-type': 'text/html' }, body: '<h1>500</h1>' });
}
