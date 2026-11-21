/**
 * In-page instrumentation injected into every frame *before* any page script
 * runs (Playwright `addInitScript`).
 *
 * It observes script elements as they are inserted (including ones that are
 * later removed), marks scripts inserted through DOM APIs (dynamic injection),
 * records worker / service-worker creation and captures JavaScript blobs.
 *
 * SECURITY NOTE: this code runs in the same JavaScript realm as untrusted page
 * scripts. A hostile page can detect, disable or feed false data to it. Data
 * it reports is therefore treated as untrusted, size-limited evidence and is
 * cross-checked against network observations made outside the page. It is
 * best-effort coverage, not a security boundary.
 *
 * Kept as a plain string so test/build tooling cannot inject helpers into it.
 */

export const REPORT_BINDING = '__thirdsentryReport';

export interface InitScriptOptions {
  readonly maxInlineChars: number;
  readonly maxBlobBytes: number;
  readonly maxReports: number;
}

export function buildInitScript(options: InitScriptOptions): string {
  return `(() => {
  'use strict';
  const OPTS = ${JSON.stringify(options)};
  const BINDING = ${JSON.stringify(REPORT_BINDING)};
  if (window.__thirdsentryInstalled) return;
  try { Object.defineProperty(window, '__thirdsentryInstalled', { value: true, enumerable: false }); } catch (e) {}

  const W = window;
  const getBinding = () => { try { const fn = W[BINDING]; return typeof fn === 'function' ? fn : null; } catch (e) { return null; } };
  let bindingRef = getBinding();
  let sent = 0;
  let queue = [];
  let flushScheduled = false;
  const nativeSetTimeout = W.setTimeout.bind(W);
  const flush = () => {
    flushScheduled = false;
    if (!bindingRef) bindingRef = getBinding();
    if (!bindingRef) { if (queue.length) { flushScheduled = true; nativeSetTimeout(flush, 50); } return; }
    const batch = queue; queue = [];
    try { bindingRef(batch); } catch (e) {}
  };
  // Drop counters are reported to the collector (outside the page) so that
  // lost evidence marks the page partial instead of disappearing silently.
  const stats = { reportsDropped: 0, untrackedBlobs: 0 };
  let statsScheduled = false;
  const scheduleStats = () => {
    if (statsScheduled) return;
    statsScheduled = true;
    nativeSetTimeout(() => {
      statsScheduled = false;
      queue.push({ t: 'stats', reportsDropped: stats.reportsDropped, untrackedBlobs: stats.untrackedBlobs });
      if (!flushScheduled) { flushScheduled = true; nativeSetTimeout(flush, 0); }
    }, 200);
  };
  const send = (msg) => {
    if (sent >= OPTS.maxReports) { stats.reportsDropped++; scheduleStats(); return; }
    sent++;
    msg.frameUrl = String(location.href);
    msg.timestamp = new Date().toISOString();
    queue.push(msg);
    if (!flushScheduled) { flushScheduled = true; nativeSetTimeout(flush, 0); }
  };

  const insertedByScript = new WeakSet();
  const viaWrite = new WeakSet();
  const reported = new WeakSet();
  let writeDepth = 0;

  const domPath = (el) => {
    const parts = [];
    let node = el;
    let depth = 0;
    while (node && node.nodeType === 1 && depth < 25) {
      const tag = node.tagName.toLowerCase();
      let idx = 1;
      let sib = node.previousElementSibling;
      while (sib) { if (sib.tagName === node.tagName) idx++; sib = sib.previousElementSibling; }
      parts.unshift(tag + ':nth-of-type(' + idx + ')');
      node = node.parentElement;
      depth++;
    }
    if (!parts.length) return 'detached>script';
    return parts.join('>');
  };

  // Registry of blob URL -> Blob for blobs that are not obviously JavaScript
  // (e.g. image previews), so their content can still be captured if they are
  // later used as a script or worker source. JavaScript-typed blobs are
  // captured immediately and do not need the registry. When the registry is
  // full, revoked entries are evicted first; otherwise the blob is counted as
  // untracked (reported to the collector).
  const MAX_TRACKED_BLOBS = 2000;
  const blobs = new Map();
  const revokedBlobs = new Set();
  const capturedBlobs = new Set();
  const nativeCreateObjectURL = URL.createObjectURL;
  const nativeRevokeObjectURL = URL.revokeObjectURL;
  const trackBlob = (url, blob) => {
    if (blobs.size >= MAX_TRACKED_BLOBS) {
      for (const old of revokedBlobs) { revokedBlobs.delete(old); blobs.delete(old); if (blobs.size < MAX_TRACKED_BLOBS) break; }
    }
    if (blobs.size >= MAX_TRACKED_BLOBS) { stats.untrackedBlobs++; scheduleStats(); return; }
    blobs.set(url, blob);
  };
  const toBase64 = (buf) => {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  };
  const captureBlob = (url, known) => {
    if (capturedBlobs.has(url)) return;
    const blob = known || blobs.get(url);
    capturedBlobs.add(url);
    if (!blob) {
      // Used as a script/worker source but not held: JS evidence may be lost.
      send({ t: 'blob', blobUrl: url, missed: true });
      return;
    }
    blobs.delete(url);
    const truncated = blob.size > OPTS.maxBlobBytes;
    blob.slice(0, OPTS.maxBlobBytes).arrayBuffer().then((buf) => {
      send({ t: 'blob', blobUrl: url, mimeType: String(blob.type || ''), size: blob.size, truncated, textBase64: toBase64(buf) });
    }, () => {
      send({ t: 'blob', blobUrl: url, mimeType: String(blob.type || ''), size: blob.size, truncated: true });
    });
  };
  const looksLikeScriptType = (type) => /javascript|ecmascript|wasm/i.test(type || '');
  try {
    URL.createObjectURL = function (obj) {
      const url = nativeCreateObjectURL.apply(this, arguments);
      try {
        if (obj instanceof Blob) {
          if (looksLikeScriptType(obj.type)) captureBlob(url, obj);
          else trackBlob(url, obj);
        }
      } catch (e) {}
      return url;
    };
    URL.revokeObjectURL = function (url) {
      try { if (blobs.has(String(url))) revokedBlobs.add(String(url)); } catch (e) {}
      return nativeRevokeObjectURL.apply(this, arguments);
    };
  } catch (e) {}

  const reportScript = (el, via) => {
    if (reported.has(el)) return;
    reported.add(el);
    const src = el.getAttribute('src');
    const msg = {
      t: 'script',
      kind: src !== null ? 'external' : 'inline',
      type: el.getAttribute('type') || undefined,
      domPath: domPath(el),
      async: el.async === true,
      defer: el.defer === true,
      integrity: el.getAttribute('integrity') || undefined,
      crossOrigin: el.getAttribute('crossorigin') || undefined,
      hasNonce: !!(el.nonce || el.getAttribute('nonce')),
      insertedByScript: insertedByScript.has(el) || viaWrite.has(el),
      viaDocumentWrite: viaWrite.has(el),
      observedVia: via,
    };
    if (src !== null) {
      try { msg.src = String(el.src); } catch (e) { msg.src = String(src); }
      if (msg.src.startsWith('blob:')) captureBlob(msg.src);
    } else {
      const text = String(el.textContent || '');
      msg.textBytes = text.length;
      msg.textTruncated = text.length > OPTS.maxInlineChars;
      msg.text = msg.textTruncated ? text.slice(0, OPTS.maxInlineChars) : text;
    }
    send(msg);
  };

  const markTree = (node) => {
    try {
      if (!node || node.nodeType !== 1 && node.nodeType !== 11) return;
      if (node.nodeType === 1 && node.tagName === 'SCRIPT') insertedByScript.add(node);
      if (node.querySelectorAll) node.querySelectorAll('script').forEach((s) => insertedByScript.add(s));
    } catch (e) {}
  };
  const wrap = (proto, name, argIndexes) => {
    try {
      const original = proto[name];
      if (typeof original !== 'function') return;
      const wrapped = function () {
        for (const i of argIndexes) { const a = arguments[i]; if (a && typeof a === 'object') markTree(a); }
        if (argIndexes.length === 0) { for (const a of arguments) if (a && typeof a === 'object') markTree(a); }
        return original.apply(this, arguments);
      };
      Object.defineProperty(proto, name, { value: wrapped, writable: true, configurable: true });
    } catch (e) {}
  };
  wrap(Node.prototype, 'appendChild', [0]);
  wrap(Node.prototype, 'insertBefore', [0]);
  wrap(Node.prototype, 'replaceChild', [0]);
  wrap(Element.prototype, 'append', []);
  wrap(Element.prototype, 'prepend', []);
  wrap(Element.prototype, 'before', []);
  wrap(Element.prototype, 'after', []);
  wrap(Element.prototype, 'replaceWith', []);
  wrap(Element.prototype, 'insertAdjacentElement', [1]);
  try { wrap(DocumentFragment.prototype, 'append', []); wrap(DocumentFragment.prototype, 'prepend', []); } catch (e) {}

  const wrapWrite = (name) => {
    try {
      const original = Document.prototype[name];
      Object.defineProperty(Document.prototype, name, {
        value: function () { writeDepth++; try { return original.apply(this, arguments); } finally { writeDepth--; } },
        writable: true, configurable: true,
      });
    } catch (e) {}
  };
  wrapWrite('write');
  wrapWrite('writeln');

  const handleAdded = (node) => {
    if (node.nodeType !== 1) return;
    if (node.tagName === 'SCRIPT') {
      if (writeDepth > 0) viaWrite.add(node);
      reportScript(node, 'mutation');
      return;
    }
    if (node.getElementsByTagName) {
      const inner = node.getElementsByTagName('script');
      for (let i = 0; i < inner.length; i++) {
        if (writeDepth > 0) viaWrite.add(inner[i]);
        reportScript(inner[i], 'mutation');
      }
    }
  };
  try {
    const observer = new MutationObserver((records) => {
      for (const r of records) for (const n of r.addedNodes) handleAdded(n);
    });
    observer.observe(document, { childList: true, subtree: true });
  } catch (e) {}

  const hookWorker = (name, kind) => {
    try {
      const Original = W[name];
      if (typeof Original !== 'function') return;
      const Hooked = function (url, opts) {
        try {
          const resolved = String(new URL(String(url), location.href));
          if (resolved.startsWith('blob:')) captureBlob(resolved);
          send({ t: 'worker', kind, url: resolved, source: 'constructor-hook' });
        } catch (e) {}
        return new Original(url, opts);
      };
      Hooked.prototype = Original.prototype;
      Object.defineProperty(W, name, { value: Hooked, writable: true, configurable: true });
    } catch (e) {}
  };
  hookWorker('Worker', 'dedicated-worker');
  hookWorker('SharedWorker', 'shared-worker');

  try {
    const swc = navigator.serviceWorker;
    const proto = swc && Object.getPrototypeOf(swc);
    if (proto && typeof proto.register === 'function') {
      const originalRegister = proto.register;
      Object.defineProperty(proto, 'register', {
        value: function (scriptURL, options) {
          try {
            const resolved = String(new URL(String(scriptURL), location.href));
            const scope = options && options.scope ? String(new URL(String(options.scope), location.href)) : undefined;
            send({ t: 'worker', kind: 'service-worker', url: resolved, scope, source: 'registration-hook' });
          } catch (e) {}
          return originalRegister.apply(this, arguments);
        },
        writable: true, configurable: true,
      });
    }
  } catch (e) {}
})();`;
}

/**
 * Function evaluated in each frame at the end of a page scan to snapshot the
 * script elements present in the DOM. It is not injected into the page, but
 * `frame.evaluate` runs in the page's MAIN world, so a hostile page can still
 * tamper with the DOM APIs it uses (querySelectorAll, getAttribute, ...) or with
 * the elements themselves. Its output is page-reported data like the init
 * script's: it may add context but must never remove a network-derived signal
 * (see docs/limitations.md, "In-page instrumentation").
 */
export const SNAPSHOT_SCRIPT = `(maxInlineChars) => {
  const out = [];
  const domPath = (el) => {
    const parts = [];
    let node = el; let depth = 0;
    while (node && node.nodeType === 1 && depth < 25) {
      let idx = 1; let sib = node.previousElementSibling;
      while (sib) { if (sib.tagName === node.tagName) idx++; sib = sib.previousElementSibling; }
      parts.unshift(node.tagName.toLowerCase() + ':nth-of-type(' + idx + ')');
      node = node.parentElement; depth++;
    }
    return parts.join('>') || 'detached>script';
  };
  const scripts = document.getElementsByTagName('script');
  for (let i = 0; i < scripts.length && i < 2000; i++) {
    const el = scripts[i];
    const src = el.getAttribute('src');
    const item = {
      kind: src !== null ? 'external' : 'inline',
      type: el.getAttribute('type') || undefined,
      domPath: domPath(el),
      async: el.async === true,
      defer: el.defer === true,
      integrity: el.getAttribute('integrity') || undefined,
      crossOrigin: el.getAttribute('crossorigin') || undefined,
      hasNonce: !!(el.nonce || el.getAttribute('nonce')),
    };
    if (src !== null) { item.src = String(el.src || src); }
    else {
      const text = String(el.textContent || '');
      item.textBytes = text.length;
      item.textTruncated = text.length > maxInlineChars;
      item.text = item.textTruncated ? text.slice(0, maxInlineChars) : text;
    }
    out.push(item);
  }
  return { items: out, total: scripts.length };
}`;
