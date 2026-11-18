import { describe, expect, it } from 'vitest';
import { analyzeJavaScript } from '../../src/analysis/ast-analyzer.js';
import { RULES } from '../../src/analysis/indicator-rules.js';
import { BENIGN_ANALYTICS, MINIFIED_LIBRARY, SKIMMER, obfuscatedLoader } from '../fixtures/scripts.js';

const ids = (src: string): string[] => Object.keys(analyzeJavaScript(src).counts).sort();
const has = (src: string, id: string): boolean => (analyzeJavaScript(src).counts[id] ?? 0) > 0;

describe('rule catalogue', () => {
  it('documents every rule completely', () => {
    for (const r of RULES) {
      expect(r.id).toMatch(/^SD-[A-Z0-9-]+$/);
      for (const field of [r.name, r.description, r.explanation, r.investigation, r.falsePositives]) expect(field.length).toBeGreaterThan(10);
      expect(['info', 'low', 'medium', 'high', 'critical']).toContain(r.severity);
      expect(['low', 'medium', 'high']).toContain(r.confidence);
    }
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
  });
});

describe('individual rules', () => {
  it.each([
    ['SD-EVAL', 'eval(code)', 'var x = { eval: 1 }; x.eval;'],
    ['SD-EVAL', 'window.eval("1")', 'function f(eval2){ return eval2("x") }'],
    ['SD-NEW-FUNCTION', 'var f = new Function("a", "return a")', 'function Fn(){}; new Fn()'],
    ['SD-NEW-FUNCTION', '[].constructor.constructor("return this")()', 'obj.constructor()'],
    ['SD-STRING-TIMER', 'setTimeout("doIt()", 10)', 'setTimeout(function(){ doIt() }, 10)'],
    ['SD-SCRIPT-INJECTION', 'var s = document.createElement("script"); document.head.appendChild(s)', 'document.createElement("div")'],
    ['SD-SCRIPT-INJECTION', 'document.write("<scr" + "ipt src=x></script>")', 'document.write("<p>hello</p>")'],
    ['SD-REMOTE-SCRIPT-LOAD', 'var s = document.createElement("script"); s.src = "https://cdn.evil.example/x.js"', 'var s = document.createElement("script"); s.src = "/local.js"'],
    ['SD-REMOTE-SCRIPT-LOAD', '(function(d){ var s = d.createElement("script"); s.src = "//cdn.evil.example/x.js" })(document)', 'var i = new Image(); i.src = "https://px.example/p"'],
    ['SD-COOKIE-ACCESS', '(function(w, d){ return d.cookie })(window, document)', '(function(w, d){ return d.cookie })(window, other)'],
    ['SD-BEACON', 'var n = navigator; n.sendBeacon(u, d)', 'var n = other; n.sendBeacon(u, d)'],
    ['SD-REMOTE-SCRIPT-LOAD', 'importScripts("https://cdn.example/w.js")', 'importScripts("./w.js")'],
    ['SD-REMOTE-SCRIPT-LOAD', 'import("https://esm.example/mod.js")', 'import("./mod.js")'],
    ['SD-COOKIE-ACCESS', 'var c = document.cookie', 'var c = doc.cookieJar'],
    ['SD-WEB-STORAGE', 'localStorage.getItem("k")', 'var localStorageKey = 1'],
    ['SD-WEB-STORAGE', 'window.sessionStorage.setItem("k", 1)', 'storage.getItem("k")'],
    ['SD-SENSITIVE-FIELD-ACCESS', 'document.querySelector("input[name=cardnumber]")', 'document.querySelector("#main-nav")'],
    ['SD-SENSITIVE-FIELD-ACCESS', 'document.getElementById("password")', 'document.getElementById("passage")'],
    ['SD-FORM-FIELD-ACCESS', 'document.querySelectorAll("input")', 'document.querySelectorAll(".card-grid")'],
    ['SD-FORM-FIELD-ACCESS', 'form.addEventListener("submit", f)', 'btn.addEventListener("click", f)'],
    ['SD-KEYSTROKE-CAPTURE', 'document.addEventListener("keydown", f)', 'document.addEventListener("scroll", f)'],
    ['SD-KEYSTROKE-CAPTURE', 'el.onkeyup = f', 'el.onclick = f'],
    ['SD-CLIPBOARD', 'navigator.clipboard.readText()', 'navigator.userAgent'],
    ['SD-CLIPBOARD', 'document.addEventListener("paste", f)', 'document.addEventListener("load", f)'],
    ['SD-BEACON', 'navigator.sendBeacon(u, d)', 'sendBeaconLater(u)'],
    ['SD-WEBSOCKET', 'new WebSocket("wss://live.example/s")', 'new MySocket("x")'],
    ['SD-REMOTE-ENDPOINT', 'fetch("https://api.example/x")', 'fetch("/api/x")'],
    ['SD-REMOTE-ENDPOINT', 'new Image().src = "https://px.example/p?d=" + d', 'img.src = "/logo.png"'],
    ['SD-REMOTE-ENDPOINT', 'xhr.open("POST", "https://c.example/collect")', 'dialog.open("modal")'],
    ['SD-NETWORK-API-HOOK', 'XMLHttpRequest.prototype.send = function(){}', 'MyThing.prototype.send = function(){}'],
    ['SD-NETWORK-API-HOOK', 'window.fetch = wrapped', 'var fetchLater = wrapped'],
  ])('%s matches "%s" but not "%s"', (rule, positive, negative) => {
    expect(has(positive, rule)).toBe(true);
    expect(has(negative, rule)).toBe(false);
  });

  it('does not treat a locally defined eval as global eval', () => {
    expect(has('function f(){ var eval = function(x){return x}; eval("1") }', 'SD-EVAL')).toBe(false);
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
    const m = r.matches.find((x) => x.ruleId === 'SD-EVAL');
    expect(m?.line).toBe(2);
    expect(m?.snippet.length).toBeLessThan(200);
    expect(m?.snippet).toContain('eval(payload)');
  });
});

describe('aggregate rules and false positives', () => {
  it('flags the skimmer pattern as a sensitive-data + transmission combination', () => {
    const found = ids(SKIMMER);
    expect(found).toEqual(expect.arrayContaining(['SD-SENSITIVE-FIELD-ACCESS', 'SD-KEYSTROKE-CAPTURE', 'SD-REMOTE-ENDPOINT', 'SD-EXFIL-COMBINATION']));
  });

  it('does not flag typical analytics code as a skimming combination or obfuscation', () => {
    const found = ids(BENIGN_ANALYTICS);
    expect(found).toEqual(expect.arrayContaining(['SD-COOKIE-ACCESS', 'SD-WEB-STORAGE', 'SD-BEACON']));
    expect(found).not.toContain('SD-EXFIL-COMBINATION');
    expect(found).not.toContain('SD-OBFUSCATION');
    expect(found).not.toContain('SD-SENSITIVE-FIELD-ACCESS');
  });

  it('does not treat ordinary minified code as obfuscated', () => {
    expect(ids(MINIFIED_LIBRARY)).not.toContain('SD-OBFUSCATION');
  });

  it('detects obfuscation from several independent signals', () => {
    const r = analyzeJavaScript(obfuscatedLoader());
    expect(r.counts['SD-OBFUSCATION']).toBe(1);
    expect(r.counts['SD-EVAL']).toBe(1);
    expect(r.matches.find((m) => m.ruleId === 'SD-OBFUSCATION')?.detail).toMatch(/hex-named identifiers/);
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
    const only = RULES.filter((r) => r.id === 'SD-EVAL');
    expect(Object.keys(analyzeJavaScript('eval(x); document.cookie', { rules: only }).counts)).toEqual(['SD-EVAL']);
  });
});
