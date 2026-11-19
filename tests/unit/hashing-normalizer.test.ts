import { describe, expect, it } from 'vitest';
import { sha256Hex, sriHash, verifySri } from '../../src/analysis/hashing.js';
import { normalizeJavaScript, normalizeLineEndings } from '../../src/analysis/normalizer.js';

describe('hashing', () => {
  it('computes SHA-256 of raw bytes', () => {
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(sha256Hex(Buffer.from([0xff, 0x00]))).toHaveLength(64);
  });

  it('distinguishes byte-level differences', () => {
    expect(sha256Hex('a\r\nb')).not.toBe(sha256Hex('a\nb'));
  });

  it('produces SRI values and verifies them', () => {
    const data = Buffer.from('alert(1)');
    const sri = sriHash(data);
    expect(sri).toMatch(/^sha256-[A-Za-z0-9+/]+=*$/);
    expect(verifySri(sri, data)).toBe(true);
    expect(verifySri(sri, Buffer.from('alert(2)'))).toBe(false);
  });

  it('uses only the strongest SRI algorithm present', () => {
    const data = Buffer.from('x');
    const strong = sriHash(data, 'sha384');
    const weakWrong = sriHash(Buffer.from('y'), 'sha256');
    expect(verifySri(`${weakWrong} ${strong}`, data)).toBe(true);
    // A matching sha256 does not help if the (stronger) sha384 does not match.
    expect(verifySri(`${sriHash(data)} ${sriHash(Buffer.from('y'), 'sha384')}`, data)).toBe(false);
    expect(verifySri('md5-abc', data)).toBeNull();
  });
});

describe('normalizer', () => {
  it('treats formatting-only changes as equal', () => {
    const a = normalizeJavaScript('function f(a,b){return a+b}\n// comment\n');
    const b = normalizeJavaScript('/* header */\r\nfunction f(a, b) {\r\n    return a + b;\r\n}\r\n');
    expect(a.status).toBe('normalized');
    expect(a.normalizedSha256).toBe(b.normalizedSha256);
  });

  it('detects semantic changes', () => {
    const a = normalizeJavaScript('send("https://a.example/collect")');
    const b = normalizeJavaScript('send("https://b.example/collect")');
    expect(a.normalizedSha256).not.toBe(b.normalizedSha256);
  });

  it('does not hide changes in string literal contents', () => {
    const a = normalizeJavaScript('var s = "a  b";');
    const b = normalizeJavaScript('var s = "a b";');
    expect(a.normalizedSha256).not.toBe(b.normalizedSha256);
  });

  it('keeps identifier names (no renaming)', () => {
    expect(normalizeJavaScript('var a=1').normalizedSha256).not.toBe(normalizeJavaScript('var b=1').normalizedSha256);
  });

  it('handles ES modules and classic scripts', () => {
    expect(normalizeJavaScript('import x from "./x.js"; export default x;').status).toBe('normalized');
    expect(normalizeJavaScript('with (obj) { a = 1 }').status).toBe('normalized');
  });

  it('falls back on parse errors without throwing', () => {
    const r = normalizeJavaScript('function ( {');
    expect(r.status).toBe('parse-error');
    expect(r.normalizedSha256).toBeUndefined();
    expect(r.error).toBeTruthy();
  });

  it('refuses oversize input', () => {
    expect(normalizeJavaScript('x'.repeat(100), { maxChars: 10 }).status).toBe('too-large');
  });

  it('normalises BOM and line endings', () => {
    expect(normalizeLineEndings('﻿a\r\nb\rc')).toBe('a\nb\nc');
  });
});
