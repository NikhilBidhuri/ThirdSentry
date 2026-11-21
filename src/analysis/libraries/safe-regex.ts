/**
 * Defences for regular expressions that come from the downloaded (untrusted)
 * vulnerability database. JavaScript regexes cannot be interrupted, so
 * catastrophic backtracking is prevented up front instead of time-boxed
 * (a time box would also make results non-deterministic):
 *
 *  1. Pattern length is capped (MAX_PATTERN_LENGTH).
 *  2. A small structural scan rejects the classic ReDoS shapes: a group that
 *     contains an unbounded quantifier and is itself repeated more than once
 *     ("(a+)+", "(a*){2,}", "(.*a)*"), an alternation inside an unbounded
 *     repeated group ("(a|aa)+"), a backreference inside one, and patterns
 *     with more than MAX_UNBOUNDED unbounded quantifiers overall. Repeat
 *     bounds above MAX_REPEAT_BOUND are rejected.
 *  3. The pattern must compile, with no flags.
 *  4. Input handed to a regex is capped (MAX_INPUT_CHARS), so even a
 *     quadratic pattern has a hard bound on work.
 *  5. The database as a whole is capped in the number of regexes (see vulndb).
 *
 * The check is deliberately conservative: a few legitimate patterns may be
 * rejected (they are then skipped and counted in the load report).
 */

export const MAX_PATTERN_LENGTH = 600;
export const MAX_UNBOUNDED = 6;
export const MAX_REPEAT_BOUND = 10_000;
export const MAX_INPUT_CHARS = 2 * 1024 * 1024;

export type PatternCheck = { readonly ok: true } | { readonly ok: false; readonly reason: string };

interface Frame {
  hasUnbounded: boolean;
  hasAlternation: boolean;
  hasBackref: boolean;
  lookaround: boolean;
}

const newFrame = (lookaround = false): Frame => ({ hasUnbounded: false, hasAlternation: false, hasBackref: false, lookaround });

interface Quantifier {
  readonly unbounded: boolean;
  readonly max: number;
  readonly end: number;
}

/** Parse a quantifier starting at `i`; undefined if there is none (a literal "{" is not one). */
function readQuantifier(p: string, i: number): Quantifier | undefined {
  const c = p[i];
  let q: Quantifier | undefined;
  if (c === '*' || c === '+') q = { unbounded: true, max: Infinity, end: i + 1 };
  else if (c === '?') q = { unbounded: false, max: 1, end: i + 1 };
  else if (c === '{') {
    const m = /^\{(\d+)(?:(,)(\d*))?\}/.exec(p.slice(i, i + 24));
    if (m) {
      const min = Number(m[1]);
      const max = m[2] === undefined ? min : m[3] === '' ? Infinity : Number(m[3]);
      q = { unbounded: max === Infinity, max, end: i + m[0].length };
    }
  }
  if (!q) return undefined;
  if (p[q.end] === '?') q = { ...q, end: q.end + 1 }; // lazy modifier
  return q;
}

export function checkPattern(pattern: string): PatternCheck {
  if (pattern.length === 0) return { ok: false, reason: 'empty pattern' };
  if (pattern.length > MAX_PATTERN_LENGTH) return { ok: false, reason: `pattern longer than ${MAX_PATTERN_LENGTH} characters` };
  const stack: Frame[] = [];
  let top = newFrame();
  let unboundedCount = 0;
  let i = 0;
  // The group closed immediately before the current position (the atom a quantifier would repeat).
  let lastGroup: Frame | undefined;
  while (i < pattern.length) {
    const c = pattern[i] as string;
    if (c === '\\') {
      const next = pattern[i + 1] ?? '';
      if (/[1-9]/.test(next) || (next === 'k' && pattern[i + 2] === '<')) top.hasBackref = true;
      i += 2;
      lastGroup = undefined;
    } else if (c === '[') {
      i++;
      if (pattern[i] === '^') i++;
      if (pattern[i] === ']') i++;
      while (i < pattern.length && pattern[i] !== ']') i += pattern[i] === '\\' ? 2 : 1;
      if (i >= pattern.length) return { ok: false, reason: 'unterminated character class' };
      i++;
      lastGroup = undefined;
    } else if (c === '(') {
      stack.push(top);
      const prefix = /^\(\?(?:<[A-Za-z_][A-Za-z0-9_]*>|<=|<!|=|!|:)/.exec(pattern.slice(i, i + 40));
      top = newFrame(prefix !== null && /^\(\?(?:<=|<!|=|!)/.test(prefix[0]));
      i += prefix ? prefix[0].length : 1;
      lastGroup = undefined;
    } else if (c === ')') {
      const inner = top;
      const parent = stack.pop();
      if (!parent) return { ok: false, reason: 'unbalanced parenthesis' };
      top = parent;
      if (inner.hasUnbounded) top.hasUnbounded = true;
      if (inner.hasBackref) top.hasBackref = true;
      lastGroup = inner;
      i++;
    } else if (c === '|') {
      top.hasAlternation = true;
      i++;
      lastGroup = undefined;
    } else if (c === '*' || c === '+' || c === '?' || c === '{') {
      const q = readQuantifier(pattern, i);
      if (!q) {
        i++; // literal "{"
        lastGroup = undefined;
        continue;
      }
      if (q.max !== Infinity && q.max > MAX_REPEAT_BOUND) return { ok: false, reason: `repeat bound above ${MAX_REPEAT_BOUND}` };
      if (q.unbounded) {
        unboundedCount++;
        top.hasUnbounded = true;
      }
      const g = lastGroup;
      if (g && q.max > 1) {
        if (g.hasUnbounded) return { ok: false, reason: 'nested quantifiers (a repeated group containing an unbounded quantifier)' };
        if (q.unbounded && g.hasAlternation && !g.lookaround) return { ok: false, reason: 'alternation inside an unbounded repeated group' };
        if (q.unbounded && g.hasBackref) return { ok: false, reason: 'backreference inside an unbounded repeated group' };
      }
      i = q.end;
      lastGroup = undefined;
    } else {
      i++;
      lastGroup = undefined;
    }
  }
  if (stack.length > 0) return { ok: false, reason: 'unbalanced parenthesis' };
  if (unboundedCount > MAX_UNBOUNDED) return { ok: false, reason: `more than ${MAX_UNBOUNDED} unbounded quantifiers` };
  return { ok: true };
}

/** Compile a pattern after checkPattern; returns a reason string instead of throwing. */
export function compileSafe(pattern: string): { readonly regex: RegExp } | { readonly error: string } {
  const check = checkPattern(pattern);
  if (!check.ok) return { error: check.reason };
  try {
    return { regex: new RegExp(pattern) };
  } catch (error) {
    return { error: `does not compile: ${error instanceof Error ? error.message.slice(0, 120) : 'invalid'}` };
  }
}

/** Run a regex against (a capped prefix of) the input. Never throws. */
export function execCapped(regex: RegExp, input: string): RegExpExecArray | null {
  try {
    return regex.exec(input.length > MAX_INPUT_CHARS ? input.slice(0, MAX_INPUT_CHARS) : input);
  } catch {
    return null;
  }
}
