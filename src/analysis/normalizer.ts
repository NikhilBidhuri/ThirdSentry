import { generate } from '@babel/generator';
import { sha256Hex } from './hashing.js';
import { parseForGoal, type ScriptGoal } from './parser.js';
import type { NormalizationStatus } from '../types/index.js';

/**
 * Conservative JavaScript normalisation.
 *
 * Goal: recognise when two versions of a script differ only in formatting
 * (whitespace, line endings, comments, indentation), so that a byte-level
 * change can be explained as "formatting only" instead of "code changed".
 *
 * What it does:
 *  - strips a UTF-8 BOM and converts CRLF/CR to LF,
 *  - parses the code with Babel using the goal the browser uses (classic
 *    script or module, see parser.ts) and re-prints it with a fixed code
 *    style, which removes insignificant whitespace and comments.
 *
 * What it deliberately does NOT do: rename identifiers, reorder code, change
 * literal values or string quoting (Babel keeps the raw literal text), or
 * remove dead code. Any change to executable code therefore changes the
 * normalised hash.
 *
 * The raw content and its raw SHA-256 are always kept; normalisation only
 * adds a second hash. If parsing fails, no normalised hash is produced and
 * comparison falls back to the raw hash.
 */

/**
 * Bump when the normalised output format changes, so old hashes are not compared to new ones.
 * v2: classic scripts are parsed with the classic-script goal (HTML-like comments), not 'unambiguous'.
 */
export const NORMALIZER_VERSION = 'babel8-v2';

export interface NormalizationResult {
  readonly status: NormalizationStatus;
  readonly normalized?: string;
  readonly normalizedSha256?: string;
  readonly error?: string;
}

export function normalizeLineEndings(source: string): string {
  let s = source;
  if (s.charCodeAt(0) === 0xfeff) s = s.slice(1);
  return s.replace(/\r\n?/g, '\n');
}

export interface NormalizeOptions {
  readonly maxChars?: number;
  /** How the browser runs the code (see parser.ts). Defaults to unknown: classic script first. */
  readonly goal?: ScriptGoal;
}

export function normalizeJavaScript(source: string, options: NormalizeOptions = {}): NormalizationResult {
  const maxChars = options.maxChars ?? 10 * 1024 * 1024;
  if (source.length > maxChars) return { status: 'too-large', error: `Source exceeds ${maxChars} characters` };
  const text = normalizeLineEndings(source);
  let ast;
  try {
    ast = parseForGoal(text, options.goal ?? 'unknown');
  } catch (error) {
    return { status: 'parse-error', error: (error as Error).message.split('\n')[0]?.slice(0, 300) ?? 'parse error' };
  }
  try {
    const { code } = generate(ast, {
      comments: false,
      compact: false,
      minified: false,
      concise: false,
      retainLines: false,
      jsescOption: { minimal: true },
    });
    const normalized = `${code.trim()}\n`;
    return { status: 'normalized', normalized, normalizedSha256: sha256Hex(normalized) };
  } catch (error) {
    return { status: 'parse-error', error: `generation failed: ${(error as Error).message.slice(0, 300)}` };
  }
}
