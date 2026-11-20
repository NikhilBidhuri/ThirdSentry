import { parse, type ParseResult } from '@babel/parser';
import type { File } from '@babel/types';
import type { ResourceType } from '../types/index.js';

/**
 * Parsing goal of a piece of JavaScript, as the browser will run it.
 *
 *  - `script`: a classic script (external/inline `<script>`, classic workers,
 *    blob/data scripts). Browsers apply Annex B semantics, in particular
 *    HTML-like comments: `<!--` starts a single-line comment anywhere, and
 *    `-->` at the start of a line does too. Babel implements these in
 *    `sourceType: 'script'`.
 *  - `module`: an ES module, where those sequences are ordinary operators.
 *  - `unknown`: the goal is not known (code fetched with fetch/XHR, or a
 *    caller without a resource type). Parsed as a classic script first,
 *    because that is what browsers do by default, and as a module only if
 *    that fails.
 *
 * Parsing a classic script with the wrong goal desynchronises the analyser
 * from the browser: `a <!--b /*\n payload \n// *\/` is `a < !(--b) /* … *\/`
 * for a module parser, which hides `payload` inside a block comment, while a
 * browser comments out the rest of the first line and runs `payload`.
 */
export type ScriptGoal = 'script' | 'module' | 'unknown';

const MODULE_TYPES = new Set<ResourceType>(['module', 'inline-module']);

/** Parsing goal for a resource type (undefined → unknown). */
export function goalForResourceType(type: ResourceType | undefined): ScriptGoal {
  if (type === undefined || type === 'fetched-script') return 'unknown';
  return MODULE_TYPES.has(type) ? 'module' : 'script';
}

/**
 * Parse JavaScript with the given Babel source type and the most permissive
 * options that remain standards-based (no JSX/TypeScript/Flow). Prefer
 * {@link parseForGoal}, which picks the source type the browser uses.
 */
export function parseJavaScript(source: string, options: { errorRecovery?: boolean; sourceType?: 'script' | 'module' | 'unambiguous' } = {}): ParseResult<File> {
  return parse(source, {
    sourceType: options.sourceType ?? 'script',
    errorRecovery: options.errorRecovery ?? false,
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowImportExportEverywhere: true,
    allowUndeclaredExports: true,
    allowNewTargetOutsideFunction: true,
    allowSuperOutsideMethod: true,
    ranges: false,
    tokens: false,
    plugins: [],
  });
}

/**
 * True when the source can only be an ES module (contains top-level
 * import/export). Used to classify scripts loaded via import() when the
 * browser does not send Sec-Fetch-* metadata (e.g. plain-HTTP origins).
 */
export function isModuleSource(source: string): boolean {
  try {
    return parseJavaScript(source, { errorRecovery: true, sourceType: 'unambiguous' }).program.sourceType === 'module';
  } catch {
    return false;
  }
}

/**
 * Parse with the goal the browser uses. Classic scripts (and unknown goals)
 * are parsed as `script`, with HTML-like comment semantics; modules as
 * `module`. If the preferred goal fails, the other one is tried so that a
 * mislabelled resource can still be analysed: the browser rejects code that
 * does not parse under its goal, so the fallback cannot reveal less than
 * what runs.
 */
export function parseForGoal(source: string, goal: ScriptGoal = 'unknown', errorRecovery = false): ParseResult<File> {
  const order: ReadonlyArray<'script' | 'module'> = goal === 'module' ? ['module', 'script'] : ['script', 'module'];
  let firstError: unknown;
  for (const sourceType of order) {
    try {
      return parseJavaScript(source, { errorRecovery, sourceType });
    } catch (error) {
      firstError ??= error;
    }
  }
  throw firstError;
}

/** Parse with an unknown goal (classic script first, then module). */
export function parseLenient(source: string, errorRecovery = false): ParseResult<File> {
  return parseForGoal(source, 'unknown', errorRecovery);
}
