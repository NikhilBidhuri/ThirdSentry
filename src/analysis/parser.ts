import { parse, type ParseResult } from '@babel/parser';
import type { File } from '@babel/types';

/**
 * Parse JavaScript as found on the web. Third-party code may be a classic
 * script or a module, so `unambiguous` is used, with the most permissive
 * options that remain standards-based (no JSX/TypeScript/Flow).
 */
export function parseJavaScript(source: string, options: { errorRecovery?: boolean; sourceType?: 'script' | 'module' | 'unambiguous' } = {}): ParseResult<File> {
  return parse(source, {
    sourceType: options.sourceType ?? 'unambiguous',
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
    return parseJavaScript(source, { errorRecovery: true }).program.sourceType === 'module';
  } catch {
    return false;
  }
}

/** Parse, retrying as a classic script if module parsing fails (e.g. `with`, legacy octal). */
export function parseLenient(source: string, errorRecovery = false): ParseResult<File> {
  try {
    return parseJavaScript(source, { errorRecovery });
  } catch (first) {
    try {
      return parseJavaScript(source, { errorRecovery, sourceType: 'script' });
    } catch {
      throw first;
    }
  }
}
