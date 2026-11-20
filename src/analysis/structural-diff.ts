import { createTwoFilesPatch } from 'diff';
import { normalizeJavaScript, normalizeLineEndings } from './normalizer.js';
import { goalForResourceType } from './parser.js';
import type { ResourceType } from '../types/index.js';

/**
 * Human-readable code diff between two versions of a script.
 *
 * Both versions are pretty-printed by the normaliser first, which turns
 * minified one-line bundles into reviewable, line-based code and hides pure
 * formatting noise. If either version cannot be parsed, the raw text (with
 * normalised line endings) is diffed instead.
 */

export interface CodeDiff {
  readonly mode: 'normalized' | 'raw';
  readonly patch: string;
  readonly truncated: boolean;
  readonly addedLines: number;
  readonly removedLines: number;
}

export interface DiffOptions {
  readonly context?: number;
  readonly maxLines?: number;
  readonly oldLabel?: string;
  readonly newLabel?: string;
  /** Resource type of the script, which decides classic-script vs module parsing. Unknown → classic script first. */
  readonly resourceType?: ResourceType;
}

export function diffScripts(oldSource: string, newSource: string, options: DiffOptions = {}): CodeDiff {
  const goal = goalForResourceType(options.resourceType);
  const a = normalizeJavaScript(oldSource, { goal });
  const b = normalizeJavaScript(newSource, { goal });
  const useNormalized = a.normalized !== undefined && b.normalized !== undefined;
  const left = useNormalized ? (a.normalized) : normalizeLineEndings(oldSource);
  const right = useNormalized ? (b.normalized) : normalizeLineEndings(newSource);
  const patch = createTwoFilesPatch(options.oldLabel ?? 'approved', options.newLabel ?? 'current', left, right, '', '', {
    context: options.context ?? 3,
  });
  const lines = patch.split('\n');
  const maxLines = options.maxLines ?? 400;
  let added = 0;
  let removed = 0;
  for (const line of lines) {
    if (line.startsWith('+') && !line.startsWith('+++')) added++;
    else if (line.startsWith('-') && !line.startsWith('---')) removed++;
  }
  const truncated = lines.length > maxLines;
  // Very long single lines (e.g. unparseable minified code) are clipped for display.
  const shown = (truncated ? lines.slice(0, maxLines) : lines).map((l) => (l.length > 400 ? `${l.slice(0, 400)}…` : l));
  return {
    mode: useNormalized ? 'normalized' : 'raw',
    patch: shown.join('\n') + (truncated ? `\n… diff truncated (${lines.length - maxLines} more lines)` : ''),
    truncated,
    addedLines: added,
    removedLines: removed,
  };
}
