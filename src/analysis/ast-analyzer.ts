import { default as traverse, type NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';
import { normalizeLineEndings } from './normalizer.js';
import { parseForGoal, type ScriptGoal } from './parser.js';
import { RULES } from './indicator-rules.js';
import type { AnalysisState, NodeHandler, Rule, RuleMatch } from './rule-types.js';

/**
 * Static JavaScript analysis: parse once with Babel, traverse once, and let
 * every enabled rule observe the nodes it is interested in.
 *
 * Safety: the analysed code is untrusted input. It is parsed, never executed.
 * Input size is capped, and any parser/traversal failure (including stack
 * exhaustion on pathological nesting) is caught and reported as
 * "not analysed" rather than crashing the scan.
 */

export interface AnalyzerOptions {
  readonly rules?: readonly Rule[];
  /** Scripts larger than this are not analysed (reported as such). */
  readonly maxBytes?: number;
  /** Maximum matches with snippets retained per rule (counts are always complete). */
  readonly maxMatchesPerRule?: number;
  /** How the browser runs the code (see parser.ts). Defaults to unknown: classic script first. */
  readonly goal?: ScriptGoal;
}

export interface AnalysisResult {
  readonly analyzed: boolean;
  readonly error?: string;
  readonly counts: Readonly<Record<string, number>>;
  readonly matches: readonly RuleMatch[];
  /** Hostnames referenced in URL-like strings and network calls. */
  readonly hosts: readonly string[];
}

const DEFAULT_MAX_BYTES = 3 * 1024 * 1024;
const SNIPPET_RADIUS = 70;

class LineIndex {
  private readonly starts: number[] = [0];
  constructor(private readonly source: string) {
    for (let i = 0; i < source.length; i++) if (source.charCodeAt(i) === 10) this.starts.push(i + 1);
  }
  snippet(line: number, column: number): string {
    const start = this.starts[line - 1];
    if (start === undefined) return '';
    const end = this.starts[line] ?? this.source.length;
    const text = this.source.slice(start, end).replace(/\n$/, '');
    const from = Math.max(0, column - SNIPPET_RADIUS);
    const to = Math.min(text.length, column + SNIPPET_RADIUS);
    return `${from > 0 ? '…' : ''}${text.slice(from, to).trim()}${to < text.length ? '…' : ''}`;
  }
}

/**
 * Node types that behave like the key type and are dispatched to the same
 * rule handlers, so that `eval?.(x)`, `` Function`x` `` and `document?.cookie`
 * cannot evade rules written for plain calls and member accesses.
 */
const VISITOR_ALIASES: Readonly<Record<string, readonly string[]>> = {
  CallExpression: ['OptionalCallExpression', 'TaggedTemplateExpression'],
  MemberExpression: ['OptionalMemberExpression'],
};

function buildVisitor(rules: readonly Rule[], state: AnalysisState): Record<string, (path: NodePath) => void> {
  const byType = new Map<string, NodeHandler[]>();
  for (const rule of rules) {
    for (const [type, handler] of Object.entries(rule.visitors ?? {})) {
      if (!handler) continue;
      for (const t of [type, ...(VISITOR_ALIASES[type] ?? [])]) {
        const list = byType.get(t) ?? [];
        list.push(handler);
        byType.set(t, list);
      }
    }
  }
  const visitor: Record<string, (path: NodePath) => void> = {};
  for (const [type, handlers] of byType) {
    visitor[type] = (path: NodePath) => {
      for (const h of handlers) h(path, state);
    };
  }
  return visitor;
}

export function analyzeJavaScript(rawSource: string, options: AnalyzerOptions = {}): AnalysisResult {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const rules = options.rules ?? RULES;
  const maxMatches = options.maxMatchesPerRule ?? 5;
  if (Buffer.byteLength(rawSource, 'utf8') > maxBytes) {
    return { analyzed: false, error: `script larger than analysis.maxScriptBytes (${maxBytes})`, counts: {}, matches: [], hosts: [] };
  }
  const source = normalizeLineEndings(rawSource);
  const enabled = new Set(rules.map((r) => r.id));
  const counts = new Map<string, number>();
  const matches: RuleMatch[] = [];
  const perRule = new Map<string, number>();
  let lines: LineIndex | undefined;

  const state: AnalysisState = {
    counts,
    matches,
    hosts: new Set<string>(),
    scratch: new Map<string, number>(),
    source,
    report(ruleId: string, node: Node, detail?: string) {
      if (!enabled.has(ruleId)) return;
      counts.set(ruleId, (counts.get(ruleId) ?? 0) + 1);
      const kept = perRule.get(ruleId) ?? 0;
      if (kept >= maxMatches) return;
      perRule.set(ruleId, kept + 1);
      const line = node.loc?.start.line ?? 1;
      const column = node.loc?.start.column ?? 0;
      lines ??= new LineIndex(source);
      matches.push({
        ruleId,
        line,
        column,
        snippet: node.type === 'File' || node.type === 'Program' ? '' : lines.snippet(line, column),
        ...(detail ? { detail: detail.slice(0, 300) } : {}),
      });
    },
  };

  let ast;
  try {
    ast = parseForGoal(source, options.goal ?? 'unknown', true);
  } catch (error) {
    return { analyzed: false, error: `parse error: ${(error as Error).message.split('\n')[0]?.slice(0, 200) ?? ''}`, counts: {}, matches: [], hosts: [] };
  }
  try {
    traverse(ast, buildVisitor(rules, state));
    for (const rule of rules) rule.finalize?.(state, ast);
  } catch (error) {
    return { analyzed: false, error: `analysis error: ${(error as Error).message.slice(0, 200)}`, counts: {}, matches: [], hosts: [] };
  }
  return {
    analyzed: true,
    counts: Object.fromEntries([...counts.entries()].sort(([a], [b]) => a.localeCompare(b))),
    matches,
    hosts: [...state.hosts].sort().slice(0, 100),
  };
}
