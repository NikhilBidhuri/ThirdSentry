import type { NodePath } from '@babel/traverse';
import type { Node } from '@babel/types';
import type { Severity } from '../config/schema.js';
import type { Confidence } from '../types/findings.js';

/**
 * Static-analysis rule definition.
 *
 * Rules observe AST nodes during a single shared traversal and report
 * matches. Aggregate rules (obfuscation, source+sink combinations) decide in
 * `finalize` based on what was collected. Rules describe *behaviour worth
 * reviewing*; none of them is evidence of malicious intent on its own.
 */

export interface RuleMatch {
  readonly ruleId: string;
  readonly line: number;
  readonly column: number;
  /** Short source excerpt (never the whole script). */
  readonly snippet: string;
  readonly detail?: string;
}

export interface AnalysisState {
  /** Matches by rule id (all rules, before per-rule caps). */
  readonly counts: Map<string, number>;
  readonly matches: RuleMatch[];
  /** Hostnames referenced in URL-like string literals. */
  readonly hosts: Set<string>;
  /** Free-form per-rule scratch space for aggregate rules. */
  readonly scratch: Map<string, number>;
  readonly source: string;
  report(ruleId: string, node: Node, detail?: string): void;
}

export type NodeHandler = (path: NodePath, state: AnalysisState) => void;

export interface Rule {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  /** Which kind of behaviour this is; used by combination rules. */
  readonly role: 'source' | 'sink' | 'dynamic-code' | 'obfuscation' | 'hooking' | 'combination' | 'loader';
  /** Plain-language explanation of why the behaviour matters. */
  readonly explanation: string;
  /** What a developer should do to investigate a match. */
  readonly investigation: string;
  /** Common legitimate reasons for this pattern. */
  readonly falsePositives: string;
  /** Node types → handlers. */
  readonly visitors?: Partial<Record<string, NodeHandler>>;
  /** Called once after traversal; may call state.report for aggregate matches. */
  finalize?(state: AnalysisState, ast: Node): void;
}

/** Default risk weight contributed by a newly introduced match, by rule severity. */
export const SEVERITY_WEIGHT: Record<Severity, number> = { info: 2, low: 6, medium: 12, high: 22, critical: 32 };
