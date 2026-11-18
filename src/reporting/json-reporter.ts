import type { AnalysisReport } from '../types/report.js';
import { stableStringify } from '../utils/fs.js';

/**
 * JSON report: the complete analysis report (scan summary, per-site
 * comparison, findings with signals and evidence, coverage limitations).
 * Versioned via `schemaVersion` and `kind`.
 */
export function renderJsonReport(report: AnalysisReport): string {
  return stableStringify(report);
}
