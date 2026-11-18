import { formatZodIssues } from '../config/loader.js';
import { BaselineError } from '../utils/errors.js';
import { BaselineSchema, type Baseline } from './baseline-schema.js';

/**
 * Validate baseline data loaded from disk. Baselines are reviewed in Git and
 * may be edited by hand, so both the schema and semantic invariants are
 * checked before a baseline is trusted for comparison.
 */
export function validateBaseline(data: unknown, expectedSite: string, source: string): Baseline {
  const parsed = BaselineSchema.safeParse(data);
  if (!parsed.success) {
    throw new BaselineError(`Invalid baseline ${source}:\n${formatZodIssues(parsed.error)}`, 'Fix the file or regenerate it with "scriptdrift baseline".');
  }
  const baseline = parsed.data;
  if (baseline.site !== expectedSite) {
    throw new BaselineError(`Baseline ${source} belongs to site "${baseline.site}", expected "${expectedSite}"`);
  }
  const seen = new Set<string>();
  for (const r of baseline.resources) {
    if (seen.has(r.identity)) throw new BaselineError(`Baseline ${source} lists resource ${r.identity} more than once`);
    seen.add(r.identity);
  }
  return baseline;
}
