import type { ScriptDriftConfig } from '../config/schema.js';
import type { ScriptResource } from '../types/index.js';
import { matchesAnyGlob } from '../utils/patterns.js';
import { analyzeJavaScript } from './ast-analyzer.js';
import { RULES } from './indicator-rules.js';
import type { Rule } from './rule-types.js';

/**
 * Runs static behaviour analysis over every captured JavaScript resource of a
 * scan and attaches an indicator summary to it. Runs in the trusted analysis
 * process on content captured by the browser worker; the content is parsed,
 * never executed.
 */

const ANALYZABLE = new Set<ScriptResource['type']>([
  'script',
  'module',
  'inline-script',
  'inline-module',
  'dedicated-worker',
  'shared-worker',
  'service-worker',
  'blob-script',
  'data-script',
  'fetched-script',
]);

export function enabledRules(config: Pick<ScriptDriftConfig, 'rules'>): Rule[] {
  return RULES.filter((r) => config.rules[r.id]?.enabled !== false);
}

export function analyzeResources(
  resources: readonly ScriptResource[],
  contents: ReadonlyMap<string, Buffer>,
  config: Pick<ScriptDriftConfig, 'rules' | 'analysis'>,
): void {
  if (!config.analysis.enabled) return;
  const rules = enabledRules(config);
  const cache = new Map<string, ReturnType<typeof analyzeJavaScript>>();
  for (const resource of resources) {
    if (!ANALYZABLE.has(resource.type) || resource.discovery.includes('importmap')) continue;
    const sha = resource.hashes.sha256;
    const body = sha ? contents.get(sha) : undefined;
    if (!sha || !body) {
      resource.indicators = { analyzed: false, error: `content ${resource.content.status}`, counts: {}, matches: [], hosts: [] };
      continue;
    }
    const url = resource.finalUrl ?? resource.originalUrl ?? resource.identity;
    const applicable = rules.filter((r) => !matchesAnyGlob(url, config.rules[r.id]?.ignoreResources ?? []) && !matchesAnyGlob(resource.identity, config.rules[r.id]?.ignoreResources ?? []));
    const cacheKey = `${sha}|${applicable.map((r) => r.id).join(',')}`;
    let result = cache.get(cacheKey);
    if (!result) {
      result = analyzeJavaScript(body.toString('utf8'), { rules: applicable, maxBytes: config.analysis.maxScriptBytes });
      cache.set(cacheKey, result);
    }
    resource.indicators = {
      analyzed: result.analyzed,
      ...(result.error ? { error: result.error } : {}),
      counts: result.counts,
      matches: result.matches,
      hosts: result.hosts,
    };
  }
}
