import { readFile } from 'node:fs/promises';
import { relative } from 'node:path';
import { RULES_BY_ID } from '../analysis/indicator-rules.js';
import { explainScore } from '../analysis/risk-scoring.js';
import type { Finding, Severity } from '../types/findings.js';
import type { AnalysisReport } from '../types/report.js';
import { projectHomepage } from '../utils/version.js';

/**
 * SARIF 2.1.0 output for GitHub Code Scanning and other SARIF consumers.
 *
 * Third-party scripts are not files in your repository, so every result is
 * anchored to the site's entry in thirdsentry.yml (the closest thing in the
 * repository that "owns" the monitored page). The script URL, hashes and
 * evidence are carried in the message and result properties.
 */

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
/** GitHub uses `security-severity` (0-10) to rank security alerts. */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };

const KIND_DESCRIPTIONS: Record<string, string> = {
  'resource-added': 'A script that is not in the approved baseline started loading.',
  'resource-removed': 'An approved script no longer loads.',
  'resource-modified': 'The content of an approved script changed.',
  'resource-formatting-changed': 'An approved script was reformatted; the parsed code is unchanged.',
  'resource-moved': 'Approved code is now served from a different URL or domain.',
  'resource-type-changed': 'A resource is now loaded as a different type.',
  'redirect-changed': 'A script URL now redirects to a different destination.',
  'content-unavailable': 'The content of an approved script could not be captured.',
  'sri-mismatch': 'The Subresource Integrity attribute does not match the served content.',
  'new-script-domain': 'Scripts are loaded from a domain never approved for this site.',
  'new-outbound-domain': 'The page sends requests to a domain never approved for this site.',
  'new-outbound-host': 'A new hostname under an approved domain is contacted.',
  'denylisted-domain': 'A denylisted domain is used by the page.',
  'iframe-origin-added': 'A new iframe origin is embedded in the page.',
  'iframe-origin-removed': 'An approved iframe origin is no longer embedded.',
};

export interface SarifOptions {
  /** Absolute path of thirdsentry.yml. */
  readonly configPath: string;
  /** Repository root used to make artifact paths relative (default: config directory's project root). */
  readonly baseDir: string;
}

function ruleIdFor(f: Finding): string {
  return `thirdsentry/${f.kind}`;
}

async function siteLines(configPath: string): Promise<Map<string, number>> {
  const lines = new Map<string, number>();
  try {
    const text = await readFile(configPath, 'utf8');
    text.split(/\r?\n/).forEach((line, i) => {
      const m = /^\s*-?\s*name:\s*["']?([A-Za-z0-9._-]+)["']?\s*$/.exec(line);
      if (m?.[1] && !lines.has(m[1])) lines.set(m[1], i + 1);
    });
  } catch {
    // Config not readable: results fall back to line 1.
  }
  return lines;
}

function messageFor(f: Finding): string {
  const parts = [f.title + (f.resourceUrl ? `: ${f.resourceUrl}` : '') + '.', f.reason];
  if (f.previousHash !== undefined || f.currentHash !== undefined) parts.push(`Previous SHA-256: ${f.previousHash ?? 'none'}. Current SHA-256: ${f.currentHash ?? 'none'}.`);
  parts.push(`Severity ${f.severity}, confidence ${f.confidence}. Why: ${explainScore(f.signals)}.`);
  parts.push(`Next step: ${f.recommendedAction.replace('<finding-id>', f.id)}`);
  return parts.join(' ');
}

export async function buildSarif(report: AnalysisReport, options: SarifOptions): Promise<Record<string, unknown>> {
  const lines = await siteLines(options.configPath);
  const configUri = relative(options.baseDir, options.configPath).split('\\').join('/') || 'thirdsentry.yml';

  const homepage = projectHomepage();
  const ruleIds = [...new Set(report.findings.map(ruleIdFor))].sort();
  const rules = ruleIds.map((id) => {
    const kind = id.slice('thirdsentry/'.length);
    const worst = report.findings.filter((f) => ruleIdFor(f) === id).reduce<Severity>((w, f) => (SECURITY_SEVERITY[f.severity] > SECURITY_SEVERITY[w] ? f.severity : w), 'info');
    return {
      id,
      name: kind.replace(/(^|-)(\w)/g, (_m, _d: string, c: string) => c.toUpperCase()),
      shortDescription: { text: KIND_DESCRIPTIONS[kind] ?? kind },
      fullDescription: { text: `${KIND_DESCRIPTIONS[kind] ?? kind} ThirdSentry reports changes and behaviour worth reviewing; a result is not proof of malicious activity.` },
      ...(homepage ? { helpUri: `${homepage.replace(/\/$/, '')}/blob/main/docs/rules.md` } : {}),
      help: { text: 'Review the change, confirm it with the vendor if unexpected, and approve it with "thirdsentry baseline --approve <finding-id>" once it is understood.' },
      defaultConfiguration: { level: LEVEL[worst] },
      properties: { tags: ['security', 'supply-chain', 'third-party-javascript'], 'security-severity': SECURITY_SEVERITY[worst], precision: 'medium' },
    };
  });

  const results = report.findings.map((f) => {
    const behaviour = f.signals.filter((s) => s.id.includes('rule:')).map((s) => s.id.replace(/^(new-)?rule:/, ''));
    return {
      ruleId: ruleIdFor(f),
      ruleIndex: ruleIds.indexOf(ruleIdFor(f)),
      level: LEVEL[f.severity],
      message: { text: messageFor(f) },
      locations: [
        {
          physicalLocation: { artifactLocation: { uri: configUri }, region: { startLine: lines.get(f.site) ?? 1 } },
          logicalLocations: [{ name: f.site, kind: 'module', fullyQualifiedName: `${f.site}${f.page ?? ''}` }],
        },
      ],
      partialFingerprints: { 'thirdsentryFindingId/v1': f.id },
      properties: {
        findingId: f.id,
        site: f.site,
        pages: f.pages,
        resourceUrl: f.resourceUrl,
        resourceType: f.resourceType,
        domain: f.domain,
        previousHash: f.previousHash,
        currentHash: f.currentHash,
        severity: f.severity,
        confidence: f.confidence,
        category: f.category,
        score: f.score,
        signals: f.signals,
        behaviourRules: behaviour.map((id) => ({ id, name: RULES_BY_ID.get(id)?.name ?? id })),
        'security-severity': SECURITY_SEVERITY[f.severity],
      },
      ...(f.suppressed ? { suppressions: [{ kind: 'external', justification: f.suppressed.reason }] } : {}),
    };
  });

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'ThirdSentry', ...(homepage ? { informationUri: homepage } : {}), semanticVersion: report.toolVersion, version: report.toolVersion, rules } },
        automationDetails: { id: `thirdsentry/${report.sites.map((s) => s.name).join('+')}/` },
        invocations: [
          {
            executionSuccessful: report.scanStatus === 'complete',
            startTimeUtc: report.scanStartedAt,
            endTimeUtc: report.scanFinishedAt,
            toolExecutionNotifications: report.scanIssues.map((i) => ({ level: i.level === 'error' ? 'error' : i.level === 'warning' ? 'warning' : 'note', message: { text: i.message }, descriptor: { id: i.code } })),
          },
        ],
        results,
        properties: { scanId: report.scanId, headline: report.headline, coverageLimitations: report.coverageLimitations },
      },
    ],
  };
}
