import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path';
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
  'policy-accepted-update': 'A script covered by a script policy changed; the policy accepts new versions (new behaviour is still reported).',
  'pinned-hash-mismatch': 'A pinned script does not match any of its allowed hashes.',
  'vulnerable-library': 'A JavaScript library with known vulnerabilities (CVE) is loaded.',
};

export interface SarifOptions {
  /** Absolute path of thirdsentry.yml. */
  readonly configPath: string;
  /**
   * Repository root used to make artifact paths relative. Default:
   * GITHUB_WORKSPACE when it contains the config, else the enclosing Git
   * work tree, else the config's directory.
   */
  readonly baseDir?: string;
  readonly env?: NodeJS.ProcessEnv;
}

function isInside(dir: string, path: string): boolean {
  const rel = relative(dir, path);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}

/**
 * Code Scanning resolves artifact URIs against the repository root, so the
 * config path must be relative to that root (not to the config's directory,
 * which differs when thirdsentry.yml lives in a subdirectory).
 */
export function sarifBaseDir(configPath: string, env: NodeJS.ProcessEnv = process.env): string {
  const config = resolve(configPath);
  const workspace = env.GITHUB_WORKSPACE;
  if (workspace && isInside(resolve(workspace), config)) return resolve(workspace);
  for (let dir = dirname(config); ; dir = dirname(dir)) {
    if (existsSync(resolve(dir, '.git'))) return dir;
    if (dirname(dir) === dir) break;
  }
  return dirname(config);
}

/** Description used for finding kinds this version does not know (e.g. added by newer modules). */
function kindDescription(kind: string): string {
  return KIND_DESCRIPTIONS[kind] ?? `ThirdSentry finding of kind "${kind}".`;
}

function securitySeverity(severity: string): string {
  return SECURITY_SEVERITY[severity as Severity] ?? SECURITY_SEVERITY.info;
}

function level(severity: string): 'error' | 'warning' | 'note' {
  return LEVEL[severity as Severity] ?? 'note';
}

function ruleIdFor(f: Finding): string {
  const kind = String(f.kind || 'unknown').replace(/[^A-Za-z0-9._-]/g, '-');
  return `thirdsentry/${kind}`;
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
  parts.push(`Severity ${f.severity}, confidence ${f.confidence}. Why: ${explainScore(f.signals ?? [])}.`);
  if (f.recommendedAction) parts.push(`Next step: ${f.recommendedAction.replace('<finding-id>', f.id)}`);
  return parts.join(' ');
}

export async function buildSarif(report: AnalysisReport, options: SarifOptions): Promise<Record<string, unknown>> {
  const lines = await siteLines(options.configPath);
  const baseDir = options.baseDir ?? sarifBaseDir(options.configPath, options.env);
  const configRel = relative(baseDir, options.configPath);
  // Outside the repository: fall back to the file name rather than a "../" path.
  const configUri = (configRel && !configRel.startsWith('..') && !isAbsolute(configRel) ? configRel : basename(options.configPath)).split('\\').join('/') || 'thirdsentry.yml';

  const homepage = projectHomepage();
  const ruleIds = [...new Set(report.findings.map(ruleIdFor))].sort();
  const rules = ruleIds.map((id) => {
    const kind = id.slice('thirdsentry/'.length);
    const worst = report.findings.filter((f) => ruleIdFor(f) === id).reduce<Severity>((w, f) => (Number(securitySeverity(f.severity)) > Number(securitySeverity(w)) ? f.severity : w), 'info');
    return {
      id,
      name: kind.replace(/(^|-)(\w)/g, (_m, _d: string, c: string) => c.toUpperCase()),
      shortDescription: { text: kindDescription(kind) },
      fullDescription: { text: `${kindDescription(kind)} ThirdSentry reports changes and behaviour worth reviewing; a result is not proof of malicious activity.` },
      ...(homepage ? { helpUri: `${homepage.replace(/\/$/, '')}/blob/main/docs/rules.md` } : {}),
      help: { text: 'Review the change, confirm it with the vendor if unexpected, and approve it with "thirdsentry baseline --approve <finding-id>" once it is understood.' },
      defaultConfiguration: { level: level(worst) },
      properties: { tags: ['security', 'supply-chain', 'third-party-javascript'], 'security-severity': securitySeverity(worst), precision: 'medium' },
    };
  });

  const results = report.findings.map((f) => {
    const behaviour = (f.signals ?? []).filter((s) => s.id.includes('rule:')).map((s) => s.id.replace(/^(new-)?rule:/, ''));
    return {
      ruleId: ruleIdFor(f),
      ruleIndex: ruleIds.indexOf(ruleIdFor(f)),
      level: level(f.severity),
      message: { text: messageFor(f) },
      locations: [
        {
          physicalLocation: { artifactLocation: { uri: configUri }, region: { startLine: lines.get(f.site) ?? 1 } },
          ...(f.site ? { logicalLocations: [{ name: f.site, kind: 'module', fullyQualifiedName: `${f.site}${f.page ?? ''}` }] } : {}),
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
        'security-severity': securitySeverity(f.severity),
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
        // No automationDetails.id: the upload step's `category` identifies the
        // analysis. Deriving it from the scanned sites made every --site subset
        // (or a newly added site) a separate analysis whose old alerts never close.
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
