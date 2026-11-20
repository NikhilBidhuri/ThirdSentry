import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createBaseline } from '../../src/baseline/baseline-manager.js';
import { compareSite } from '../../src/monitoring/comparison-engine.js';
import { buildFindings } from '../../src/monitoring/finding-engine.js';
import { renderHtmlReport, escapeHtml } from '../../src/reporting/html-reporter.js';
import { renderJsonReport } from '../../src/reporting/json-reporter.js';
import { buildSarif, sarifBaseDir } from '../../src/reporting/sarif-reporter.js';
import type { Finding } from '../../src/types/findings.js';
import type { AnalysisReport } from '../../src/types/report.js';
import { destination, scan, scriptResource, site } from '../fixtures/builders.js';
import { tempDir } from '../helpers.js';

const EVIL_URL = 'https://cdn.example/x.js?"><script>alert(1)</script>';

function sampleReport(extra: Partial<Finding> = {}): { report: AnalysisReport; findings: Finding[] } {
  const base = createBaseline(site([scriptResource('https://cdn.example/a.js', 'a()')]), { scanId: 's1' });
  const current = site([scriptResource('https://cdn.example/a.js', 'b()'), scriptResource(EVIL_URL, 'x()')], {
    destinations: [destination('cdn.example'), destination('collect.evil.example', { methods: ['POST'] })],
  });
  const findings = buildFindings(compareSite(current, base).changes, { site: current }).map((f, i) => (i === 0 ? { ...f, ...extra } : f));
  const report: AnalysisReport = {
    schemaVersion: 1,
    kind: 'thirdsentry-report',
    generatedAt: '2026-01-01T00:00:00.000Z',
    toolVersion: '0.1.0',
    scanId: 'scan-1',
    scanPath: '.thirdsentry/reports/scans/scan-1.json',
    scanStatus: 'partial',
    scanStartedAt: '2026-01-01T00:00:00.000Z',
    scanFinishedAt: '2026-01-01T00:01:00.000Z',
    scanSummary: { sites: 1, pages: 1, pagesComplete: 1, pagesPartial: 0, pagesFailed: 0, resources: 2, firstPartyResources: 0, thirdPartyResources: 2, resourcesWithoutContent: 0, thirdPartyDomains: 2, blockedConnections: 0 },
    scanIssues: [{ level: 'warning', code: 'network-not-idle', message: 'idle <timeout>' }],
    sites: [{ name: 'shop', url: 'https://shop.example/', status: 'complete', baseline: { exists: true, path: 'x' }, unchangedResources: 0, newResources: 1, modifiedResources: 1, removedResources: 0, newDomains: [], pagesNotCompared: [], findings: findings.length }],
    findings,
    findingCounts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
    highestSeverity: 'medium',
    coverageLimitations: ['Only configured pages are visited.'],
    headline: 'Something <changed>',
  };
  return { report, findings };
}

describe('JSON report', () => {
  it('is stable, versioned JSON', () => {
    const { report } = sampleReport();
    const text = renderJsonReport(report);
    expect(JSON.parse(text)).toMatchObject({ kind: 'thirdsentry-report', schemaVersion: 1 });
    expect(renderJsonReport(report)).toBe(text);
  });
});

describe('SARIF report', () => {
  it('produces valid SARIF 2.1.0 anchored to the site entry in the config', async () => {
    const dir = await tempDir('sarif-');
    const configPath = join(dir, 'thirdsentry.yml');
    await writeFile(configPath, 'version: 1\nsites:\n  - name: other\n    url: https://o.example\n  - name: shop\n    url: https://shop.example\n');
    const { report, findings } = sampleReport({ suppressed: { reason: 'accepted' } });
    const sarif = (await buildSarif(report, { configPath, baseDir: dir })) as {
      version: string;
      runs: Array<{ tool: { driver: { name: string; rules: Array<{ id: string; properties: Record<string, unknown> }> } }; results: Array<Record<string, unknown>>; invocations: Array<{ executionSuccessful: boolean }> }>;
    };
    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0];
    expect(run?.tool.driver.name).toBe('ThirdSentry');
    expect(run?.results).toHaveLength(findings.length);
    expect(run?.invocations[0]?.executionSuccessful).toBe(false);
    const first = run?.results[0] as { ruleId: string; ruleIndex: number; level: string; locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }>; partialFingerprints: Record<string, string>; suppressions?: unknown[] };
    expect(run?.tool.driver.rules[first.ruleIndex]?.id).toBe(first.ruleId);
    expect(first.locations[0]?.physicalLocation.artifactLocation.uri).toBe('thirdsentry.yml');
    expect(first.locations[0]?.physicalLocation.region.startLine).toBe(5);
    expect(first.partialFingerprints['thirdsentryFindingId/v1']).toBe(findings[0]?.id);
    expect(first.suppressions).toEqual([{ kind: 'external', justification: 'accepted' }]);
    expect(['error', 'warning', 'note']).toContain(first.level);
    expect(run?.tool.driver.rules[0]?.properties['security-severity']).toMatch(/^\d+\.\d$/);
  });
});

describe('HTML report', () => {
  it('escapes untrusted strings and cannot run scripts', () => {
    const { report } = sampleReport();
    const html = renderHtmlReport(report, scan([site([scriptResource(EVIL_URL, 'x()')])]));
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('Something &lt;changed&gt;');
    expect(html).toMatch(/Content-Security-Policy" content="default-src 'none'/);
    expect(html.toLowerCase()).not.toMatch(/<script[\s>]/);
    expect(html).not.toMatch(/(src|href)="https?:/);
  });

  it('contains the sections ordinary developers need', () => {
    const { report } = sampleReport();
    const html = renderHtmlReport(report, scan([site([scriptResource('https://cdn.example/a.js', 'a()')])]));
    for (const section of ['Summary', 'Findings', 'Sites', 'Coverage limitations', 'Scripts on shop', 'Outbound destinations', 'What to do']) expect(html).toContain(section);
  });

  it('escapes all HTML special characters', () => {
    expect(escapeHtml(`<a href="x" onclick='y'>&</a>`)).toBe('&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
  });
});

describe('SARIF analysis identity and paths', () => {
  it('does not derive automationDetails.id from the scanned sites (the upload category identifies the analysis)', async () => {
    const dir = await tempDir('sarif-auto-');
    const configPath = join(dir, 'thirdsentry.yml');
    await writeFile(configPath, 'version: 1\nsites:\n  - name: shop\n    url: https://shop.example\n');
    const { report } = sampleReport();
    const sarif = (await buildSarif(report, { configPath, baseDir: dir })) as { runs: Array<Record<string, unknown>> };
    expect(sarif.runs[0]?.automationDetails).toBeUndefined();
  });

  it('makes the config path relative to the repository root, not the config directory', async () => {
    const repo = await tempDir('sarif-repo-');
    await mkdir(join(repo, '.git'));
    await mkdir(join(repo, 'monitoring'));
    const configPath = join(repo, 'monitoring', 'thirdsentry.yml');
    await writeFile(configPath, 'version: 1\nsites:\n  - name: shop\n    url: https://shop.example\n');
    const { report } = sampleReport();
    type Sarif = { runs: Array<{ results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }> }> };
    const uri = (s: Sarif): string | undefined => s.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri;
    expect(uri((await buildSarif(report, { configPath, env: {} })) as Sarif)).toBe('monitoring/thirdsentry.yml');
    expect(sarifBaseDir(configPath, {})).toBe(repo);
    // GITHUB_WORKSPACE wins when it contains the config.
    expect(uri((await buildSarif(report, { configPath, env: { GITHUB_WORKSPACE: join(repo, 'monitoring', '..') } })) as Sarif)).toBe('monitoring/thirdsentry.yml');
    const nested = join(repo, 'monitoring');
    expect(uri((await buildSarif(report, { configPath, env: { GITHUB_WORKSPACE: nested } })) as Sarif)).toBe('thirdsentry.yml');
  });

  it('generates a generic rule for finding kinds it does not know', async () => {
    const dir = await tempDir('sarif-kind-');
    const configPath = join(dir, 'thirdsentry.yml');
    await writeFile(configPath, 'version: 1\nsites:\n  - name: shop\n    url: https://shop.example\n');
    const { report } = sampleReport();
    const odd = { id: 'TS-00000000beef', kind: 'coverage-degraded', title: 'Coverage degraded', site: 'shop', severity: 'medium', detectedAt: 'x', reason: 'Fewer pages loaded.' } as unknown as Finding;
    const sarif = (await buildSarif({ ...report, findings: [...report.findings, odd] }, { configPath, baseDir: dir })) as {
      runs: Array<{ tool: { driver: { rules: Array<{ id: string; shortDescription: { text: string } }> } }; results: Array<{ ruleId: string; ruleIndex: number; level: string }> }>;
    };
    const run = sarif.runs[0];
    const rule = run?.tool.driver.rules.find((r) => r.id === 'thirdsentry/coverage-degraded');
    expect(rule?.shortDescription.text).toMatch(/coverage-degraded/);
    const result = run?.results.find((r) => r.ruleId === 'thirdsentry/coverage-degraded');
    expect(run?.tool.driver.rules[result?.ruleIndex ?? -1]?.id).toBe('thirdsentry/coverage-degraded');
    expect(result?.level).toBe('warning');
    // The HTML report renders it too.
    expect(renderHtmlReport({ ...report, findings: [odd] }, undefined)).toContain('Coverage degraded');
  });
});
