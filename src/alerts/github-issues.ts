import type { AlertFinding, AlertPayload } from './alert-payload.js';
import { AlertDeliveryError, requireHttpsUrl, sendHttp, type FetchLike } from './http.js';

/**
 * GitHub Issues integration: one issue per finding, de-duplicated by a hidden
 * marker in the issue body. Requires a token with `issues: write` on the
 * repository (in GitHub Actions: `permissions: issues: write` and GITHUB_TOKEN).
 */

export interface GithubTarget {
  readonly repository: string;
  readonly token: string;
  readonly apiUrl: string;
  readonly labels: readonly string[];
  readonly maxIssuesPerRun: number;
}

const MARKER = (id: string): string => `<!-- scriptdrift-finding: ${id} -->`;

function headers(token: string): Record<string, string> {
  return {
    accept: 'application/vnd.github+json',
    authorization: `Bearer ${token}`,
    'x-github-api-version': '2022-11-28',
    'content-type': 'application/json',
  };
}

function mdEscape(value: string): string {
  return value.replace(/[\\`*_{}[\]<>|]/g, (c) => `\\${c}`);
}

export function issueBody(f: AlertFinding, payload: AlertPayload): string {
  const lines = [
    MARKER(f.id),
    `**Severity:** ${f.severity} · **Confidence:** ${f.confidence} · **Category:** ${f.category}`,
    `**Site:** ${mdEscape(f.site)} · **Pages:** ${f.pages.map(mdEscape).join(', ') || 'n/a'}`,
    f.resourceUrl ? `**Resource:** \`${f.resourceUrl.replace(/`/g, '')}\`` : '',
    '',
    mdEscape(f.reason),
    '',
    f.previousHash !== undefined || f.currentHash !== undefined ? `| | SHA-256 |\n|---|---|\n| previous | \`${f.previousHash ?? 'none'}\` |\n| current | \`${f.currentHash ?? 'none'}\` |\n` : '',
    `**Why this rating:** ${mdEscape(f.why)}`,
    '',
    '<details><summary>Evidence</summary>',
    '',
    ...f.evidence.map((e) => `- **${mdEscape(e.label)}:** \`${e.value.replace(/`/g, '')}\``),
    '',
    '</details>',
    '',
    `**What to do:** ${mdEscape(f.recommendedAction)}`,
    '',
    `_Scan ${payload.scanId} · report: ${mdEscape(payload.reportLocation)} · finding ${f.id}_`,
    '',
    '_ScriptDrift reports changes worth reviewing; this is not proof of compromise._',
  ];
  return lines.filter((l, i, all) => !(l === '' && all[i - 1] === '')).join('\n');
}

async function existingFindingIds(target: GithubTarget, api: URL, timeoutMs: number, fetchImpl?: FetchLike): Promise<Set<string>> {
  const ids = new Set<string>();
  const label = target.labels[0];
  for (let page = 1; page <= 5; page++) {
    const url = new URL(`${api.pathname.replace(/\/$/, '')}/repos/${target.repository}/issues`, api);
    url.searchParams.set('state', 'open');
    url.searchParams.set('per_page', '100');
    url.searchParams.set('page', String(page));
    if (label) url.searchParams.set('labels', label);
    const res = await sendHttp({ method: 'GET', url: url.toString(), headers: headers(target.token), timeoutMs }, fetchImpl);
    let issues: Array<{ body?: string | null }>;
    try {
      issues = JSON.parse(res.text) as Array<{ body?: string | null }>;
    } catch {
      throw new AlertDeliveryError('GitHub returned an unexpected response while listing issues');
    }
    for (const issue of issues) {
      for (const m of (issue.body ?? '').matchAll(/<!-- scriptdrift-finding: (SD-[0-9a-f]{12}) -->/g)) ids.add(m[1] as string);
    }
    if (issues.length < 100) break;
  }
  return ids;
}

export async function createGithubIssues(
  payload: AlertPayload,
  target: GithubTarget,
  options: { timeoutMs: number; fetchImpl?: FetchLike },
): Promise<{ created: string[]; existing: string[]; skipped: string[] }> {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(target.repository)) {
    throw new AlertDeliveryError('alerts.github.repository must look like "owner/repo"', undefined, false);
  }
  const api = requireHttpsUrl(target.apiUrl, 'alerts.github.apiUrl', /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?\//.test(target.apiUrl));
  const existing = await existingFindingIds(target, api, options.timeoutMs, options.fetchImpl);
  const created: string[] = [];
  const already: string[] = [];
  const skipped: string[] = [];
  for (const f of payload.findings) {
    if (existing.has(f.id)) {
      already.push(f.id);
      continue;
    }
    if (created.length >= target.maxIssuesPerRun) {
      skipped.push(f.id);
      continue;
    }
    const url = new URL(`${api.pathname.replace(/\/$/, '')}/repos/${target.repository}/issues`, api);
    await sendHttp(
      {
        url: url.toString(),
        headers: headers(target.token),
        body: JSON.stringify({ title: `[ScriptDrift] ${f.severity.toUpperCase()}: ${f.title} (${f.site})`.slice(0, 250), body: issueBody(f, payload), labels: target.labels }),
        timeoutMs: options.timeoutMs,
      },
      options.fetchImpl,
    );
    created.push(f.id);
  }
  return { created, existing: already, skipped };
}
