import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { CollectRequest } from '../browser/collector.js';
import { PART_FILES, type ScanFooter, type ScanHeader, type SiteStart, type SiteSummary } from '../browser/evidence-sink.js';
import {
  IssueSchema,
  PageEvidenceSchema,
  ScanEvidenceSchema,
  SiteEvidenceSchema,
  type Issue,
  type PageEvidence,
  type ScanEvidence,
  type SiteEvidence,
} from '../types/evidence.js';
import { z } from 'zod';
import { EvidenceValidationError } from '../utils/errors.js';
import { readJsonFile } from '../utils/fs.js';

/**
 * Trusted-side assembly of the incremental evidence parts written by the
 * browser worker (see src/browser/evidence-sink.ts). Every part is validated
 * on its own, so one corrupt or oversized part costs only that page. When the
 * worker died or timed out, completed sites/pages are kept and the missing
 * ones are marked failed with an explicit issue.
 */

const HeaderSchema = ScanEvidenceSchema.omit({ sites: true, finishedAt: true });
const FooterSchema = z.object({ finishedAt: z.string().max(64), issues: z.array(IssueSchema).max(1_000) });
const StartSchema = SiteEvidenceSchema.pick({ name: true, url: true, profile: true, browserName: true, emulation: true, startedAt: true });
const SummarySchema = SiteEvidenceSchema.omit({ pages: true });

export interface AssembleOptions {
  readonly maxBytes: number;
  /** Why the worker did not finish (undefined when it exited normally). */
  readonly failure?: string;
}

function failedPage(page: CollectRequest['sites'][number]['pages'][number], code: string, message: string): PageEvidence {
  const now = new Date().toISOString();
  return {
    pageKey: page.key,
    pageUrl: page.url,
    sensitive: page.sensitive,
    status: 'failed',
    issues: [{ level: 'error', code, message }],
    startedAt: now,
    finishedAt: now,
    documentHeaders: {},
    cspHeaders: [],
    cspReportOnlyHeaders: [],
    frames: [],
    scriptResponses: [],
    domScripts: [],
    blobs: [],
    workers: [],
    requests: [],
    requestsDropped: 0,
    scriptsDropped: 0,
    consoleErrors: [],
    pageErrors: [],
  };
}

async function readPart<T>(dir: string, name: string, schema: z.ZodType<T>, maxBytes: number): Promise<T | undefined> {
  let raw: unknown;
  try {
    raw = await readJsonFile(join(dir, name), maxBytes);
  } catch {
    return undefined;
  }
  const parsed = schema.safeParse(raw);
  return parsed.success ? parsed.data : undefined;
}

export async function assembleEvidence(dir: string, request: CollectRequest, options: AssembleOptions): Promise<ScanEvidence> {
  const names = new Set(await readdir(dir).catch(() => [] as string[]));
  const header: ScanHeader | undefined = names.has(PART_FILES.header)
    ? await readPart(dir, PART_FILES.header, HeaderSchema, options.maxBytes)
    : undefined;
  const footer: ScanFooter | undefined = names.has(PART_FILES.footer)
    ? await readPart(dir, PART_FILES.footer, FooterSchema, options.maxBytes)
    : undefined;
  if (!header) {
    throw new EvidenceValidationError(
      `Browser worker produced no evidence${options.failure ? ` (${options.failure})` : ''}: scan header missing or invalid`,
    );
  }

  const scanIssues: Issue[] = [...header.issues, ...(footer?.issues ?? [])];
  if (!footer) {
    scanIssues.push({
      level: 'error',
      code: 'worker-incomplete',
      message: `Browser worker did not finish${options.failure ? `: ${options.failure}` : ''}; evidence of completed pages was kept, remaining pages are marked failed`,
    });
  }

  let remaining = options.maxBytes;
  const sites: SiteEvidence[] = [];
  for (const [siteIndex, reqSite] of request.sites.entries()) {
    const start: SiteStart | undefined = names.has(PART_FILES.siteStart(siteIndex))
      ? await readPart(dir, PART_FILES.siteStart(siteIndex), StartSchema, options.maxBytes)
      : undefined;
    const summary: SiteSummary | undefined = names.has(PART_FILES.site(siteIndex))
      ? await readPart(dir, PART_FILES.site(siteIndex), SummarySchema, options.maxBytes)
      : undefined;
    const pages: PageEvidence[] = [];
    const siteIssues: Issue[] = [...(summary?.issues ?? [])];
    for (const [pageIndex, reqPage] of reqSite.pages.entries()) {
      const file = PART_FILES.page(siteIndex, pageIndex);
      let page: PageEvidence | undefined;
      if (names.has(file) && remaining > 0) {
        page = await readPart(dir, file, PageEvidenceSchema, Math.min(options.maxBytes, remaining));
        if (page) remaining -= JSON.stringify(page).length;
        else siteIssues.push({ level: 'error', code: 'page-evidence-invalid', message: `Evidence of page ${reqPage.key} was unreadable, oversized or invalid and was discarded` });
      }
      if (!page) {
        const inFlight = !summary && start !== undefined && !pages.some((p) => p.issues[0]?.code === 'worker-died-during-page' || p.issues[0]?.code === 'page-not-scanned');
        page = failedPage(
          reqPage,
          inFlight ? 'worker-died-during-page' : 'page-not-scanned',
          inFlight
            ? `Browser worker ended while scanning this page${options.failure ? ` (${options.failure})` : ''}; evidence for it was lost`
            : 'Page evidence is missing (worker did not reach it or its evidence was discarded)',
        );
      }
      pages.push(page);
    }
    const now = new Date().toISOString();
    if (!summary) {
      siteIssues.push({ level: 'error', code: 'site-incomplete', message: 'Site scan did not finish; completed pages were kept' });
    }
    sites.push({
      name: summary?.name ?? start?.name ?? reqSite.name,
      url: summary?.url ?? start?.url ?? reqSite.url,
      profile: summary?.profile ?? start?.profile ?? reqSite.profile,
      browserName: summary?.browserName ?? start?.browserName ?? 'unknown',
      browserVersion: summary?.browserVersion ?? 'unknown',
      emulation: summary?.emulation ?? start?.emulation ?? '',
      status: summary ? summary.status : pages.some((p) => p.status !== 'failed') ? 'partial' : 'failed',
      issues: siteIssues,
      startedAt: summary?.startedAt ?? start?.startedAt ?? now,
      finishedAt: summary?.finishedAt ?? now,
      pages,
      proxyEvents: summary?.proxyEvents ?? [],
      proxyEventsDropped: summary?.proxyEventsDropped ?? 0,
    });
  }
  return {
    ...header,
    finishedAt: footer?.finishedAt ?? new Date().toISOString(),
    issues: scanIssues,
    sites,
  };
}
