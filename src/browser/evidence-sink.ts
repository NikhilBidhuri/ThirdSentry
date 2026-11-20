import { once } from 'node:events';
import { createWriteStream } from 'node:fs';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { Issue, PageEvidence, ScanEvidence, SiteEvidence } from '../types/evidence.js';

/**
 * Incremental evidence output.
 *
 * The browser worker used to build the evidence of the whole scan in memory
 * and serialise it once at the end, so a crash or timeout on the last page
 * lost everything. Evidence is now emitted as it is produced: one part per
 * completed page plus small site/scan records. The process-mode worker
 * writes the parts to its output directory (DirectorySink) and the trusted
 * coordinator assembles whatever was completed (src/security/evidence-assembly.ts).
 * In-process collection uses MemorySink and produces the usual ScanEvidence.
 *
 * Part files (all JSON, written atomically via rename):
 *   scan.json                       scan header (no sites)
 *   site-0000.start.json            site metadata when the site starts
 *   site-0000.page-0000.json        one PageEvidence per page, in page order
 *   site-0000.json                  site summary (SiteEvidence without pages)
 *   scan.end.json                   footer when the collection finished normally
 */

export type ScanHeader = Omit<ScanEvidence, 'sites' | 'finishedAt'>;
export type SiteStart = Pick<SiteEvidence, 'name' | 'url' | 'profile' | 'browserName' | 'emulation' | 'startedAt'>;
export type SiteSummary = Omit<SiteEvidence, 'pages'>;
export interface ScanFooter {
  readonly finishedAt: string;
  readonly issues: Issue[];
}

export interface EvidenceSink {
  begin(header: ScanHeader): Promise<void>;
  siteStarted(siteIndex: number, start: SiteStart): Promise<void>;
  page(siteIndex: number, pageIndex: number, page: PageEvidence): Promise<void>;
  siteFinished(siteIndex: number, site: SiteSummary): Promise<void>;
  end(footer: ScanFooter): Promise<void>;
}

const pad = (n: number): string => String(n).padStart(4, '0');

export const PART_FILES = {
  header: 'scan.json',
  footer: 'scan.end.json',
  siteStart: (site: number): string => `site-${pad(site)}.start.json`,
  page: (site: number, page: number): string => `site-${pad(site)}.page-${pad(page)}.json`,
  site: (site: number): string => `site-${pad(site)}.json`,
} as const;

/** Writes each part as its own file so completed work survives a crash. */
export class DirectorySink implements EvidenceSink {
  private readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
  }

  private async write(name: string, value: unknown): Promise<void> {
    await mkdir(this.dir, { recursive: true });
    const target = join(this.dir, name);
    const tmp = `${target}.${randomBytes(6).toString('hex')}.tmp`;
    await writeFile(tmp, JSON.stringify(value));
    await rename(tmp, target);
  }

  begin(header: ScanHeader): Promise<void> {
    return this.write(PART_FILES.header, header);
  }

  siteStarted(siteIndex: number, start: SiteStart): Promise<void> {
    return this.write(PART_FILES.siteStart(siteIndex), start);
  }

  page(siteIndex: number, pageIndex: number, page: PageEvidence): Promise<void> {
    return this.write(PART_FILES.page(siteIndex, pageIndex), page);
  }

  siteFinished(siteIndex: number, site: SiteSummary): Promise<void> {
    return this.write(PART_FILES.site(siteIndex), site);
  }

  end(footer: ScanFooter): Promise<void> {
    return this.write(PART_FILES.footer, footer);
  }
}

/** Collects the parts in memory and produces a regular ScanEvidence. */
export class MemorySink implements EvidenceSink {
  private header: ScanHeader | undefined;
  private footer: ScanFooter | undefined;
  private readonly sites = new Map<number, { summary?: SiteSummary; pages: PageEvidence[] }>();

  begin(header: ScanHeader): Promise<void> {
    this.header = header;
    return Promise.resolve();
  }

  siteStarted(siteIndex: number): Promise<void> {
    this.sites.set(siteIndex, { pages: [] });
    return Promise.resolve();
  }

  page(siteIndex: number, _pageIndex: number, page: PageEvidence): Promise<void> {
    const site = this.sites.get(siteIndex) ?? { pages: [] };
    site.pages.push(page);
    this.sites.set(siteIndex, site);
    return Promise.resolve();
  }

  siteFinished(siteIndex: number, summary: SiteSummary): Promise<void> {
    const site = this.sites.get(siteIndex) ?? { pages: [] };
    site.summary = summary;
    this.sites.set(siteIndex, site);
    return Promise.resolve();
  }

  end(footer: ScanFooter): Promise<void> {
    this.footer = footer;
    return Promise.resolve();
  }

  result(): ScanEvidence {
    if (!this.header || !this.footer) throw new Error('evidence collection did not finish');
    const sites: SiteEvidence[] = [...this.sites.entries()]
      .sort(([a], [b]) => a - b)
      .flatMap(([, s]) => (s.summary ? [{ ...s.summary, pages: s.pages }] : []));
    return { ...this.header, finishedAt: this.footer.finishedAt, issues: this.footer.issues, sites };
  }
}

/**
 * Write a ScanEvidence as the regular single-file JSON format consumed by
 * `analyze`, serialising one page at a time instead of building one string
 * for the whole scan (which can exceed V8's string limit).
 */
export async function writeEvidenceJson(path: string, evidence: ScanEvidence): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  const out = createWriteStream(tmp);
  const put = async (chunk: string): Promise<void> => {
    if (!out.write(chunk)) await once(out, 'drain');
  };
  try {
    const { sites, ...rest } = evidence;
    const head = JSON.stringify(rest);
    await put(`${head.slice(0, -1)}${head.length > 2 ? ',' : ''}"sites":[`);
    for (const [i, site] of sites.entries()) {
      const { pages, ...siteRest } = site;
      const siteHead = JSON.stringify(siteRest);
      await put(`${i > 0 ? ',' : ''}${siteHead.slice(0, -1)}${siteHead.length > 2 ? ',' : ''}"pages":[`);
      for (const [j, page] of pages.entries()) await put(`${j > 0 ? ',' : ''}${JSON.stringify(page)}`);
      await put(']}');
    }
    await put(']}');
    out.end();
    await once(out, 'finish');
  } catch (error) {
    out.destroy();
    throw error;
  }
  await rename(tmp, path);
}
