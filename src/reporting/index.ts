import { isAbsolute, join, resolve } from 'node:path';
import type { ResolvedConfig } from '../config/loader.js';
import type { ScanResult } from '../types/index.js';
import type { AnalysisReport } from '../types/report.js';
import { ConfigError } from '../utils/errors.js';
import { stableStringify, writeFileAtomic } from '../utils/fs.js';
import { renderHtmlReport } from './html-reporter.js';
import { renderJsonReport } from './json-reporter.js';
import { buildSarif } from './sarif-reporter.js';

export const REPORT_FORMATS = ['json', 'sarif', 'html'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export function parseFormats(value: string | undefined, fallback: readonly ReportFormat[]): ReportFormat[] {
  if (!value) return [...fallback];
  const formats = value.split(',').map((f) => f.trim().toLowerCase()).filter(Boolean);
  const bad = formats.filter((f) => !(REPORT_FORMATS as readonly string[]).includes(f));
  if (bad.length) throw new ConfigError(`Unknown report format(s): ${bad.join(', ')}`, `Use one or more of: ${REPORT_FORMATS.join(', ')}`);
  return [...new Set(formats)] as ReportFormat[];
}

export interface WrittenReports {
  readonly json?: string;
  readonly sarif?: string;
  readonly html?: string;
}

/** Write the requested report formats to `outputDir` (default: .thirdsentry/reports). */
export async function writeReports(
  resolved: ResolvedConfig,
  report: AnalysisReport,
  scan: ScanResult | undefined,
  formats: readonly ReportFormat[],
  outputDir?: string,
): Promise<WrittenReports> {
  const dir = outputDir ? (isAbsolute(outputDir) ? outputDir : resolve(process.cwd(), outputDir)) : resolved.paths.reports;
  const out: { json?: string; sarif?: string; html?: string } = {};
  for (const format of formats) {
    switch (format) {
      case 'json': {
        const path = join(dir, 'report.json');
        await writeFileAtomic(path, renderJsonReport(report));
        out.json = path;
        break;
      }
      case 'sarif': {
        const path = join(dir, 'report.sarif');
        const sarif = await buildSarif(report, { configPath: resolved.configPath, baseDir: resolved.baseDir });
        await writeFileAtomic(path, stableStringify(sarif));
        out.sarif = path;
        break;
      }
      case 'html': {
        const path = join(dir, 'report.html');
        await writeFileAtomic(path, renderHtmlReport(report, scan));
        out.html = path;
        break;
      }
    }
  }
  return out;
}
