import { join, resolve, sep } from 'node:path';
import { ThirdSentryError } from '../utils/errors.js';
import { ExitCode } from '../utils/exit-codes.js';

/**
 * Layout of the ThirdSentry storage directory (default `.thirdsentry/`).
 *
 *   baselines/<site>/baseline.json                    approved baseline (commit to Git)
 *   reports/scans/<scan-id>.json                      scan results (do not commit by default)
 *   reports/scans/<scan-id>/report.{json,sarif,html}  reports generated for that scan
 *   reports/latest-scan.json                          atomically updated copy of the most recent scan
 *   reports/report.{json,sarif,html}                  atomically updated copies of the latest reports
 *   state/                                            finding/alert state and the storage lock
 *   cache/content/<sha256>                            retained script bodies (retention.scriptContent)
 *   evidence/                                         transient worker hand-off files
 *
 * Every path built from data (site names, scan IDs) is checked to stay inside
 * the storage directory: scan results and evidence may be crafted.
 */
export interface StoragePaths {
  readonly root: string;
  readonly baselines: string;
  readonly reports: string;
  readonly scans: string;
  readonly latestScan: string;
  readonly state: string;
  readonly lock: string;
  readonly cache: string;
  readonly content: string;
  readonly evidence: string;
}

export function storagePaths(root: string): StoragePaths {
  const reports = join(root, 'reports');
  const cache = join(root, 'cache');
  const state = join(root, 'state');
  return {
    root,
    baselines: join(root, 'baselines'),
    reports,
    scans: join(reports, 'scans'),
    latestScan: join(reports, 'latest-scan.json'),
    state,
    lock: join(state, 'thirdsentry.lock'),
    cache,
    content: join(cache, 'content'),
    evidence: join(root, 'evidence'),
  };
}

/** Throw unless `target` resolves to `root` itself or a path below it. Returns the resolved target. */
export function assertInside(root: string, target: string): string {
  const r = resolve(root);
  const t = resolve(target);
  if (t !== r && !t.startsWith(r.endsWith(sep) ? r : r + sep)) {
    throw new ThirdSentryError(`Refusing to access a path outside the storage directory: ${t}`, { exitCode: ExitCode.ConfigError });
  }
  return t;
}

/** Same rule as site names in thirdsentry.yml. */
const SITE_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const SCAN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function assertSiteName(site: string): string {
  if (!SITE_NAME.test(site) || site.includes('..')) {
    throw new ThirdSentryError(`Invalid site name ${JSON.stringify(site)}`, {
      exitCode: ExitCode.ConfigError,
      hint: 'Site names may only contain letters, digits, ".", "_" and "-".',
    });
  }
  return site;
}

export function assertScanId(scanId: string): string {
  if (!SCAN_ID.test(scanId) || scanId.includes('..')) throw new ThirdSentryError(`Invalid scan id: ${JSON.stringify(scanId)}`, { exitCode: ExitCode.ConfigError });
  return scanId;
}

export function baselinePath(paths: StoragePaths, site: string): string {
  return assertInside(paths.baselines, join(paths.baselines, assertSiteName(site), 'baseline.json'));
}

export function scanResultPath(paths: StoragePaths, scanId: string): string {
  return assertInside(paths.scans, join(paths.scans, `${assertScanId(scanId)}.json`));
}

/** Directory holding the reports generated for one scan. */
export function scanReportDir(paths: StoragePaths, scanId: string): string {
  return assertInside(paths.scans, join(paths.scans, assertScanId(scanId)));
}
