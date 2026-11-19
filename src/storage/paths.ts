import { join } from 'node:path';

/**
 * Layout of the ThirdSentry storage directory (default `.thirdsentry/`).
 *
 *   baselines/<site>/baseline.json   approved baseline (commit to Git)
 *   reports/scans/<scan-id>.json     scan results (do not commit by default)
 *   reports/latest-scan.json         copy of the most recent scan
 *   reports/report.{json,sarif,html} latest analysis reports
 *   state/                           dedup/alert state
 *   cache/content/<sha256>           optional retained script bodies
 *   evidence/                        transient worker hand-off files
 */
export interface StoragePaths {
  readonly root: string;
  readonly baselines: string;
  readonly reports: string;
  readonly scans: string;
  readonly latestScan: string;
  readonly state: string;
  readonly cache: string;
  readonly content: string;
  readonly evidence: string;
}

export function storagePaths(root: string): StoragePaths {
  const reports = join(root, 'reports');
  const cache = join(root, 'cache');
  return {
    root,
    baselines: join(root, 'baselines'),
    reports,
    scans: join(reports, 'scans'),
    latestScan: join(reports, 'latest-scan.json'),
    state: join(root, 'state'),
    cache,
    content: join(cache, 'content'),
    evidence: join(root, 'evidence'),
  };
}

export function baselinePath(paths: StoragePaths, site: string): string {
  return join(paths.baselines, site, 'baseline.json');
}
