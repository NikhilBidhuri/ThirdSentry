import type { Severity } from '../../types/findings.js';
import type { DetectedLibrary } from '../../types/index.js';
import { normalizeLibraryName, severityRank, type Advisory, type LibraryDb } from './vulndb.js';
import { compareVersions, inVulnerableRange } from './version.js';

export interface LibraryVulnerability {
  readonly library: DetectedLibrary;
  /** Advisories that affect the detected version, most severe first. */
  readonly advisories: readonly Advisory[];
  /** Lowest version that fixes every matched advisory (best effort: the highest "below" bound). */
  readonly fixedIn?: string;
  readonly highestSeverity: Exclude<Severity, 'info'>;
}

export function matchAdvisories(library: DetectedLibrary, db: LibraryDb, minSeverity: Severity = 'low'): Advisory[] {
  const entry = db.libraries.get(normalizeLibraryName(library.name));
  if (!entry) return [];
  const seen = new Set<string>();
  const out: Advisory[] = [];
  for (const a of entry.advisories) {
    if (severityRank(a.severity) < severityRank(minSeverity)) continue;
    if (!inVulnerableRange(library.version, { atOrAbove: a.atOrAbove, below: a.below })) continue;
    if (seen.has(a.id)) continue;
    seen.add(a.id);
    out.push(a);
  }
  return out.sort((x, y) => severityRank(y.severity) - severityRank(x.severity) || x.id.localeCompare(y.id));
}

export function findVulnerabilities(libraries: readonly DetectedLibrary[], db: LibraryDb, minSeverity: Severity = 'low'): LibraryVulnerability[] {
  const out: LibraryVulnerability[] = [];
  for (const library of libraries) {
    const advisories = matchAdvisories(library, db, minSeverity);
    if (advisories.length === 0) continue;
    let fixedIn: string | undefined;
    for (const a of advisories) {
      if (a.below && (fixedIn === undefined || (compareVersions(a.below, fixedIn) ?? 0) > 0)) fixedIn = a.below;
    }
    out.push({ library, advisories, ...(fixedIn ? { fixedIn } : {}), highestSeverity: (advisories[0] as Advisory).severity });
  }
  return out;
}
