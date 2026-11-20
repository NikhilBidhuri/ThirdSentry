import { BASELINE_SCHEMA_VERSION } from '../baseline/baseline-schema.js';
import { ThirdSentryError } from '../utils/errors.js';
import { ExitCode } from '../utils/exit-codes.js';

/**
 * Schema versioning for persisted files (baselines, scan results).
 *
 * Policy (see docs/baselines.md#file-format-versions):
 *  - Every persisted file carries an integer `schemaVersion`.
 *  - A file written by an OLDER version is upgraded in memory, one version at
 *    a time, by the migrations registered here, and then validated against
 *    the current schema. It is written back in the current format only when
 *    the file is saved again for another reason (e.g. the next approval).
 *  - A file written by a NEWER version is refused with a clear "upgrade
 *    ThirdSentry" error; it is never guessed at, rewritten or downgraded.
 *  - Bumping a schema version requires registering a migration from the
 *    previous version and a test that reads a file in the old format.
 */

export type Migration = (data: Record<string, unknown>) => Record<string, unknown>;

export interface MigrationRegistry {
  /** Human-readable name of the file type ("baseline", "scan result"). */
  readonly name: string;
  /** Schema version written by this ThirdSentry version. */
  readonly current: number;
  /** migrations[n] upgrades a version-n document to version n+1. */
  readonly migrations: Readonly<Record<number, Migration>>;
}

export class SchemaVersionError extends ThirdSentryError {
  constructor(message: string, hint?: string) {
    super(message, { exitCode: ExitCode.ConfigError, ...(hint ? { hint } : {}) });
  }
}

/**
 * Upgrade `data` to `registry.current`. Returns the input unchanged when it is
 * already current; throws SchemaVersionError for newer or unknown versions.
 */
export function upgradeDocument(registry: MigrationRegistry, data: unknown, source: string): unknown {
  if (data === null || typeof data !== 'object' || Array.isArray(data)) return data; // schema validation reports this
  let doc = data as Record<string, unknown>;
  const version = doc.schemaVersion;
  if (typeof version !== 'number' || !Number.isInteger(version) || version < 1) return data; // let schema validation report it
  if (version > registry.current) {
    throw new SchemaVersionError(
      `${source} is a ${registry.name} in format version ${version}, but this ThirdSentry version only understands up to version ${registry.current}`,
      'It was written by a newer ThirdSentry. Upgrade ThirdSentry (npm install thirdsentry@latest) instead of editing the file.',
    );
  }
  for (let v = version; v < registry.current; v++) {
    const migrate = registry.migrations[v];
    if (!migrate) {
      throw new SchemaVersionError(`${source} is a ${registry.name} in format version ${version}, which cannot be upgraded (no migration from version ${v})`);
    }
    doc = { ...migrate(doc), schemaVersion: v + 1 };
  }
  return doc;
}

/** Baselines: version 1 is the first released format. */
export const BASELINE_MIGRATIONS: MigrationRegistry = { name: 'baseline', current: BASELINE_SCHEMA_VERSION, migrations: {} };

/** Scan results: version 1 is the first released format. */
export const SCAN_RESULT_MIGRATIONS: MigrationRegistry = { name: 'scan result', current: 1, migrations: {} };
