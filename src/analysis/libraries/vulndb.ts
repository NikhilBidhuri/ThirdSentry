import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import type { Severity } from '../../types/findings.js';
import { compileSafe } from './safe-regex.js';
import { SEED_DB_JSON } from './seed-data.js';
import { parseVersion } from './version.js';

/**
 * Vulnerability database in the retire.js repository format
 * (jsrepository.json, Apache-2.0, https://github.com/RetireJS/retire.js).
 *
 * The file is untrusted input: it is downloaded from the internet by
 * "thirdsentry vulndb update" and read later by the (network-less) analyzer.
 * It is validated with a strict schema, size-limited, and every regex in it
 * goes through safe-regex.ts before it is compiled. Nothing in it is ever
 * executed or evaluated; only regexes (bounded, see safe-regex.ts) and
 * version comparisons are derived from it.
 */

export const DEFAULT_VULNDB_URL = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json';
export const MAX_DB_BYTES = 16 * 1024 * 1024;
export const MAX_LIBRARIES = 2_000;
export const MAX_VULNS_PER_LIBRARY = 1_000;
export const MAX_REGEXES = 2_000;
export const DB_FILE = 'jsrepository.json';
export const DB_META_FILE = 'meta.json';

export const SEVERITIES_ASCENDING = ['low', 'medium', 'high', 'critical'] as const;
const SEV_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const strList = (maxItems: number, maxLen: number) => z.array(z.string().max(maxLen)).max(maxItems);

const VulnerabilitySchema = z.object({
  atOrAbove: z.string().max(40).optional(),
  below: z.string().max(40).optional(),
  severity: z.enum(SEVERITIES_ASCENDING),
  identifiers: z
    .object({
      summary: z.string().max(4_000).optional(),
      CVE: strList(20, 40).optional(),
    })
    .optional(),
  info: strList(50, 2_048).optional(),
});

const ExtractorsSchema = z.object({
  uri: strList(50, 1_000).optional(),
  filename: strList(50, 1_000).optional(),
  filecontent: strList(100, 1_000).optional(),
  /** sha1 of the file content -> version. */
  hashes: z.record(z.string().regex(/^[0-9a-f]{40}$/), z.string().max(40)).optional(),
});

const LibrarySchema = z.object({
  vulnerabilities: z.array(VulnerabilitySchema).max(MAX_VULNS_PER_LIBRARY),
  extractors: ExtractorsSchema.optional(),
});

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export const VulnDbFileSchema = z
  .record(z.string().min(1).max(100), LibrarySchema)
  .refine((db) => Object.keys(db).length <= MAX_LIBRARIES, `more than ${MAX_LIBRARIES} libraries`)
  .refine((db) => Object.keys(db).every((k) => !FORBIDDEN_KEYS.has(k)), 'forbidden library name');

export interface Advisory {
  readonly id: string;
  readonly cves: readonly string[];
  readonly severity: Exclude<Severity, 'info'>;
  readonly atOrAbove?: string;
  readonly below?: string;
  readonly summary: string;
  readonly links: readonly string[];
}

export interface CompiledPattern {
  readonly regex: RegExp;
  /** The pattern is a comment banner (license header) rather than code. */
  readonly banner: boolean;
}

export interface LibraryEntry {
  readonly name: string;
  readonly advisories: readonly Advisory[];
  readonly filecontent: readonly CompiledPattern[];
  readonly filename: readonly RegExp[];
  readonly uri: readonly RegExp[];
  /** sha1 (hex) -> version */
  readonly hashes: ReadonlyMap<string, string>;
}

export interface DbInfo {
  readonly source: 'bundled-seed' | 'cache';
  readonly sourceUrl?: string;
  readonly fetchedAt?: string;
  readonly sha256?: string;
  readonly ageDays?: number;
  readonly libraries: number;
  readonly advisories: number;
  readonly skippedPatterns: number;
  readonly skippedAdvisories: number;
  readonly stale: boolean;
  readonly warnings: readonly string[];
}

export interface LibraryDb {
  readonly libraries: ReadonlyMap<string, LibraryEntry>;
  readonly info: DbInfo;
}

const ALIASES: Readonly<Record<string, string>> = { angular: 'angularjs', jqueryui: 'jquery-ui', 'jquery-ui-dist': 'jquery-ui' };

/** Canonical library name: lower case, ".js" suffix dropped, a few aliases folded. */
export function normalizeLibraryName(name: string): string {
  const n = name.trim().toLowerCase().replace(/\.js$/, '');
  return ALIASES[n] ?? n;
}

const VERSION_FRAGMENT_LAZY = '[0-9][0-9a-z._\\-]{0,30}?';
const VERSION_FRAGMENT_GREEDY = '[0-9][0-9a-z._\\-]{0,30}';

/** Replace retire's version placeholder with a named capture group. */
function expandExtractor(pattern: string, greedy: boolean): string {
  const frag = greedy ? VERSION_FRAGMENT_GREEDY : VERSION_FRAGMENT_LAZY;
  return pattern.replace(/\(§§version§§\)/g, `(?<ver>${frag})`).replace(/§§version§§/g, `(?<ver>${frag})`);
}

function isBannerPattern(p: string): boolean {
  return /^(?:\/\\\*|\/\/|\\\*|\/\*)/.test(p);
}

function advisoryId(cves: readonly string[], summary: string, below: string | undefined, atOrAbove: string | undefined): string {
  const cve = cves.find((c) => /^CVE-\d{4}-\d{4,9}$/.test(c));
  if (cve) return cve;
  return `ADV-${createHash('sha256').update(`${summary}|${atOrAbove ?? ''}|${below ?? ''}`).digest('hex').slice(0, 10)}`;
}

/** Only https links from the database are ever shown to users (they are rendered in reports and alerts). */
function safeLinks(info: readonly string[] | undefined, cves: readonly string[]): string[] {
  const out: string[] = [];
  for (const cve of cves) if (/^CVE-\d{4}-\d{4,9}$/.test(cve)) out.push(`https://nvd.nist.gov/vuln/detail/${cve}`);
  for (const link of info ?? []) {
    try {
      const u = new URL(link);
      if (u.protocol === 'https:' && !u.username && !u.password) out.push(u.toString());
    } catch {
      /* not a URL */
    }
  }
  return [...new Set(out)].slice(0, 6);
}

export interface ParsedDb {
  readonly libraries: Map<string, LibraryEntry>;
  readonly libraryCount: number;
  readonly advisoryCount: number;
  readonly skippedPatterns: number;
  readonly skippedAdvisories: number;
}

/** Validate (throws ZodError on schema violations) and compile a database. */
export function parseVulnDb(raw: unknown): ParsedDb {
  // JSON.parse creates "__proto__" as an ordinary own key; refuse it before any object is built from the data.
  if (typeof raw === 'object' && raw !== null && Object.keys(raw).some((k) => FORBIDDEN_KEYS.has(k))) throw new Error('forbidden library name');
  const data = VulnDbFileSchema.parse(raw);
  const libraries = new Map<string, LibraryEntry>();
  let regexCount = 0;
  let skippedPatterns = 0;
  let skippedAdvisories = 0;
  let advisoryCount = 0;
  const compile = (source: string, greedy: boolean): RegExp | undefined => {
    if (regexCount >= MAX_REGEXES) {
      skippedPatterns++;
      return undefined;
    }
    const c = compileSafe(expandExtractor(source, greedy));
    if ('error' in c) {
      skippedPatterns++;
      return undefined;
    }
    regexCount++;
    return c.regex;
  };
  for (const [key, lib] of Object.entries(data)) {
    if (key === 'retire-example') continue;
    const name = normalizeLibraryName(key);
    const advisories: Advisory[] = [];
    for (const v of lib.vulnerabilities) {
      const parsableBelow = v.below === undefined || parseVersion(v.below) !== undefined;
      const parsableAbove = v.atOrAbove === undefined || parseVersion(v.atOrAbove) !== undefined;
      if ((v.below === undefined && v.atOrAbove === undefined) || !parsableBelow || !parsableAbove) {
        skippedAdvisories++;
        continue;
      }
      const cves = v.identifiers?.CVE ?? [];
      const summary = (v.identifiers?.summary ?? '').replace(/\s+/g, ' ').trim().slice(0, 300);
      advisories.push({
        id: advisoryId(cves, summary, v.below, v.atOrAbove),
        cves: cves.filter((c) => /^CVE-\d{4}-\d{4,9}$/.test(c)),
        severity: v.severity,
        ...(v.atOrAbove !== undefined ? { atOrAbove: v.atOrAbove } : {}),
        ...(v.below !== undefined ? { below: v.below } : {}),
        summary,
        links: safeLinks(v.info, cves),
      });
    }
    advisoryCount += advisories.length;
    const x = lib.extractors;
    const filecontent: CompiledPattern[] = [];
    for (const p of x?.filecontent ?? []) {
      const regex = compile(p, true);
      if (regex) filecontent.push({ regex, banner: isBannerPattern(p) });
    }
    const filename = (x?.filename ?? []).map((p) => compile(p, false)).filter((r): r is RegExp => r !== undefined);
    const uri = (x?.uri ?? []).map((p) => compile(p, false)).filter((r): r is RegExp => r !== undefined);
    const existing = libraries.get(name);
    if (existing) {
      // Two upstream keys folding to one name: merge.
      libraries.set(name, {
        name,
        advisories: [...existing.advisories, ...advisories],
        filecontent: [...existing.filecontent, ...filecontent],
        filename: [...existing.filename, ...filename],
        uri: [...existing.uri, ...uri],
        hashes: new Map([...existing.hashes, ...Object.entries(x?.hashes ?? {})]),
      });
    } else {
      libraries.set(name, { name, advisories, filecontent, filename, uri, hashes: new Map(Object.entries(x?.hashes ?? {})) });
    }
  }
  return { libraries, libraryCount: libraries.size, advisoryCount, skippedPatterns, skippedAdvisories };
}

export interface DbMeta {
  readonly sourceUrl: string;
  readonly fetchedAt: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly libraries: number;
  readonly advisories: number;
}

export function vulnDbDir(cacheDir: string): string {
  return join(cacheDir, 'vulndb');
}

export function ageInDays(fetchedAt: string, now: Date): number | undefined {
  const t = Date.parse(fetchedAt);
  return Number.isNaN(t) ? undefined : Math.max(0, Math.floor((now.getTime() - t) / 86_400_000));
}

function seedDb(extraWarnings: readonly string[]): LibraryDb {
  const parsed = parseVulnDb(SEED_DB_JSON);
  return {
    libraries: parsed.libraries,
    info: {
      source: 'bundled-seed',
      libraries: parsed.libraryCount,
      advisories: parsed.advisoryCount,
      skippedPatterns: parsed.skippedPatterns,
      skippedAdvisories: parsed.skippedAdvisories,
      stale: false,
      warnings: [
        'Using the small bundled seed vulnerability database. Run "thirdsentry vulndb update" for the full, current retire.js database.',
        ...extraWarnings,
      ],
    },
  };
}

export interface LoadDbOptions {
  readonly now?: Date;
  /** Warn when the cached database is older than this many days. */
  readonly maxAgeDays?: number;
}

/**
 * Load the cached database if present and valid, otherwise the bundled seed.
 * Never throws and never uses the network: a damaged cache falls back to the
 * seed with a warning.
 */
export async function loadLibraryDb(cacheDir: string, options: LoadDbOptions = {}): Promise<LibraryDb> {
  const now = options.now ?? new Date();
  const dir = vulnDbDir(cacheDir);
  const dbPath = join(dir, DB_FILE);
  let metaText: string;
  try {
    const s = await stat(dbPath);
    if (!s.isFile()) return seedDb([]);
    if (s.size > MAX_DB_BYTES) return seedDb([`The cached vulnerability database is larger than ${MAX_DB_BYTES} bytes and was ignored.`]);
    metaText = await readFile(join(dir, DB_META_FILE), 'utf8').catch(() => '');
  } catch {
    return seedDb([]);
  }
  try {
    const body = await readFile(dbPath);
    const sha256 = createHash('sha256').update(body).digest('hex');
    let meta: Partial<DbMeta> = {};
    try {
      meta = metaText ? (JSON.parse(metaText) as Partial<DbMeta>) : {};
    } catch {
      meta = {};
    }
    const warnings: string[] = [];
    if (meta.sha256 && meta.sha256 !== sha256) {
      return seedDb(['The cached vulnerability database does not match its recorded SHA-256 (corrupted or edited) and was ignored. Run "thirdsentry vulndb update".']);
    }
    if (!meta.sha256) warnings.push('The cached vulnerability database has no metadata; its age is unknown.');
    const parsed = parseVulnDb(JSON.parse(body.toString('utf8')) as unknown);
    const ageDays = meta.fetchedAt ? ageInDays(meta.fetchedAt, now) : undefined;
    const maxAge = options.maxAgeDays;
    const stale = maxAge !== undefined && ageDays !== undefined && ageDays > maxAge;
    if (stale) warnings.push(`The vulnerability database is ${ageDays} days old (limit ${maxAge}). Run "thirdsentry vulndb update" so new advisories are not missed.`);
    if (parsed.skippedPatterns > 0) warnings.push(`${parsed.skippedPatterns} detection pattern(s) from the database were skipped (unsafe, invalid or over the limit).`);
    return {
      libraries: parsed.libraries,
      info: {
        source: 'cache',
        ...(meta.sourceUrl ? { sourceUrl: meta.sourceUrl } : {}),
        ...(meta.fetchedAt ? { fetchedAt: meta.fetchedAt } : {}),
        sha256,
        ...(ageDays !== undefined ? { ageDays } : {}),
        libraries: parsed.libraryCount,
        advisories: parsed.advisoryCount,
        skippedPatterns: parsed.skippedPatterns,
        skippedAdvisories: parsed.skippedAdvisories,
        stale,
        warnings,
      },
    };
  } catch (error) {
    return seedDb([`The cached vulnerability database is invalid (${error instanceof Error ? error.message.slice(0, 160) : 'unreadable'}) and was ignored.`]);
  }
}

export function severityRank(s: Severity): number {
  return SEV_RANK[s] ?? 0;
}
