import { createHash } from 'node:crypto';
import type { DetectedLibrary, LibraryDetectionMethod } from '../../types/index.js';
import { execCapped, MAX_INPUT_CHARS } from './safe-regex.js';
import { normalizeLibraryName, type LibraryDb } from './vulndb.js';
import { parseVersion } from './version.js';

/**
 * Library detection. Pure, offline and deterministic: the same URL, content
 * and database always give the same result. Four sources, strongest first:
 *
 *  - content-hash  exact SHA-256 match against configured `libraries.knownHashes`
 *                  (or SHA-1 match against hashes in the vulnerability database)
 *  - banner        license/banner comments ("/*! jQuery v3.5.1 | ...")
 *  - code          well-known version assignments (jquery:"3.5.1", VERSION = '4.17.20')
 *  - url           version in the URL or file name (/jquery-3.5.1.min.js, /lodash@4.17.20/,
 *                  cdnjs/jsdelivr/unpkg/Google paths)
 *
 * Patterns shipped here are written to be linear-time (bounded repeats, no
 * nested quantifiers). Patterns from the vulnerability database go through
 * safe-regex.ts. Content patterns only look at the first MAX_INPUT_CHARS.
 */

export interface KnownHash {
  readonly sha256: string;
  readonly name: string;
  readonly version: string;
}

export interface DetectInput {
  readonly url?: string | undefined;
  readonly body?: Buffer | string | undefined;
  readonly db?: LibraryDb | undefined;
  readonly knownHashes?: readonly KnownHash[] | undefined;
}

const MAX_DETECTIONS = 20;
const V = '(\\d{1,4}\\.\\d{1,4}(?:\\.\\d{1,4}){0,2}(?:-[0-9A-Za-z.]{1,20})?)';

interface BuiltinPattern {
  readonly name: string;
  readonly method: 'banner' | 'code';
  readonly regex: RegExp;
  /** Only applied when the content also contains this marker (disambiguates generic assignments). */
  readonly requires?: string;
}

const BUILTIN: readonly BuiltinPattern[] = [
  { name: 'jquery', method: 'banner', regex: new RegExp(`/\\*[!*]?\\s{0,4}\\*?\\s{0,4}jQuery (?:JavaScript Library )?v${V}`) },
  { name: 'jquery', method: 'code', regex: new RegExp(`[^a-z.]jquery:\\s?["']${V}["']`) },
  { name: 'jquery', method: 'code', regex: new RegExp(`\\.fn\\.jquery\\s?=\\s?["']${V}["']`) },
  { name: 'jquery-ui', method: 'banner', regex: new RegExp(`/\\*!?[\\s*]{1,8}jQuery UI(?: -)? v?${V}`) },
  { name: 'jquery-ui', method: 'code', regex: new RegExp(`\\$?\\.ui\\.version\\s?=\\s?["']${V}["']`) },
  { name: 'bootstrap', method: 'banner', regex: new RegExp(`/\\*!?[\\s*]{1,8}Bootstrap v${V}`) },
  { name: 'bootstrap', method: 'code', regex: new RegExp(`VERSION\\s?=\\s?["']${V}["']`), requires: 'bootstrap' },
  { name: 'lodash', method: 'banner', regex: new RegExp(`/\\*[\\s*!@a-z]{0,40}(?:Lo-Dash|lodash|Lodash) v?${V}`) },
  { name: 'lodash', method: 'code', regex: new RegExp(`VERSION\\s?=\\s?["']${V}["']`), requires: '__lodash_hash_undefined__' },
  { name: 'moment', method: 'banner', regex: new RegExp(`//!? moment\\.js\\s{1,4}//!? version : ${V}`) },
  { name: 'moment', method: 'code', regex: new RegExp(`\\.version\\s?=\\s?["']${V}["']`), requires: 'isMoment' },
  { name: 'angularjs', method: 'banner', regex: new RegExp(`/\\*[*\\s]{1,8}(?:@license )?AngularJS(?: NES)? v${V}`) },
  { name: 'angularjs', method: 'code', regex: new RegExp(`errors\\.angularjs\\.org/${V}/`) },
  { name: 'handlebars', method: 'banner', regex: new RegExp(`/\\*+![\\s]{1,8}(?:@license)?[\\s]{0,8}handlebars v+${V}`) },
  { name: 'handlebars', method: 'code', regex: new RegExp(`Handlebars\\.VERSION\\s?=\\s?["']${V}["']`) },
  { name: 'handlebars', method: 'code', regex: new RegExp(`Handlebars=\\{VERSION:["']${V}["']`) },
  { name: 'dompurify', method: 'banner', regex: new RegExp(`/\\*! @license DOMPurify ${V}`) },
  { name: 'dompurify', method: 'code', regex: new RegExp(`DOMPurify\\.version\\s?=\\s?["']${V}["']`) },
  { name: 'underscore', method: 'banner', regex: new RegExp(`//\\s{1,4}Underscore\\.js ${V}|/\\*[\\s!]{1,8}Underscore\\.js ${V}`) },
];

/** Names recognised in file names and directory-style URLs without a CDN marker. */
const KNOWN_URL_NAMES: ReadonlySet<string> = new Set([
  'jquery',
  'jquery-ui',
  'bootstrap',
  'lodash',
  'moment',
  'angularjs',
  'handlebars',
  'dompurify',
  'underscore',
  'react',
  'react-dom',
  'vue',
  'axios',
  'backbone',
  'd3',
  'chart',
  'select2',
  'popper',
]);

const CONFIDENCE: Record<LibraryDetectionMethod, DetectedLibrary['confidence']> = { 'content-hash': 'high', banner: 'high', code: 'medium', url: 'medium' };
const RANK: Record<LibraryDetectionMethod, number> = { 'content-hash': 4, banner: 3, code: 2, url: 1 };
const GENERIC_BAD_NAMES = new Set(['v', 'version', 'license', 'licence', 'copyright', 'build', 'release', 'the', 'and', 'for', 'by', 'a', 'an']);

const NAME_RE = /^@?[a-z0-9][a-z0-9._/-]{0,80}$/;

function isKnownName(name: string, db: LibraryDb | undefined): boolean {
  return KNOWN_URL_NAMES.has(name) || (db?.libraries.has(name) ?? false);
}

function clean(version: string | undefined): string | undefined {
  if (!version) return undefined;
  const v = version.replace(/(?:[.-]min)$/i, '').replace(/[._-]+$/, '');
  return parseVersion(v) ? v : undefined;
}

function make(name: string, version: string | undefined, method: LibraryDetectionMethod, confidence?: DetectedLibrary['confidence']): DetectedLibrary | undefined {
  const v = clean(version);
  const n = normalizeLibraryName(name);
  if (!v || !NAME_RE.test(n)) return undefined;
  return { name: n, version: v, method, confidence: confidence ?? CONFIDENCE[method] };
}

/** Detections derived from a URL or file name alone. */
export function detectFromUrl(rawUrl: string | undefined, db?: LibraryDb): DetectedLibrary[] {
  if (!rawUrl) return [];
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return [];
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return [];
  const out: DetectedLibrary[] = [];
  const add = (d: DetectedLibrary | undefined): void => {
    if (d) out.push(d);
  };
  let path = u.pathname;
  try {
    path = decodeURIComponent(path);
  } catch {
    /* keep the raw path */
  }
  // name@version in a path segment: /lodash@4.17.20/, /npm/jquery@3.5.1/dist/..., /gh/owner/repo@1.2.3/
  for (const m of path.matchAll(/\/((?:@[a-z0-9._-]{1,60}\/)?[a-z0-9][a-z0-9._-]{0,60})@v?(\d[0-9A-Za-z.-]{0,30})(?=\/|$)/gi)) {
    add(make(m[1] as string, m[2], 'url'));
  }
  const segments = path.split('/').filter(Boolean);
  // /ajax/libs/<name>/<version>/ (cdnjs, Google Hosted Libraries) and /<known-name>/<version>/
  for (let i = 0; i + 1 < segments.length; i++) {
    const name = normalizeLibraryName(segments[i] as string);
    const ver = (segments[i + 1] as string).replace(/^v/, '');
    if (!/^\d/.test(ver)) continue;
    if (segments[i - 1] === 'libs') add(make(name, ver, 'url'));
    else if (isKnownName(name, db) && i + 2 < segments.length) add(make(name, ver, 'url', 'low'));
  }
  // file name: jquery-3.5.1.min.js, lodash.4.17.js, jquery-ui-1.12.1.custom.min.js
  const file = segments.at(-1) ?? '';
  const fm = /^([a-z][a-z0-9._-]{0,60}?)[-_.@]v?(\d{1,4}\.\d{1,4}(?:\.\d{1,4}){0,2}(?:-[0-9a-z.]{1,20}?)?)(?:\.custom)?(?:[.-]min)?\.(?:js|mjs|cjs)$/i.exec(file);
  if (fm) {
    const name = normalizeLibraryName(fm[1] as string);
    if (isKnownName(name, db)) add(make(name, fm[2], 'url'));
  }
  if (db) {
    for (const [name, entry] of db.libraries) {
      for (const re of entry.filename) {
        const m = execCapped(re, file);
        if (m) add(make(name, m.groups?.ver, 'url'));
      }
      for (const re of entry.uri) {
        const m = execCapped(re, u.pathname);
        if (m) add(make(name, m.groups?.ver, 'url'));
      }
    }
  }
  return out;
}

function detectGenericBanner(text: string, have: ReadonlySet<string>): DetectedLibrary[] {
  const head = text.slice(0, 400);
  if (!/^\s{0,16}(?:\/\*|\/\/)/.test(head)) return [];
  const m = /(?:^|[\s*!@])([A-Za-z][A-Za-z0-9._-]{1,40})(?: JavaScript Library| Library)?,? v(\d{1,4}\.\d{1,4}(?:\.\d{1,4}){0,2}(?:-[0-9A-Za-z.]{1,20})?)(?![\d.])/.exec(head);
  if (!m) return [];
  const name = normalizeLibraryName(m[1] as string);
  if (GENERIC_BAD_NAMES.has(name) || have.has(name)) return [];
  const d = make(name, m[2], 'banner', 'medium');
  return d ? [d] : [];
}

/** Detections derived from the script content alone (cacheable per content hash). */
export function detectFromContent(body: Buffer | string | undefined, db?: LibraryDb, knownHashes: readonly KnownHash[] = []): DetectedLibrary[] {
  if (body === undefined) return [];
  const buf = typeof body === 'string' ? Buffer.from(body, 'utf8') : body;
  const out: DetectedLibrary[] = [];
  const add = (d: DetectedLibrary | undefined): void => {
    if (d) out.push(d);
  };
  const sha256 = createHash('sha256').update(buf).digest('hex');
  for (const k of knownHashes) if (k.sha256.toLowerCase() === sha256) add(make(k.name, k.version, 'content-hash'));
  if (db && [...db.libraries.values()].some((l) => l.hashes.size > 0)) {
    const sha1 = createHash('sha1').update(buf).digest('hex');
    for (const [name, entry] of db.libraries) {
      const v = entry.hashes.get(sha1);
      if (v) add(make(name, v, 'content-hash'));
    }
  }
  const text = (buf.length > MAX_INPUT_CHARS ? buf.subarray(0, MAX_INPUT_CHARS) : buf).toString('utf8');
  for (const p of BUILTIN) {
    if (p.requires && !text.includes(p.requires)) continue;
    const m = execCapped(p.regex, text);
    if (m) add(make(p.name, m[1] ?? m[2], p.method));
  }
  if (db) {
    for (const [name, entry] of db.libraries) {
      for (const p of entry.filecontent) {
        const m = execCapped(p.regex, text);
        if (m) add(make(name, m.groups?.ver, p.banner ? 'banner' : 'code'));
      }
    }
  }
  out.push(...detectGenericBanner(text, new Set(out.map((d) => d.name))));
  return out;
}

/** Merge detections: strongest method per name+version; content beats URL when versions disagree. */
export function mergeDetections(all: readonly DetectedLibrary[]): DetectedLibrary[] {
  const best = new Map<string, DetectedLibrary>();
  for (const d of all) {
    const key = `${d.name}\u0000${d.version}`;
    const cur = best.get(key);
    if (!cur || RANK[d.method] > RANK[cur.method]) best.set(key, d);
  }
  const contentBased = new Set([...best.values()].filter((d) => d.method !== 'url').map((d) => d.name));
  const kept = [...best.values()].filter((d) => d.method !== 'url' || !contentBased.has(d.name));
  return kept
    .sort((a, b) => a.name.localeCompare(b.name) || (a.version < b.version ? -1 : a.version > b.version ? 1 : 0))
    .slice(0, MAX_DETECTIONS);
}

export function detectLibraries(input: DetectInput): DetectedLibrary[] {
  return mergeDetections([...detectFromContent(input.body, input.db, input.knownHashes), ...detectFromUrl(input.url, input.db)]);
}
