import { parse as parseDomain } from 'tldts';
import { matchesAnyHost, normalizeHost } from '../utils/patterns.js';
import type { Party, ResourceType } from '../types/index.js';

export interface HostInfo {
  readonly hostname: string;
  readonly registrableDomain: string;
  readonly isIp: boolean;
}

/** Hostname and registrable domain (eTLD+1, using the Public Suffix List via tldts). */
export function hostInfo(rawUrlOrHost: string): HostInfo | undefined {
  let hostname: string;
  try {
    hostname = normalizeHost(rawUrlOrHost.includes('://') ? new URL(rawUrlOrHost).hostname : rawUrlOrHost);
  } catch {
    return undefined;
  }
  if (!hostname) return undefined;
  const parsed = parseDomain(hostname, { allowPrivateDomains: true });
  const isIp = parsed.isIp === true;
  // For IPs, unknown TLDs (e.g. ".test") or bare hostnames fall back to the hostname itself.
  const registrableDomain = isIp ? hostname : (parsed.domain ?? hostname);
  return { hostname, registrableDomain, isIp };
}

export interface PartyContext {
  readonly siteRegistrableDomain: string;
  readonly firstPartyDomains: readonly string[];
}

export function partyContextFor(siteUrl: string, firstPartyDomains: readonly string[]): PartyContext {
  const info = hostInfo(siteUrl);
  return { siteRegistrableDomain: info?.registrableDomain ?? '', firstPartyDomains };
}

/**
 * First-party: same registrable domain as the site, or matching a configured
 * first-party domain pattern. Everything else is third-party.
 */
export function classifyParty(info: HostInfo | undefined, ctx: PartyContext): Party {
  if (!info) return 'third-party';
  if (info.registrableDomain === ctx.siteRegistrableDomain) return 'first-party';
  if (matchesAnyHost(info.hostname, ctx.firstPartyDomains) || matchesAnyHost(info.registrableDomain, ctx.firstPartyDomains)) {
    return 'first-party';
  }
  return 'third-party';
}

/** MIME types that make a <script> element execute as classic JavaScript (HTML spec). */
const JS_MIME_TYPES = new Set([
  'application/ecmascript',
  'application/javascript',
  'application/x-ecmascript',
  'application/x-javascript',
  'text/ecmascript',
  'text/javascript',
  'text/javascript1.0',
  'text/javascript1.1',
  'text/javascript1.2',
  'text/javascript1.3',
  'text/javascript1.4',
  'text/javascript1.5',
  'text/jscript',
  'text/livescript',
  'text/x-ecmascript',
  'text/x-javascript',
]);

export type ScriptElementKind = 'classic' | 'module' | 'importmap' | 'data';

/** Determine how a <script type="..."> element is treated by the browser. */
export function scriptElementKind(type: string | undefined): ScriptElementKind {
  const t = (type ?? '').trim().toLowerCase();
  if (t === '') return 'classic';
  if (t === 'module') return 'module';
  if (t === 'importmap') return 'importmap';
  const essence = t.split(';')[0]?.trim() ?? '';
  return JS_MIME_TYPES.has(essence) ? 'classic' : 'data';
}

const WASM = /application\/wasm/i;

export interface ExternalTypeInput {
  readonly url: string;
  readonly contentType?: string | undefined;
  readonly requestResourceType: string;
  readonly fetchDest?: string | undefined;
  readonly fetchMode?: string | undefined;
  readonly source: string;
  readonly workerKind?: 'dedicated-worker' | 'shared-worker' | 'service-worker' | undefined;
  readonly domKind?: ScriptElementKind | undefined;
  /** Lazily determine whether the body is an ES module (only consulted when needed). */
  readonly looksLikeModule?: (() => boolean) | undefined;
}

/** Classify an external (network-loaded) executable resource. */
export function classifyExternal(input: ExternalTypeInput): ResourceType {
  let pathname = '';
  let protocol = '';
  try {
    const u = new URL(input.url);
    pathname = u.pathname;
    protocol = u.protocol;
  } catch {
    // fall through with empty values
  }
  if ((input.contentType && WASM.test(input.contentType)) || /\.wasm$/i.test(pathname)) return 'wasm';
  if (protocol === 'blob:') return 'blob-script';
  if (protocol === 'data:') return 'data-script';
  if (input.source === 'service-worker-probe' || input.fetchDest === 'serviceworker' || input.workerKind === 'service-worker') {
    return 'service-worker';
  }
  if (input.fetchDest === 'sharedworker' || input.workerKind === 'shared-worker') return 'shared-worker';
  if (input.fetchDest === 'worker' || input.workerKind === 'dedicated-worker') return 'dedicated-worker';
  if (input.domKind === 'module') return 'module';
  if (input.domKind === 'classic') return 'script';
  if (input.requestResourceType === 'fetch' || input.requestResourceType === 'xhr') return 'fetched-script';
  // Module scripts (including dynamic import()) are fetched in CORS mode; classic scripts in no-cors mode.
  if (input.fetchMode === 'cors' && (input.fetchDest === 'script' || input.requestResourceType === 'script')) return 'module';
  if (input.fetchMode === 'no-cors') return 'script';
  // No script element and no fetch metadata: likely import()/static import of a module.
  if (input.domKind === undefined && input.requestResourceType === 'script') {
    if (/\.mjs$/i.test(pathname)) return 'module';
    if (input.looksLikeModule?.() === true) return 'module';
  }
  return 'script';
}

export function isJavaScriptType(type: ResourceType): boolean {
  return type !== 'wasm';
}
