import type { DomScriptEvidence, PageEvidence, ScriptResponseEvidence } from '../types/evidence.js';
import { compact } from '../utils/object.js';
import { decodeDataUrl, frameContextOf, stripFragment, type DiscoveryContext, type ResourceCandidate } from './candidate.js';
import { classifyExternal, scriptElementKind, type ScriptElementKind } from './resource-classifier.js';
import { blobIdentity, dataUrlIdentity, externalIdentity } from './resource-identity.js';
import { sha256Hex, verifySri } from '../analysis/hashing.js';
import { isModuleSource } from '../analysis/parser.js';

/**
 * External script discovery: correlates network responses (observed outside
 * the page, trustworthy) with script elements reported from the DOM (used for
 * context such as module type, SRI attribute and whether the element was
 * injected at runtime).
 */

function domIndex(page: PageEvidence): Map<string, DomScriptEvidence[]> {
  const index = new Map<string, DomScriptEvidence[]>();
  for (const el of page.domScripts) {
    if (el.kind !== 'external' || !el.src) continue;
    const key = stripFragment(el.src);
    const list = index.get(key) ?? [];
    list.push(el);
    index.set(key, list);
  }
  return index;
}

function workerKinds(page: PageEvidence): Map<string, 'dedicated-worker' | 'shared-worker' | 'service-worker'> {
  const map = new Map<string, 'dedicated-worker' | 'shared-worker' | 'service-worker'>();
  for (const w of page.workers) map.set(stripFragment(w.url), w.kind);
  return map;
}

function elementKind(elements: readonly DomScriptEvidence[]): ScriptElementKind | undefined {
  const kinds = elements.map((e) => scriptElementKind(e.type)).filter((k) => k === 'module' || k === 'classic');
  if (kinds.includes('module')) return 'module';
  if (kinds.includes('classic')) return 'classic';
  return undefined;
}

/**
 * SRI attribute to check for a response. Only the end-of-scan DOM snapshot
 * (taken outside the page's hooks) can establish it: a value reported only by
 * the in-page instrumentation is page-controlled and could create a false
 * mismatch or hide a real one by reporting the matching hash. When the
 * snapshot shows several values, a failing one wins.
 */
function corroboratedIntegrity(elements: readonly DomScriptEvidence[], body: Buffer | undefined): string | undefined {
  const values = [...new Set(elements.filter((e) => e.observedVia === 'snapshot' && e.integrity).map((e) => e.integrity as string))];
  if (values.length <= 1 || !body) return values[0];
  return values.find((v) => verifySri(v, body) === false) ?? values[0];
}

function responseCandidate(
  res: ScriptResponseEvidence,
  dom: Map<string, DomScriptEvidence[]>,
  workers: Map<string, 'dedicated-worker' | 'shared-worker' | 'service-worker'>,
  ctx: DiscoveryContext,
  consumed: Set<DomScriptEvidence>,
): ResourceCandidate {
  const chain = [...res.redirectChain, res.url].map(stripFragment);
  const elements = chain.flatMap((u) => dom.get(u) ?? []);
  elements.forEach((e) => consumed.add(e));
  const workerKind = chain.map((u) => workers.get(u)).find((k) => k !== undefined);
  const body = res.bodyStatus === 'captured' && res.bodyBase64 !== undefined ? Buffer.from(res.bodyBase64, 'base64') : undefined;
  const type = classifyExternal({
    url: res.url,
    contentType: res.contentType,
    requestResourceType: res.requestResourceType,
    fetchDest: res.fetchDest,
    fetchMode: res.fetchMode,
    source: res.source,
    workerKind,
    domKind: elementKind(elements),
    looksLikeModule: () => body !== undefined && isModuleSource(body.toString('utf8')),
  });
  const isScriptElementType = type === 'script' || type === 'module';
  // Only mutation-observer entries know whether an element was injected by
  // script; end-of-scan snapshot entries carry no provenance. Any report of
  // runtime injection counts: page-reported data may add the signal but a
  // (forged) "parser-inserted" report must not remove it.
  const observed = elements.filter((e) => e.observedVia === 'mutation');
  const dynamic = isScriptElementType && (elements.length === 0 || observed.some((e) => e.insertedByScript));
  const discovery = ['network', res.source];
  if (elements.length > 0) discovery.push('dom-element');
  else if (isScriptElementType) discovery.push('no-script-element');
  if (elements.some((e) => e.viaDocumentWrite)) discovery.push('document-write');
  const integrity = corroboratedIntegrity(elements, body);
  if (!integrity && elements.some((e) => e.integrity)) discovery.push('integrity-uncorroborated');
  const overBudget = res.bodyStatus === 'budget-exceeded';
  return compact<ResourceCandidate>({
    // Identity follows the URL the page requested (first hop), so a change of
    // redirect destination is detected as a change of the same resource.
    // blob: URLs are random per page load, so blob code is identified by content.
    identity: res.url.startsWith('blob:')
      ? blobIdentity(ctx.pageKey, res.frameUrl, res.isMainFrame, body ? sha256Hex(body) : null)
      : externalIdentity(chain[0] ?? res.url, ctx.ignoreQueryParams),
    type,
    pageKey: ctx.pageKey,
    originalUrl: chain[0],
    finalUrl: res.url,
    redirectChain: res.redirectChain,
    frameUrl: res.frameUrl,
    frameContext: frameContextOf(res.frameUrl, res.isMainFrame, res.workerUrl ?? (res.source === 'service-worker-probe' ? res.url : undefined)),
    partyUrl: res.url,
    dynamic,
    discovery,
    httpStatus: res.status,
    contentType: res.contentType,
    body,
    contentStatus: body ? 'captured' : res.bodyStatus === 'budget-exceeded' ? 'unavailable' : res.bodyStatus,
    contentNote: overBudget ? (res.bodyNote ?? 'Body not stored: evidence budget exhausted') : res.bodyNote,
    declaredSize: res.bodyBytes,
    integrity,
    fromServiceWorker: res.fromServiceWorker,
    responseHeaders: res.responseHeaders,
    domPath: undefined,
    timestamp: res.timestamp,
  });
}

export function discoverExternalScripts(page: PageEvidence, ctx: DiscoveryContext): ResourceCandidate[] {
  const dom = domIndex(page);
  const workers = workerKinds(page);
  const consumed = new Set<DomScriptEvidence>();
  const out: ResourceCandidate[] = page.scriptResponses.map((res) => responseCandidate(res, dom, workers, ctx, consumed));

  // Script elements without an observed response: data: URLs (no network
  // request), or requests that were blocked, failed or never issued.
  const seen = new Set<string>();
  for (const el of page.domScripts) {
    if (el.kind !== 'external' || !el.src || consumed.has(el)) continue;
    const kind = scriptElementKind(el.type);
    if (kind === 'data' || kind === 'importmap') continue;
    const src = stripFragment(el.src);
    if (src.startsWith('blob:')) continue; // handled by worker/blob discovery
    const dedupeKey = `${el.frameUrl}|${src}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    const frameContext = frameContextOf(el.frameUrl, el.isMainFrame);
    if (src.startsWith('data:')) {
      const decoded = decodeDataUrl(el.src, ctx.maxResourceBytes);
      const body = decoded && 'body' in decoded ? decoded.body : undefined;
      const sha = body ? sha256Hex(body) : null;
      out.push(
        compact<ResourceCandidate>({
          identity: dataUrlIdentity(sha, el.src),
          type: 'data-script',
          pageKey: ctx.pageKey,
          redirectChain: [],
          frameUrl: el.frameUrl,
          frameContext,
          partyUrl: el.frameUrl,
          dynamic: el.insertedByScript,
          discovery: ['dom-element', 'data-url'],
          body,
          contentStatus: body ? 'captured' : decoded && 'tooLarge' in decoded ? 'too-large' : 'unavailable',
          integrity: el.integrity,
          fromServiceWorker: false,
          domPath: el.domPath,
          timestamp: el.timestamp,
        }),
      );
      continue;
    }
    out.push(
      compact<ResourceCandidate>({
        identity: externalIdentity(src, ctx.ignoreQueryParams),
        type: kind === 'module' ? 'module' : 'script',
        pageKey: ctx.pageKey,
        originalUrl: el.src,
        finalUrl: undefined,
        redirectChain: [],
        frameUrl: el.frameUrl,
        frameContext,
        partyUrl: el.src,
        dynamic: el.insertedByScript,
        discovery: ['dom-element', 'no-network-response'],
        contentStatus: 'unavailable',
        contentNote: 'No network response was observed (request blocked, failed, served from an unobservable cache, or not executed).',
        integrity: el.integrity,
        fromServiceWorker: false,
        domPath: el.domPath,
        timestamp: el.timestamp,
      }),
    );
  }
  return out;
}
