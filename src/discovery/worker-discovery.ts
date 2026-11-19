import type { PageEvidence } from '../types/evidence.js';
import { compact } from '../utils/object.js';
import { sha256Hex } from '../analysis/hashing.js';
import { frameContextOf, stripFragment, type DiscoveryContext, type ResourceCandidate } from './candidate.js';
import { blobIdentity, externalIdentity } from './resource-identity.js';

/**
 * Worker and blob discovery.
 *
 *  - Blob URLs are random per page load, so blob-loaded code is identified by
 *    page, frame and content hash. Blob content is captured by the in-page
 *    hook on URL.createObjectURL (best-effort, see limitations).
 *  - Workers whose script was not observed on the network (e.g. blocked
 *    service worker registration whose probe failed) are still recorded so
 *    that their appearance is visible in change detection.
 */
export function discoverWorkersAndBlobs(page: PageEvidence, ctx: DiscoveryContext): ResourceCandidate[] {
  const out: ResourceCandidate[] = [];
  const responseUrls = new Set<string>();
  for (const r of page.scriptResponses) {
    responseUrls.add(stripFragment(r.url));
    r.redirectChain.forEach((u) => responseUrls.add(stripFragment(u)));
  }
  const referencedBlobs = new Set<string>([
    ...page.workers.map((w) => w.url).filter((u) => u.startsWith('blob:')),
    ...page.domScripts.map((s) => s.src ?? '').filter((u) => u.startsWith('blob:')),
  ]);

  const seenBlobs = new Set<string>();
  for (const blob of page.blobs) {
    const isScriptMime = /javascript|ecmascript/i.test(blob.mimeType);
    const isWasm = /wasm/i.test(blob.mimeType);
    if (!isScriptMime && !isWasm && !referencedBlobs.has(blob.blobUrl)) continue;
    if (seenBlobs.has(blob.blobUrl)) continue;
    // Already captured from the network (Chromium reports blob: script loads).
    if (responseUrls.has(blob.blobUrl) && page.scriptResponses.some((r) => r.url === blob.blobUrl && r.bodyStatus === 'captured')) continue;
    seenBlobs.add(blob.blobUrl);
    const body = blob.textBase64 !== undefined ? Buffer.from(blob.textBase64, 'base64') : undefined;
    const sha = body ? sha256Hex(body) : null;
    const workerUse = page.workers.find((w) => w.url === blob.blobUrl);
    const isMain = blob.isMainFrame ?? blob.frameUrl === page.finalUrl;
    out.push(
      compact<ResourceCandidate>({
        identity: blobIdentity(ctx.pageKey, blob.frameUrl, isMain, sha),
        type: isWasm ? 'wasm' : 'blob-script',
        pageKey: ctx.pageKey,
        originalUrl: blob.blobUrl,
        redirectChain: [],
        frameUrl: blob.frameUrl,
        frameContext: workerUse ? 'worker' : frameContextOf(blob.frameUrl, isMain),
        partyUrl: blob.frameUrl,
        dynamic: true,
        discovery: ['blob-url', ...(workerUse ? [`${workerUse.kind}-source`] : [])],
        contentType: blob.mimeType || undefined,
        body,
        contentStatus: body ? (blob.truncated ? 'truncated' : 'captured') : 'unavailable',
        contentNote: blob.truncated ? 'Blob larger than limits.maxResourceBytes; only the first part was captured' : undefined,
        declaredSize: blob.size,
        fromServiceWorker: false,
        timestamp: blob.timestamp,
      }),
    );
  }

  const seenWorkers = new Set<string>();
  for (const worker of page.workers) {
    const url = stripFragment(worker.url);
    if (url.startsWith('blob:') || url.startsWith('data:')) continue;
    if (responseUrls.has(url) || seenWorkers.has(url)) continue;
    seenWorkers.add(url);
    out.push(
      compact<ResourceCandidate>({
        identity: externalIdentity(url, ctx.ignoreQueryParams),
        type: worker.kind,
        pageKey: ctx.pageKey,
        originalUrl: worker.url,
        redirectChain: [],
        frameUrl: worker.frameUrl,
        frameContext: 'worker',
        partyUrl: worker.url,
        dynamic: false,
        discovery: [worker.source, ...(worker.blocked ? ['registration-blocked'] : [])],
        contentStatus: 'unavailable',
        contentNote:
          worker.kind === 'service-worker'
            ? 'Service worker script was not observed on the network (see service worker coverage in docs/limitations.md).'
            : 'Worker script response was not observed on the network.',
        fromServiceWorker: false,
        timestamp: worker.timestamp,
      }),
    );
  }
  return out;
}
