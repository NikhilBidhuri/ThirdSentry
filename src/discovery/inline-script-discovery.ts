import type { DomScriptEvidence, PageEvidence } from '../types/evidence.js';
import { compact } from '../utils/object.js';
import { sha256Hex } from '../analysis/hashing.js';
import { frameContextOf, type DiscoveryContext, type ResourceCandidate } from './candidate.js';
import { scriptElementKind } from './resource-classifier.js';
import { inlineIdentity } from './resource-identity.js';

/**
 * Inline script discovery.
 *
 * Inline scripts are reported twice: by the MutationObserver when inserted
 * (which also catches scripts that are removed again and tells us whether
 * the element was injected by script) and by an end-of-scan DOM snapshot
 * (independent of the in-page hooks). Entries are grouped per frame and
 * content hash and then reconciled so each element is counted once.
 */
export function discoverInlineScripts(page: PageEvidence, ctx: DiscoveryContext): ResourceCandidate[] {
  const groups = new Map<string, { mutation: DomScriptEvidence[]; snapshot: DomScriptEvidence[]; hash: string }>();
  for (const el of page.domScripts) {
    if (el.kind !== 'inline') continue;
    const kind = scriptElementKind(el.type);
    if (kind === 'data') continue;
    const text = el.text ?? '';
    if (text.trim() === '') continue;
    const hash = sha256Hex(text);
    const key = `${el.frameUrl}|${el.isMainFrame ? 'main' : 'sub'}|${kind}|${hash}`;
    const group = groups.get(key) ?? { mutation: [], snapshot: [], hash };
    (el.observedVia === 'mutation' ? group.mutation : group.snapshot).push(el);
    groups.set(key, group);
  }

  const out: ResourceCandidate[] = [];
  for (const group of groups.values()) {
    const snapshotPaths = [...new Set(group.snapshot.map((e) => e.domPath))].sort();
    const mutationPaths = [...new Set(group.mutation.map((e) => e.domPath))].sort();
    const count = Math.max(snapshotPaths.length, mutationPaths.length, 1);
    const extraMutation = mutationPaths.filter((p) => !snapshotPaths.includes(p));
    const paths = [...snapshotPaths, ...extraMutation].slice(0, count);
    const representative = (group.mutation[0] ?? group.snapshot[0]) as DomScriptEvidence;
    const kind = scriptElementKind(representative.type);
    const dynamic = group.mutation.length > 0 && group.mutation.every((e) => e.insertedByScript);
    const removed = extraMutation.length > 0 && group.snapshot.length > 0;
    const truncated = [...group.mutation, ...group.snapshot].some((e) => e.textTruncated);
    const body = Buffer.from(representative.text ?? '', 'utf8');
    for (const domPath of paths) {
      const discovery = ['dom-inline'];
      if (group.mutation.length > 0) discovery.push('mutation-observer');
      if (group.snapshot.length > 0) discovery.push('dom-snapshot');
      if (removed && extraMutation.includes(domPath)) discovery.push('removed-from-dom');
      if (kind === 'importmap') discovery.push('importmap');
      if (group.mutation.some((e) => e.viaDocumentWrite)) discovery.push('document-write');
      out.push(
        compact<ResourceCandidate>({
          identity: inlineIdentity(ctx.pageKey, representative.frameUrl, representative.isMainFrame, domPath),
          type: kind === 'module' ? 'inline-module' : 'inline-script',
          pageKey: ctx.pageKey,
          redirectChain: [],
          frameUrl: representative.frameUrl,
          frameContext: frameContextOf(representative.frameUrl, representative.isMainFrame),
          partyUrl: representative.frameUrl,
          dynamic,
          discovery,
          body,
          contentStatus: truncated ? 'truncated' : 'captured',
          contentNote: truncated ? `Inline script longer than limits.maxInlineScriptBytes; only the first part was captured` : undefined,
          declaredSize: representative.textBytes,
          fromServiceWorker: false,
          domPath,
          timestamp: representative.timestamp,
        }),
      );
    }
  }
  return out;
}
