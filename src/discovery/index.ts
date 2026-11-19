import type { PageEvidence } from '../types/evidence.js';
import type { DiscoveryContext, ResourceCandidate } from './candidate.js';
import { discoverInlineScripts } from './inline-script-discovery.js';
import { discoverExternalScripts } from './script-discovery.js';
import { discoverWorkersAndBlobs } from './worker-discovery.js';

export type { DiscoveryContext, ResourceCandidate } from './candidate.js';
export { discoverIframes, iframeOrigins } from './iframe-discovery.js';

/** Run every discovery strategy over a page's validated evidence. */
export function discoverPageResources(page: PageEvidence, ctx: DiscoveryContext): ResourceCandidate[] {
  return [...discoverExternalScripts(page, ctx), ...discoverInlineScripts(page, ctx), ...discoverWorkersAndBlobs(page, ctx)];
}
