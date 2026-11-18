import type { PageEvidence } from '../types/evidence.js';
import { redactUrl } from '../security/redaction.js';

export interface IframeInfo {
  readonly url: string; // redacted
  readonly origin: string;
  readonly parentUrl?: string;
}

/**
 * Iframes embedded in a page (any depth). Scripts running inside iframes are
 * discovered by the regular script discovery (Playwright reports frame
 * context for every request); this module records which origins are framed so
 * that new or changed iframe origins can be detected.
 */
export function discoverIframes(page: PageEvidence): IframeInfo[] {
  const out: IframeInfo[] = [];
  const mainUrl = page.frames[0]?.url;
  for (const frame of page.frames.slice(1)) {
    let origin: string;
    try {
      const u = new URL(frame.url);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
      origin = u.origin;
    } catch {
      continue;
    }
    out.push({ url: redactUrl(frame.url), origin, ...(frame.parentUrl && frame.parentUrl !== mainUrl ? { parentUrl: redactUrl(frame.parentUrl) } : {}) });
  }
  return out;
}

export function iframeOrigins(page: PageEvidence): string[] {
  return [...new Set(discoverIframes(page).map((f) => f.origin))].sort();
}
