import type { ContentStatus, ResourceType } from '../types/index.js';

/**
 * A single observation of an executable resource on a page, before
 * de-duplication. Produced by the discovery modules from validated evidence.
 */
export interface ResourceCandidate {
  readonly identity: string;
  readonly type: ResourceType;
  readonly pageKey: string;
  readonly originalUrl?: string;
  readonly finalUrl?: string;
  readonly redirectChain: readonly string[];
  readonly frameUrl?: string;
  readonly frameContext: 'main-frame' | 'iframe' | 'worker' | 'unknown';
  /** URL whose host determines first/third-party classification. */
  readonly partyUrl?: string;
  readonly dynamic: boolean;
  readonly discovery: readonly string[];
  readonly httpStatus?: number;
  readonly contentType?: string;
  readonly body?: Buffer;
  readonly contentStatus: ContentStatus;
  readonly contentNote?: string;
  readonly declaredSize?: number;
  readonly integrity?: string;
  readonly fromServiceWorker: boolean;
  readonly responseHeaders?: Readonly<Record<string, string>>;
  readonly domPath?: string;
  readonly timestamp: string;
}

export interface DiscoveryContext {
  readonly pageKey: string;
  readonly ignoreQueryParams: readonly string[];
  readonly maxResourceBytes: number;
}

export function stripFragment(raw: string): string {
  const i = raw.indexOf('#');
  return i >= 0 ? raw.slice(0, i) : raw;
}

export function frameContextOf(frameUrl: string | undefined, isMainFrame: boolean, workerUrl?: string): ResourceCandidate['frameContext'] {
  if (workerUrl) return 'worker';
  if (isMainFrame) return 'main-frame';
  if (frameUrl) return 'iframe';
  return 'unknown';
}

/** Decode a data: URL. Returns undefined for malformed input. */
export function decodeDataUrl(raw: string, maxBytes: number): { mime: string; body: Buffer } | { tooLarge: true } | undefined {
  const match = /^data:([^,]*?),(.*)$/s.exec(raw);
  if (!match) return undefined;
  const meta = match[1] ?? '';
  const data = match[2] ?? '';
  const isBase64 = /;base64$/i.test(meta);
  const mime = (isBase64 ? meta.slice(0, -7) : meta).split(';')[0]?.trim() || 'text/plain';
  if (data.length > maxBytes * 3) return { tooLarge: true };
  try {
    const body = isBase64 ? Buffer.from(data, 'base64') : Buffer.from(decodeURIComponent(data), 'utf8');
    if (body.length > maxBytes) return { tooLarge: true };
    return { mime, body };
  } catch {
    return undefined;
  }
}
