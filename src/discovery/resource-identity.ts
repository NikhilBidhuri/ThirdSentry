/**
 * Canonical resource identity.
 *
 * A resource is matched across scans by its *identity*, which is separate
 * from both the original URL (kept verbatim for evidence) and the content
 * hash. A URL alone does not identify content: the same URL can serve
 * different bytes over time (that is precisely what ScriptDrift detects),
 * and different URLs can serve identical bytes.
 *
 * External resources: identity is derived from the URL the page requested
 * (the first hop of any redirect chain) with the fragment removed,
 * scheme/host lowercased, default port removed and query parameters kept
 * (sorted by name for stability). Parameters listed in the site's
 * `ignoreQueryParams` (e.g. cache busters) are dropped from the identity only,
 * never from the stored URL. The final URL after redirects is recorded
 * separately, so a changed redirect destination shows up as a change of the
 * same resource.
 *
 * Inline scripts have no URL: identity combines the page, the frame and the
 * DOM position. Matching across scans additionally falls back to content
 * hashes because DOM positions can shift.
 */

export function canonicalUrl(raw: string, ignoreQueryParams: readonly string[] = []): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return raw;
  }
  url.hash = '';
  if (url.protocol === 'data:' || url.protocol === 'blob:') return url.toString();
  if (url.search) {
    const ignore = new Set(ignoreQueryParams);
    const params = [...new URLSearchParams(url.search)].filter(([k]) => !ignore.has(k));
    // Stable sort by key keeps the relative order of repeated keys.
    params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    url.search = params.length ? new URLSearchParams(params).toString() : '';
  }
  return url.toString();
}

export function externalIdentity(finalUrl: string, ignoreQueryParams: readonly string[] = []): string {
  return `url:${canonicalUrl(finalUrl, ignoreQueryParams)}`;
}

/** Frame component used in inline/blob identities: "main" or the frame URL without query. */
export function frameComponent(frameUrl: string | undefined, isMainFrame: boolean): string {
  if (isMainFrame) return 'main';
  if (!frameUrl) return 'unknown-frame';
  try {
    const u = new URL(frameUrl);
    return `frame:${u.origin}${u.pathname}`;
  } catch {
    return 'unknown-frame';
  }
}

export function inlineIdentity(pageKey: string, frameUrl: string | undefined, isMainFrame: boolean, domPath: string): string {
  return `inline:${pageKey}|${frameComponent(frameUrl, isMainFrame)}|${domPath}`;
}

export function blobIdentity(pageKey: string, frameUrl: string | undefined, isMainFrame: boolean, sha256: string | null): string {
  return `blob:${pageKey}|${frameComponent(frameUrl, isMainFrame)}|${sha256 ? sha256.slice(0, 16) : 'unknown'}`;
}

export function dataUrlIdentity(sha256: string | null, raw: string): string {
  return `data:${sha256 ?? raw.slice(0, 64)}`;
}

/** Key unique within a scan: identity plus content hash (or a placeholder when content is unknown). */
export function resourceKey(identity: string, sha256: string | null): string {
  return `${identity}#${sha256 ? sha256.slice(0, 16) : 'no-content'}`;
}
