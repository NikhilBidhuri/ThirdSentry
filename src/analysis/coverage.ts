import type { ScanEvidence } from '../types/evidence.js';
import type { SiteResult } from '../types/index.js';

/**
 * Plain-language coverage limitations attached to every scan, so readers never
 * mistake "nothing found" for "nothing there". Static items describe inherent
 * limits; dynamic items describe what was missed in this particular scan.
 */
export const STATIC_LIMITATIONS: readonly string[] = [
  'Only the configured pages were visited, once, without user interaction (no clicks, logins, form submissions or scrolling). Scripts loaded only after interaction, on other pages or for logged-in users are not observed.',
  'Third parties can serve different code by geography, user agent, time, A/B bucket or bot detection. A scan sees one variant; malicious code that cloaks itself from automated browsers may not be served.',
  'Code executed via eval(), new Function(), string timers or injected inline handlers (onclick="...") is only visible as part of the script that created it; javascript: URLs and inline event-handler attributes are not captured as separate resources.',
  'Dynamic-injection detection and blob capture rely on in-page instrumentation that hostile scripts can detect or disable. Network-level observation (which they cannot tamper with) remains authoritative for external scripts.',
  'Network monitoring records requests made by the browser through Playwright. It does not observe data leaving through channels such as DNS lookups by the proxy, WebRTC (disabled), browser extensions (none installed), or exfiltration deferred until after the scan window.',
  'Static analysis indicators are heuristics. They point to behaviour worth reviewing; they are not proof of malicious intent, and well-obfuscated malicious code may not trigger any rule.',
];

export function coverageLimitations(evidence: ScanEvidence, sites: readonly SiteResult[]): string[] {
  const out = [...STATIC_LIMITATIONS];
  if (evidence.serviceWorkerStrategy === 'block') {
    out.push(
      'Service workers were blocked (serviceWorkers.strategy: block) so all page traffic stayed observable. Registered service worker scripts were fetched separately for hashing, but their runtime behaviour was not exercised.',
    );
  } else {
    out.push(
      'Service workers were allowed to run. Requests made by service workers are only observable in Chromium; in Firefox and WebKit, service-worker traffic and responses served from service-worker caches are not fully visible.',
    );
  }
  const engines = new Set(sites.map((s) => s.browser.name));
  if (engines.has('webkit')) {
    out.push('WebKit profiles run Playwright\'s WebKit build, not Apple Safari or a real iOS device; mobile-webkit is emulation only.');
  }
  const withoutContent = sites.reduce((n, s) => n + s.resources.filter((r) => r.hashes.sha256 === null).length, 0);
  if (withoutContent > 0) {
    out.push(`${withoutContent} resource(s) were observed without capturable content (blocked, failed, too large or not exposed by the browser); they are tracked by identity only.`);
  }
  const incomplete = sites.flatMap((s) => s.pages).filter((p) => p.status !== 'complete').length;
  if (incomplete > 0) {
    out.push(`${incomplete} page(s) were not scanned completely; removed-resource detection is suppressed for those pages.`);
  }
  if (evidence.isolation === 'none') {
    out.push('The browser ran in the coordinator process (security.isolation.mode: none). This is intended for debugging only.');
  }
  return out;
}
