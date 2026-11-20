import { chromium, firefox, webkit, type Browser, type BrowserContext, type BrowserType, type LaunchOptions } from 'playwright';
import { getLogger } from '../utils/logger.js';
import type { BrowserProfile, EngineName } from './browser-profiles.js';

/**
 * Launches browsers with hardened defaults:
 *  - all traffic is forced through the ThirdSentry egress proxy (including
 *    loopback, which Playwright routes through the proxy for Chromium),
 *  - QUIC/HTTP3 and non-proxied WebRTC UDP are disabled so traffic cannot
 *    bypass the proxy,
 *  - background networking, component updates, sync and pings are disabled,
 *  - downloads are refused and no permissions are granted,
 *  - Chromium's renderer sandbox is kept on unless explicitly disabled.
 */

const ENGINES: Record<EngineName, BrowserType> = { chromium, firefox, webkit };

const CHROMIUM_ARGS = [
  '--disable-quic',
  '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
  '--webrtc-ip-handling-policy=disable_non_proxied_udp',
  '--disable-background-networking',
  '--disable-component-update',
  '--disable-default-apps',
  '--disable-sync',
  '--disable-domain-reliability',
  '--disable-client-side-phishing-detection',
  '--no-pings',
  '--dns-prefetch-disable',
  '--disable-features=DnsOverHttps,AsyncDns,NetworkTimeServiceQuerying,OptimizationHints,MediaRouter,Translate',
  '--metrics-recording-only',
  '--disable-dev-shm-usage',
  '--js-flags=--max-old-space-size=1024',
];

const FIREFOX_PREFS: Record<string, string | number | boolean> = {
  'network.http.http3.enable': false,
  'network.http.http3.enabled': false,
  'media.peerconnection.enabled': false,
  'network.dns.disablePrefetch': true,
  'network.prefetch-next': false,
  'network.predictor.enabled': false,
  'network.trr.mode': 5, // disable DNS-over-HTTPS
  'network.proxy.allow_hijacking_localhost': true,
  'network.proxy.no_proxies_on': '',
  'browser.safebrowsing.malware.enabled': false,
  'browser.safebrowsing.phishing.enabled': false,
  'extensions.update.enabled': false,
  'app.update.enabled': false,
  'datareporting.healthreport.uploadEnabled': false,
  'toolkit.telemetry.enabled': false,
};

export interface LaunchRequest {
  readonly profile: BrowserProfile;
  readonly proxyUrl: string;
  readonly chromiumSandbox: boolean;
  readonly launchTimeoutMs?: number;
}

export interface LaunchedBrowser {
  readonly browser: Browser;
  readonly version: string;
  close(): Promise<void>;
}

export async function launchBrowser(request: LaunchRequest): Promise<LaunchedBrowser> {
  const log = getLogger('browser');
  const { profile } = request;
  const options: LaunchOptions = {
    headless: true,
    proxy: { server: request.proxyUrl, bypass: '' },
    timeout: request.launchTimeoutMs ?? 60_000,
    handleSIGINT: false,
    handleSIGTERM: false,
    handleSIGHUP: false,
  };
  if (profile.engine === 'chromium') {
    options.args = [...CHROMIUM_ARGS];
    options.chromiumSandbox = request.chromiumSandbox;
  } else if (profile.engine === 'firefox') {
    options.firefoxUserPrefs = FIREFOX_PREFS;
  }
  log.debug({ engine: profile.engine, sandbox: request.chromiumSandbox }, 'launching browser');
  const browser = await ENGINES[profile.engine].launch(options);
  let closed = false;
  return {
    browser,
    version: browser.version(),
    async close() {
      if (closed) return;
      closed = true;
      try {
        await Promise.race([
          browser.close(),
          new Promise<void>((resolve) => setTimeout(resolve, 15_000)),
        ]);
      } catch (error) {
        log.warn({ err: error }, 'error while closing browser');
      }
    },
  };
}

export interface ContextRequest {
  readonly profile: BrowserProfile;
  readonly serviceWorkers: 'block' | 'allow';
  readonly userAgent?: string;
  /** Playwright storageState file of an authenticated session (journeys). */
  readonly storageState?: string;
}

export async function createIsolatedContext(browser: Browser, request: ContextRequest): Promise<BrowserContext> {
  const context = await browser.newContext({
    ...request.profile.contextOptions,
    ...(request.userAgent ? { userAgent: request.userAgent } : {}),
    ...(request.storageState ? { storageState: request.storageState } : {}),
    acceptDownloads: false,
    serviceWorkers: request.serviceWorkers,
    ignoreHTTPSErrors: false,
    bypassCSP: false,
    permissions: [],
    javaScriptEnabled: true,
    offline: false,
  });
  return context;
}
