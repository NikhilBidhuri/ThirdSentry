import { errors as playwrightErrors, type Browser, type BrowserContext, type Page, type Response } from 'playwright';
import type { Limits, ScanOptions } from '../config/schema.js';
import type { ResolvedPage } from '../config/loader.js';
import { filterResponseHeaders, redactText, redactUrl } from '../security/redaction.js';
import type { DomScriptEvidence, FrameEvidence, Issue, PageEvidence, PageStatus, ScriptResponseEvidence } from '../types/evidence.js';
import { getLogger } from '../utils/logger.js';
import { compact } from '../utils/object.js';
import { createIsolatedContext } from './browser-manager.js';
import type { BrowserProfile } from './browser-profiles.js';
import { buildInitScript, SNAPSHOT_SCRIPT } from './init-script.js';
import { NetworkCollector, withTimeout } from './network-collector.js';
import { ResourceCollector } from './resource-collector.js';

export interface PageScanRequest {
  readonly browser: Browser;
  readonly profile: BrowserProfile;
  readonly page: ResolvedPage;
  readonly scan: ScanOptions;
  readonly limits: Limits;
  readonly serviceWorkers: { strategy: 'block' | 'allow'; probeBlockedRegistrations: boolean };
  /** Absolute epoch-ms deadline for this page (derived from the scan budget). */
  readonly deadline: number;
}

const MAX_CONSOLE_ENTRIES = 200;
const MAX_SCREENSHOT_BASE64 = 14 * 1024 * 1024;

/**
 * Scan a single page in a fresh, isolated browser context and return the raw
 * evidence. Never throws for page-level problems: failures are reported via
 * `status` and `issues` so that a partial scan is never mistaken for a
 * complete one.
 */
export async function scanPage(request: PageScanRequest): Promise<PageEvidence> {
  const log = getLogger('page-scanner').child({ page: request.page.url });
  const startedAt = new Date().toISOString();
  const issues: Issue[] = [];
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const { limits, scan } = request;
  const state: { status: PageStatus } = { status: 'complete' };
  const degrade = (to: PageStatus): void => {
    if (to === 'failed' || (to === 'partial' && state.status === 'complete')) state.status = to;
  };

  let context: BrowserContext | undefined;
  try {
    context = await createIsolatedContext(request.browser, {
      profile: request.profile,
      serviceWorkers: request.serviceWorkers.strategy,
      ...(scan.userAgent ? { userAgent: scan.userAgent } : {}),
    });
  } catch (error) {
    return failedPage(request, startedAt, [{ level: 'error', code: 'context-failed', message: messageOf(error) }]);
  }

  const resources = new ResourceCollector({
    maxScripts: limits.maxScriptsPerPage,
    maxInlineChars: limits.maxInlineScriptBytes,
    maxBlobBase64Chars: Math.ceil((limits.maxResourceBytes * 4) / 3) + 4,
    maxEntries: 1000,
  });

  try {
    await resources.install(context);
    await context.addInitScript({
      content: buildInitScript({
        maxInlineChars: limits.maxInlineScriptBytes,
        maxBlobBytes: limits.maxResourceBytes,
        maxReports: limits.maxScriptsPerPage * 4,
      }),
    });
    const page = await context.newPage();
    resources.attachPage(page);
    const remaining = (): number => Math.max(1_000, request.deadline - Date.now());
    page.setDefaultTimeout(Math.min(scan.timeout, remaining()));
    page.setDefaultNavigationTimeout(Math.min(scan.timeout, remaining()));

    const network = new NetworkCollector(page, {
      maxRequests: limits.maxRequestsPerPage,
      maxScripts: limits.maxScriptsPerPage,
      maxResourceBytes: limits.maxResourceBytes,
      bodyTimeoutMs: 20_000,
    });
    network.attach(context);

    page.on('console', (msg) => {
      if (msg.type() === 'error' && consoleErrors.length < MAX_CONSOLE_ENTRIES) consoleErrors.push(redactText(msg.text(), 500));
    });
    page.on('pageerror', (err) => {
      if (pageErrors.length < MAX_CONSOLE_ENTRIES) pageErrors.push(redactText(err.message, 500));
    });
    page.on('dialog', (dialog) => {
      void dialog.dismiss().catch(() => undefined);
    });
    page.on('download', (download) => {
      void download.cancel().catch(() => undefined);
    });
    page.on('popup', (popup) => {
      // Popups are not scanned; close them to bound resource usage.
      void popup.close().catch(() => undefined);
    });

    // --- Navigation -------------------------------------------------------
    let docResponse: Response | null = null;
    const navWaitUntil = scan.waitUntil === 'networkidle' ? 'load' : scan.waitUntil;
    try {
      docResponse = await page.goto(request.page.url, { waitUntil: navWaitUntil, timeout: Math.min(scan.timeout, remaining()) });
    } catch (error) {
      const timeout = error instanceof playwrightErrors.TimeoutError;
      const committed = page.url() !== 'about:blank';
      issues.push({
        level: 'error',
        code: timeout ? 'navigation-timeout' : 'navigation-failed',
        message: timeout
          ? `Navigation did not reach "${navWaitUntil}" within ${scan.timeout}ms`
          : `Navigation failed: ${messageOf(error)}`,
      });
      degrade(timeout && committed ? 'partial' : 'failed');
    }

    if (docResponse) {
      const docStatus = docResponse.status();
      if (docStatus >= 400) {
        issues.push({ level: 'error', code: 'http-error', message: `Page returned HTTP ${docStatus}` });
        degrade('failed');
      }
    }

    if (state.status !== 'failed') {
      if (scan.waitUntil === 'networkidle' && scan.networkIdleTimeout > 0) {
        try {
          await page.waitForLoadState('networkidle', { timeout: Math.min(scan.networkIdleTimeout, remaining()) });
        } catch {
          issues.push({
            level: 'warning',
            code: 'network-not-idle',
            message: `Network did not become idle within ${scan.networkIdleTimeout}ms; continuing with what was observed`,
          });
        }
      }
      const settle = Math.min(scan.settleMs, Math.max(0, request.deadline - Date.now() - 5_000));
      if (settle > 0) await page.waitForTimeout(settle);
      if (Date.now() > request.deadline) {
        issues.push({ level: 'error', code: 'scan-time-limit', message: 'Scan time budget exhausted while observing the page' });
        degrade('partial');
      }
    }

    const finalUrl = page.url();
    try {
      if (docResponse && new URL(finalUrl).origin !== new URL(request.page.url).origin) {
        issues.push({
          level: 'warning',
          code: 'cross-origin-navigation',
          message: `Page ended on a different origin (${redactUrl(finalUrl)}); results describe that page`,
        });
      }
    } catch {
      // ignore malformed URLs
    }

    // --- DOM snapshot of every frame -------------------------------------
    const frames: FrameEvidence[] = [];
    const snapshotScripts: DomScriptEvidence[] = [];
    if (state.status !== 'failed') {
      for (const frame of page.frames().slice(0, 1000)) {
        frames.push(
          compact<FrameEvidence>({ url: frame.url(), parentUrl: frame.parentFrame()?.url(), name: frame.name().slice(0, 256) || undefined }),
        );
        try {
          const items = await withTimeout(
            frame.evaluate<unknown[]>(`(${SNAPSHOT_SCRIPT})(${limits.maxInlineScriptBytes})`),
            5_000,
          );
          const ts = new Date().toISOString();
          for (const item of Array.isArray(items) ? items.slice(0, limits.maxScriptsPerPage) : []) {
            const evidence = snapshotItem(item, frame.url(), frame === page.mainFrame(), ts, limits.maxInlineScriptBytes);
            if (evidence) snapshotScripts.push(evidence);
          }
        } catch (error) {
          issues.push({ level: 'warning', code: 'frame-snapshot-failed', message: `Could not inspect frame ${redactUrl(frame.url())}: ${messageOf(error)}` });
        }
      }
    }

    // --- Optional screenshot ---------------------------------------------
    let screenshotBase64: string | undefined;
    if (scan.captureScreenshots && state.status !== 'failed') {
      try {
        const png = await page.screenshot({ type: 'png', fullPage: false, timeout: 10_000 });
        if (png.length * 1.34 < MAX_SCREENSHOT_BASE64) screenshotBase64 = png.toString('base64');
      } catch (error) {
        issues.push({ level: 'warning', code: 'screenshot-failed', message: messageOf(error) });
      }
    }

    // Give queued init-script reports a moment to arrive, then collect network evidence.
    await page.waitForTimeout(100).catch(() => undefined);
    const net = await network.finalize(Math.min(30_000, remaining()));
    if (net.pendingAbandoned > 0) {
      issues.push({ level: 'warning', code: 'bodies-pending', message: `${net.pendingAbandoned} response bodies were still downloading when the page scan ended` });
    }
    if (net.requestsDropped > 0) {
      issues.push({ level: 'warning', code: 'request-limit', message: `${net.requestsDropped} requests exceeded limits.maxRequestsPerPage and were not recorded` });
      degrade('partial');
    }
    const scriptsDropped = net.scriptsDropped + resources.scriptsDropped;
    if (scriptsDropped > 0) {
      issues.push({ level: 'error', code: 'script-limit', message: `${scriptsDropped} scripts exceeded limits.maxScriptsPerPage and were not recorded` });
      degrade('partial');
    }

    const scriptResponses = [...net.scriptResponses];
    if (request.serviceWorkers.strategy === 'block' && request.serviceWorkers.probeBlockedRegistrations) {
      const probed = await probeServiceWorkers(context, resources, request, issues);
      scriptResponses.push(...probed);
    }

    const headersArray = docResponse ? await docResponse.headersArray().catch(() => []) : [];
    const docHeaders = docResponse ? await docResponse.allHeaders().catch(() => ({})) : {};
    const cspHeaders = headersArray.filter((h) => h.name.toLowerCase() === 'content-security-policy').map((h) => h.value).slice(0, 32);
    const cspReportOnlyHeaders = headersArray
      .filter((h) => h.name.toLowerCase() === 'content-security-policy-report-only')
      .map((h) => h.value)
      .slice(0, 32);

    log.debug({ status: state.status, scripts: scriptResponses.length, dom: resources.domScripts.length + snapshotScripts.length }, 'page scanned');

    return compact<PageEvidence>({
      pageKey: request.page.key,
      pageUrl: request.page.url,
      finalUrl,
      sensitive: request.page.sensitive,
      status: state.status,
      issues,
      startedAt,
      finishedAt: new Date().toISOString(),
      documentStatus: docResponse?.status(),
      documentHeaders: filterResponseHeaders(docHeaders),
      cspHeaders,
      cspReportOnlyHeaders,
      frames,
      scriptResponses,
      domScripts: [...resources.domScripts, ...snapshotScripts],
      blobs: resources.blobs,
      workers: resources.workers,
      requests: net.requests,
      requestsDropped: net.requestsDropped,
      scriptsDropped,
      consoleErrors,
      pageErrors,
      screenshotBase64,
    });
  } catch (error) {
    log.warn({ err: messageOf(error) }, 'page scan failed unexpectedly');
    return failedPage(request, startedAt, [...issues, { level: 'error', code: 'scan-error', message: messageOf(error) }]);
  } finally {
    await withTimeout(context.close(), 15_000).catch(() => undefined);
  }
}

function snapshotItem(raw: unknown, frameUrl: string, isMainFrame: boolean, timestamp: string, maxInline: number): DomScriptEvidence | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const m = raw as Record<string, unknown>;
  const s = (v: unknown, max: number): string | undefined => (typeof v === 'string' ? v.slice(0, max) : undefined);
  const b = (v: unknown): boolean | undefined => (typeof v === 'boolean' ? v : undefined);
  const kind = m.kind === 'external' ? 'external' : 'inline';
  const src = s(m.src, 16_384);
  if (kind === 'external' && !src) return undefined;
  return compact<DomScriptEvidence>({
    kind,
    src,
    type: s(m.type, 128),
    text: kind === 'inline' ? (s(m.text, maxInline) ?? '') : undefined,
    textTruncated: kind === 'inline' ? (b(m.textTruncated) ?? false) : undefined,
    textBytes: typeof m.textBytes === 'number' ? Math.max(0, Math.floor(m.textBytes)) : undefined,
    domPath: s(m.domPath, 1024) ?? 'unknown',
    frameUrl,
    isMainFrame,
    async: b(m.async),
    defer: b(m.defer),
    integrity: s(m.integrity, 1024),
    crossOrigin: s(m.crossOrigin, 64),
    hasNonce: b(m.hasNonce),
    insertedByScript: false,
    observedVia: 'snapshot',
    timestamp,
  });
}

/**
 * Under the `block` service-worker strategy registrations are refused, so the
 * worker script would never be fetched. Fetch each registered script via a
 * navigation in the same isolated context (traffic still goes through the
 * egress proxy) so it can be hashed and tracked.
 */
async function probeServiceWorkers(
  context: BrowserContext,
  resources: ResourceCollector,
  request: PageScanRequest,
  issues: Issue[],
): Promise<ScriptResponseEvidence[]> {
  const out: ScriptResponseEvidence[] = [];
  const seen = new Set<string>();
  const registrations = resources.workers.filter((w) => w.kind === 'service-worker' && w.source === 'registration-hook');
  for (const reg of registrations.slice(0, 10)) {
    reg.blocked = true;
    if (seen.has(reg.url)) continue;
    seen.add(reg.url);
    let swUrl: URL;
    try {
      swUrl = new URL(reg.url);
      const frameOrigin = reg.frameUrl ? new URL(reg.frameUrl).origin : undefined;
      if (!['http:', 'https:'].includes(swUrl.protocol) || (frameOrigin && swUrl.origin !== frameOrigin)) continue;
    } catch {
      continue;
    }
    if (Date.now() > request.deadline - 5_000) break;
    let probePage: Page | undefined;
    try {
      probePage = await context.newPage();
      const response = await probePage.goto(swUrl.toString(), { waitUntil: 'commit', timeout: 15_000 });
      if (!response) continue;
      const body = await withTimeout(response.body(), 15_000);
      const headers = await response.allHeaders();
      const tooLarge = body.length > request.limits.maxResourceBytes;
      out.push(
        compact<ScriptResponseEvidence>({
          url: response.url(),
          redirectChain: [],
          method: 'GET',
          requestResourceType: 'service-worker-probe',
          status: response.status(),
          contentType: headers['content-type'],
          responseHeaders: filterResponseHeaders(headers),
          bodyStatus: tooLarge ? 'too-large' : 'captured',
          bodyBase64: tooLarge ? undefined : body.toString('base64'),
          bodyBytes: body.length,
          isMainFrame: false,
          fromServiceWorker: false,
          workerUrl: reg.url,
          source: 'service-worker-probe',
          timestamp: new Date().toISOString(),
        }),
      );
    } catch (error) {
      issues.push({ level: 'warning', code: 'service-worker-probe-failed', message: `Could not fetch service worker script ${redactUrl(reg.url)}: ${messageOf(error)}` });
    } finally {
      await probePage?.close().catch(() => undefined);
    }
  }
  return out;
}

function failedPage(request: PageScanRequest, startedAt: string, issues: Issue[]): PageEvidence {
  return {
    pageKey: request.page.key,
    pageUrl: request.page.url,
    sensitive: request.page.sensitive,
    status: 'failed',
    issues,
    startedAt,
    finishedAt: new Date().toISOString(),
    documentHeaders: {},
    cspHeaders: [],
    cspReportOnlyHeaders: [],
    frames: [],
    scriptResponses: [],
    domScripts: [],
    blobs: [],
    workers: [],
    requests: [],
    requestsDropped: 0,
    scriptsDropped: 0,
    consoleErrors: [],
    pageErrors: [],
  };
}

function messageOf(error: unknown): string {
  const text = error instanceof Error ? error.message : String(error);
  // Playwright errors include multi-line call logs; keep the first line.
  return redactText(text.split('\n')[0] ?? text, 500);
}
