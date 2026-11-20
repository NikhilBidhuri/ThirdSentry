import { errors as playwrightErrors, type Browser, type BrowserContext, type Page, type Response } from 'playwright';
import type { Limits, ScanOptions } from '../config/schema.js';
import type { ResolvedPage } from '../config/loader.js';
import { filterResponseHeaders, redactText, redactUrl } from '../security/redaction.js';
import type { DomScriptEvidence, DroppedEvidence, FrameEvidence, Issue, PageEvidence, PageStatus, ScriptResponseEvidence } from '../types/evidence.js';
import { getLogger } from '../utils/logger.js';
import { compact } from '../utils/object.js';
import { createIsolatedContext } from './browser-manager.js';
import type { BrowserProfile } from './browser-profiles.js';
import { base64Length, clampUrl, effectiveScanBudget, jsonSize, ScanEvidenceBudget, type PageEvidenceBudget } from './evidence-budget.js';
import { buildInitScript, SNAPSHOT_SCRIPT } from './init-script.js';
import { NetworkCollector, withTimeout } from './network-collector.js';
import { captureFormSnapshot } from './form-snapshot.js';
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
  /** Evidence byte budget shared by all pages of the scan (created per page if absent). */
  readonly budget?: ScanEvidenceBudget;
}

const MAX_CONSOLE_ENTRIES = 200;
const MAX_SCREENSHOT_BASE64 = 14 * 1024 * 1024;
/** Frames whose DOM is snapshotted at the end of a page scan. */
const MAX_SNAPSHOT_FRAMES = 1000;
/** Wall-clock budget for snapshotting all frames of a page. */
export const SNAPSHOT_BUDGET_MS = 30_000;
/** Per-frame snapshot timeout. */
const FRAME_SNAPSHOT_TIMEOUT_MS = 5_000;
/** Keep the evidence below the schema's issue limit (1000). */
const MAX_PAGE_ISSUES = 900;

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

  const budget = (request.budget ?? new ScanEvidenceBudget(effectiveScanBudget(limits))).page(limits.maxEvidenceBytesPerPage);
  const resources = new ResourceCollector({
    maxScripts: limits.maxScriptsPerPage,
    maxInlineChars: limits.maxInlineScriptBytes,
    maxBlobBase64Chars: Math.ceil((limits.maxResourceBytes * 4) / 3) + 4,
    maxEntries: 1000,
    maxReportCalls: limits.maxReportCallsPerPage,
    budget,
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
      budget,
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
    // One wall-clock budget for all frames, never past the scan deadline: a
    // page with many hung frames must not push the worker past the time at
    // which the coordinator kills it (which would lose every site's evidence).
    let frames: FrameEvidence[] = [];
    let snapshotScripts: DomScriptEvidence[] = [];
    let framesNotInspected = 0;
    if (state.status !== 'failed') {
      const snap = await snapshotFrames(page, Math.min(request.deadline, Date.now() + SNAPSHOT_BUDGET_MS), limits, budget);
      frames = snap.frames;
      snapshotScripts = snap.scripts;
      framesNotInspected = snap.notInspected;
      if (snap.notInspected > 0) {
        issues.push({
          level: 'error',
          code: 'frames-not-inspected',
          message: `${snap.notInspected} of ${snap.total} frames were not inspected by the end-of-scan DOM snapshot (time budget, frame limit or timeout); inline scripts in them may be missing`,
        });
        degrade('partial');
      }
      if (snap.failures.length > 0) {
        issues.push({
          level: 'warning',
          code: 'frame-snapshot-failed',
          message: `Could not inspect ${snap.failures.length} frames (e.g. detached): ${snap.failures.slice(0, 3).join('; ')}`.slice(0, 4_000),
        });
      }
      if (snap.scriptsDropped > 0) resources.scriptsDropped += snap.scriptsDropped;
    }

    // PCI DSS 11.6.1: structure of the forms on sensitive pages (see form-snapshot.ts).
    const formSnapshot = request.page.sensitive && state.status !== 'failed' ? await captureFormSnapshot(page, Math.min(request.deadline, Date.now() + 10_000)) : undefined;

    // --- Optional screenshot ---------------------------------------------
    let screenshotBase64: string | undefined;
    if (scan.captureScreenshots && state.status !== 'failed') {
      try {
        const png = await page.screenshot({ type: 'png', fullPage: false, timeout: 10_000 });
        if (base64Length(png.length) < MAX_SCREENSHOT_BASE64) {
          if (budget.tryReserve(base64Length(png.length))) screenshotBase64 = png.toString('base64');
          else issues.push({ level: 'warning', code: 'screenshot-budget', message: 'Screenshot not stored: the evidence budget was exhausted' });
        }
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
      issues.push({
        level: 'error',
        code: 'script-limit',
        message: `${scriptsDropped} scripts were not recorded (limits.maxScriptsPerPage or the evidence budget was reached)`,
      });
      degrade('partial');
    }

    const scriptResponses = [...net.scriptResponses];
    if (request.serviceWorkers.strategy === 'block' && request.serviceWorkers.probeBlockedRegistrations) {
      const probed = await probeServiceWorkers(context, resources, request, issues, budget);
      scriptResponses.push(...probed);
    }

    const dropped = reportDrops({ net, resources, budget, scriptResponses, framesNotInspected, limits, issues, degrade });

    const headersArray = docResponse ? await docResponse.headersArray().catch(() => []) : [];
    const docHeaders = docResponse ? await docResponse.allHeaders().catch(() => ({})) : {};
    const cspHeaders = headersArray
      .filter((h) => h.name.toLowerCase() === 'content-security-policy')
      .map((h) => h.value.slice(0, 65_536))
      .slice(0, 32);
    const cspReportOnlyHeaders = headersArray
      .filter((h) => h.name.toLowerCase() === 'content-security-policy-report-only')
      .map((h) => h.value.slice(0, 65_536))
      .slice(0, 32);

    log.debug({ status: state.status, scripts: scriptResponses.length, dom: resources.domScripts.length + snapshotScripts.length }, 'page scanned');

    return compact<PageEvidence>({
      pageKey: request.page.key,
      pageUrl: request.page.url,
      finalUrl: clampUrl(finalUrl),
      sensitive: request.page.sensitive,
      status: state.status,
      issues: capIssues(issues),
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
      formSnapshot,
      dropped,
      evidenceBytes: budget.used,
    });
  } catch (error) {
    log.warn({ err: messageOf(error) }, 'page scan failed unexpectedly');
    return failedPage(request, startedAt, capIssues([...issues, { level: 'error', code: 'scan-error', message: messageOf(error) }]));
  } finally {
    await withTimeout(context.close(), 15_000).catch(() => undefined);
  }
}

interface FrameSnapshotResult {
  readonly frames: FrameEvidence[];
  readonly scripts: DomScriptEvidence[];
  /** Total frames on the page. */
  readonly total: number;
  /** Frames not inspected: over the frame limit, out of time, or timed out. */
  readonly notInspected: number;
  /** Non-timeout failures (typically frames detached during the snapshot). */
  readonly failures: string[];
  readonly scriptsDropped: number;
}

/**
 * Snapshot the script elements of every frame. The whole snapshot shares one
 * wall-clock budget (`until`), checked before every frame, so a page with
 * many hung frames cannot keep the worker busy past the scan deadline.
 */
async function snapshotFrames(page: Page, until: number, limits: Limits, budget: PageEvidenceBudget): Promise<FrameSnapshotResult> {
  const all = page.frames();
  const frames: FrameEvidence[] = [];
  const scripts: DomScriptEvidence[] = [];
  const failures: string[] = [];
  let notInspected = Math.max(0, all.length - MAX_SNAPSHOT_FRAMES);
  let scriptsDropped = 0;
  const mainFrame = page.mainFrame();
  for (const frame of all.slice(0, MAX_SNAPSHOT_FRAMES)) {
    let frameUrl: string;
    try {
      frameUrl = clampUrl(frame.url());
      frames.push(compact<FrameEvidence>({ url: frameUrl, parentUrl: optionalUrl(frame.parentFrame()?.url()), name: frame.name().slice(0, 256) || undefined }));
    } catch {
      notInspected++;
      continue;
    }
    const left = until - Date.now();
    if (left < 250) {
      notInspected++;
      continue;
    }
    try {
      const raw = await withTimeout(
        frame.evaluate<unknown>(`(${SNAPSHOT_SCRIPT})(${limits.maxInlineScriptBytes})`),
        Math.min(FRAME_SNAPSHOT_TIMEOUT_MS, left),
      );
      const { items, total } = snapshotPayload(raw);
      const ts = new Date().toISOString();
      const isMain = frame === mainFrame;
      scriptsDropped += Math.max(0, total - items.length);
      for (const item of items) {
        if (scripts.length >= limits.maxScriptsPerPage) {
          scriptsDropped++;
          continue;
        }
        const evidence = snapshotItem(item, frameUrl, isMain, ts, limits.maxInlineScriptBytes, budget);
        if (evidence === null) scriptsDropped++;
        else if (evidence) scripts.push(evidence);
      }
    } catch (error) {
      if (/timed out after/.test(messageOf(error))) notInspected++;
      else failures.push(`${redactUrl(frameUrl)}: ${messageOf(error)}`);
    }
  }
  return { frames, scripts, total: all.length, notInspected, failures, scriptsDropped };
}

function optionalUrl(raw: string | undefined): string | undefined {
  return raw === undefined ? undefined : clampUrl(raw);
}

/** Accept both the current `{ items, total }` payload and a bare array. */
function snapshotPayload(raw: unknown): { items: unknown[]; total: number } {
  if (Array.isArray(raw)) return { items: raw, total: raw.length };
  if (raw && typeof raw === 'object') {
    const r = raw as { items?: unknown; total?: unknown };
    const items = Array.isArray(r.items) ? r.items : [];
    const total = typeof r.total === 'number' && Number.isFinite(r.total) ? Math.min(Math.max(items.length, Math.floor(r.total)), 1e9) : items.length;
    return { items, total };
  }
  return { items: [], total: 0 };
}

/** Returns `undefined` for malformed items and `null` when the evidence budget refused the record. */
function snapshotItem(
  raw: unknown,
  frameUrl: string,
  isMainFrame: boolean,
  timestamp: string,
  maxInline: number,
  budget: PageEvidenceBudget,
): DomScriptEvidence | undefined | null {
  if (!raw || typeof raw !== 'object') return undefined;
  const m = raw as Record<string, unknown>;
  const s = (v: unknown, max: number): string | undefined => (typeof v === 'string' ? v.slice(0, max) : undefined);
  const b = (v: unknown): boolean | undefined => (typeof v === 'boolean' ? v : undefined);
  const kind = m.kind === 'external' ? 'external' : 'inline';
  const src = s(m.src, 16_384);
  if (kind === 'external' && !src) return undefined;
  const record = compact<DomScriptEvidence>({
    kind,
    src,
    type: s(m.type, 128),
    textBytes: typeof m.textBytes === 'number' && Number.isFinite(m.textBytes) ? Math.max(0, Math.floor(m.textBytes)) : undefined,
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
  if (!budget.tryReserve(jsonSize(record) + 64, 'meta')) return null;
  if (kind === 'inline') {
    const text = s(m.text, maxInline) ?? '';
    if (budget.tryReserve(jsonSize(text))) {
      record.text = text;
      record.textTruncated = b(m.textTruncated) ?? false;
    } else {
      record.text = '';
      record.textTruncated = true;
      record.textStatus = 'budget-exceeded';
    }
  }
  return record;
}

interface DropReport {
  readonly net: { urlsTruncated: number; bodiesOverBudget: number };
  readonly resources: ResourceCollector;
  readonly budget: PageEvidenceBudget;
  readonly scriptResponses: readonly ScriptResponseEvidence[];
  readonly framesNotInspected: number;
  readonly limits: Limits;
  readonly issues: Issue[];
  readonly degrade: (to: PageStatus) => void;
}

/**
 * Turn every "observed but not recorded" counter into an explicit issue and
 * mark the page partial whenever JavaScript evidence may have been lost.
 */
function reportDrops(r: DropReport): DroppedEvidence {
  const { resources, budget, issues, degrade } = r;
  const mib = (n: number): string => `${Math.round((n / (1024 * 1024)) * 10) / 10} MiB`;
  if (budget.refused > 0) {
    issues.push({
      level: 'error',
      code: 'evidence-budget',
      message:
        `${budget.refused} bodies, texts or records were not stored because the evidence budget was exhausted ` +
        `(${budget.scanExhausted ? 'per scan: limits.maxEvidenceBytesPerScan' : `per page: limits.maxEvidenceBytesPerPage = ${mib(r.limits.maxEvidenceBytesPerPage)}`}); ` +
        `affected content is recorded as "budget-exceeded"`,
    });
    degrade('partial');
  }
  if (resources.reportCallsDropped > 0 || resources.reportItemsIgnored > 0) {
    issues.push({
      level: 'error',
      code: 'report-budget',
      message: `The page made more than limits.maxReportCallsPerPage (${r.limits.maxReportCallsPerPage}) calls to the in-page reporting channel; ${resources.reportCallsDropped} calls and ${resources.reportItemsIgnored} oversized-batch items were ignored`,
    });
    degrade('partial');
  }
  if (resources.inPageReportsDropped > 0) {
    issues.push({
      level: 'error',
      code: 'instrumentation-report-limit',
      message: `The in-page instrumentation discarded ${resources.inPageReportsDropped} reports (per-frame report limit); script elements, blobs or workers may be missing`,
    });
    degrade('partial');
  }
  if (resources.blobsDropped > 0) {
    issues.push({ level: 'error', code: 'blob-limit', message: `${resources.blobsDropped} JavaScript blob reports exceeded the per-page limit and were not recorded` });
    degrade('partial');
  }
  if (resources.workersDropped > 0) {
    issues.push({ level: 'error', code: 'worker-limit', message: `${resources.workersDropped} worker reports exceeded the per-page limit and were not recorded` });
    degrade('partial');
  }
  // blob: URLs used as a script/worker source whose content neither the hook
  // nor the network layer captured.
  const capturedFromNetwork = new Set(r.scriptResponses.filter((x) => x.bodyStatus === 'captured').map((x) => x.url));
  const capturedFromHook = new Set(resources.blobs.filter((b) => b.textBase64 !== undefined).map((b) => b.blobUrl));
  const missed = [...resources.missedBlobUrls].filter((u) => !capturedFromNetwork.has(u) && !capturedFromHook.has(u));
  if (missed.length > 0) {
    issues.push({
      level: 'error',
      code: 'blob-not-captured',
      message: `${missed.length} blob: URLs were used as a script or worker source but their content could not be captured`,
    });
    degrade('partial');
  }
  if (resources.untrackedBlobs > 0) {
    // Not JavaScript when created; only matters if later used as a script,
    // which is then reported as blob-not-captured above.
    issues.push({ level: 'info', code: 'blob-registry-full', message: `${resources.untrackedBlobs} non-JavaScript blobs were not tracked by the in-page instrumentation (registry full)` });
  }
  if (r.net.urlsTruncated > 0) {
    issues.push({ level: 'warning', code: 'url-truncated', message: `${r.net.urlsTruncated} URLs longer than 16384 characters were truncated` });
  }
  return compact<DroppedEvidence>({
    blobs: resources.blobsDropped || undefined,
    workers: resources.workersDropped || undefined,
    reportCalls: resources.reportCallsDropped || undefined,
    inPageReports: resources.inPageReportsDropped || undefined,
    untrackedBlobs: resources.untrackedBlobs || undefined,
    budgetExceeded: budget.refused || undefined,
    framesNotInspected: r.framesNotInspected || undefined,
  });
}

/** Keep the number of issues within the evidence schema limit, summarising the rest. */
function capIssues(issues: Issue[]): Issue[] {
  if (issues.length <= MAX_PAGE_ISSUES) return issues;
  const kept = issues.slice(0, MAX_PAGE_ISSUES - 1);
  kept.push({ level: 'warning', code: 'issues-truncated', message: `${issues.length - kept.length} further issues were not recorded` });
  return kept;
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
  budget: PageEvidenceBudget,
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
      const overBudget = !tooLarge && !budget.tryReserve(base64Length(body.length));
      out.push(
        compact<ScriptResponseEvidence>({
          url: clampUrl(response.url()),
          redirectChain: [],
          method: 'GET',
          requestResourceType: 'service-worker-probe',
          status: response.status(),
          contentType: headers['content-type'],
          responseHeaders: filterResponseHeaders(headers),
          bodyStatus: tooLarge ? 'too-large' : overBudget ? 'budget-exceeded' : 'captured',
          bodyBase64: tooLarge || overBudget ? undefined : body.toString('base64'),
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
