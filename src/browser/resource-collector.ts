import type { BrowserContext, Frame, Page, Worker } from 'playwright';

interface BindingSource {
  readonly frame: Frame;
  readonly page: Page;
  readonly context: BrowserContext;
}
import { REPORT_BINDING } from './init-script.js';
import type { BlobEvidence, DomScriptEvidence, WorkerEvidence } from '../types/evidence.js';
import { compact } from '../utils/object.js';
import { clampUrl, jsonSize, type PageEvidenceBudget } from './evidence-budget.js';

/**
 * Receives reports from the in-page instrumentation (script elements, blobs,
 * worker constructions) and Playwright worker events.
 *
 * Messages from the page are untrusted: they are shape-checked and
 * size-limited here, and the frame URL is taken from Playwright (not from the
 * message) whenever possible. The page decides how often it calls the
 * binding and how much it sends, so calls, entries and bytes are all
 * budgeted, and everything that is not recorded is counted so the page can be
 * marked partial instead of silently losing evidence.
 */

export interface ResourceCollectorOptions {
  readonly maxScripts: number;
  readonly maxInlineChars: number;
  readonly maxBlobBase64Chars: number;
  readonly maxEntries: number;
  /** Binding calls accepted per page (limits.maxReportCallsPerPage). */
  readonly maxReportCalls?: number;
  /** Evidence byte budget for this page. */
  readonly budget?: PageEvidenceBudget;
}

type Json = Record<string, unknown>;

/** Items processed from a single binding call; the rest is counted as ignored. */
const MAX_BATCH_ITEMS = 10_000;
/** Blob URLs remembered as "referenced as script but content not captured". */
const MAX_MISSED_BLOBS = 100;

const str = (v: unknown, max: number): string | undefined => (typeof v === 'string' ? v.slice(0, max) : undefined);
const bool = (v: unknown): boolean | undefined => (typeof v === 'boolean' ? v : undefined);
const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : undefined);

interface InPageStats {
  reportsDropped: number;
  untrackedBlobs: number;
}

export class ResourceCollector {
  readonly domScripts: DomScriptEvidence[] = [];
  readonly blobs: BlobEvidence[] = [];
  readonly workers: WorkerEvidence[] = [];
  scriptsDropped = 0;
  blobsDropped = 0;
  workersDropped = 0;
  /** Binding calls ignored because limits.maxReportCallsPerPage was reached. */
  reportCallsDropped = 0;
  /** Report items ignored because a single call carried too many. */
  reportItemsIgnored = 0;
  /** Inline texts / blob contents not stored because the evidence budget was exhausted. */
  contentOverBudget = 0;
  /** blob: URLs used as script/worker source whose content the in-page hook could not capture. */
  readonly missedBlobUrls = new Set<string>();
  private reportCalls = 0;
  private readonly inPageStats = new Map<Frame, InPageStats>();
  private options: ResourceCollectorOptions;
  private page: Page | undefined;

  constructor(options: ResourceCollectorOptions) {
    this.options = options;
  }

  /**
   * Start a new observation segment (journeys: the span between two captures)
   * on the same context: recorded items and counters are cleared and later
   * items are charged to `budget`. The binding and listeners stay installed.
   */
  reset(budget?: PageEvidenceBudget): void {
    this.domScripts.length = 0;
    this.blobs.length = 0;
    this.workers.length = 0;
    this.missedBlobUrls.clear();
    this.inPageStats.clear();
    this.scriptsDropped = 0;
    this.blobsDropped = 0;
    this.workersDropped = 0;
    this.reportCallsDropped = 0;
    this.reportItemsIgnored = 0;
    this.contentOverBudget = 0;
    this.reportCalls = 0;
    if (budget) this.options = { ...this.options, budget };
  }

  /** Reports the in-page instrumentation discarded itself, summed over frames. */
  get inPageReportsDropped(): number {
    let n = 0;
    for (const s of this.inPageStats.values()) n += s.reportsDropped;
    return n;
  }

  /** Blobs the in-page instrumentation stopped tracking (registry full), summed over frames. */
  get untrackedBlobs(): number {
    let n = 0;
    for (const s of this.inPageStats.values()) n += s.untrackedBlobs;
    return n;
  }

  /** Must be called before any page is created in the context. */
  async install(context: BrowserContext): Promise<void> {
    await context.exposeBinding(REPORT_BINDING, (source: BindingSource, batch: unknown) => {
      this.reportCalls++;
      if (this.reportCalls > (this.options.maxReportCalls ?? Number.POSITIVE_INFINITY)) {
        this.reportCallsDropped++;
        return;
      }
      this.handleBatch(source, batch);
    });
    context.on('serviceworker', (worker: Worker) => {
      this.addWorker({ url: clampUrl(worker.url()), kind: 'service-worker', source: 'playwright-event', timestamp: new Date().toISOString() });
    });
  }

  attachPage(page: Page): void {
    this.page = page;
    page.on('worker', (worker: Worker) => {
      this.addWorker({ url: clampUrl(worker.url()), kind: 'dedicated-worker', source: 'playwright-event', timestamp: new Date().toISOString() });
    });
  }

  addWorker(worker: WorkerEvidence): void {
    if (this.workers.length >= this.options.maxEntries || (this.options.budget && !this.options.budget.tryReserve(jsonSize(worker), 'meta'))) {
      this.workersDropped++;
      return;
    }
    this.workers.push(worker);
  }

  private handleBatch(source: BindingSource, batch: unknown): void {
    if (!Array.isArray(batch)) return;
    let frameUrl: string;
    let isMainFrame: boolean;
    try {
      frameUrl = clampUrl(source.frame.url());
      isMainFrame = this.page !== undefined && source.frame === this.page.mainFrame();
    } catch {
      return;
    }
    if (batch.length > MAX_BATCH_ITEMS) this.reportItemsIgnored += batch.length - MAX_BATCH_ITEMS;
    for (const raw of batch.slice(0, MAX_BATCH_ITEMS)) {
      if (!raw || typeof raw !== 'object') continue;
      const msg = raw as Json;
      const timestamp = new Date().toISOString();
      switch (msg.t) {
        case 'script':
          this.handleScript(msg, frameUrl, isMainFrame, timestamp);
          break;
        case 'blob':
          this.handleBlob(msg, frameUrl, isMainFrame, timestamp);
          break;
        case 'worker':
          this.handleWorker(msg, frameUrl, timestamp);
          break;
        case 'stats':
          this.handleStats(msg, source.frame);
          break;
        default:
          break;
      }
    }
  }

  private handleScript(msg: Json, frameUrl: string, isMainFrame: boolean, timestamp: string): void {
    if (this.domScripts.length >= this.options.maxScripts) {
      this.scriptsDropped++;
      return;
    }
    const kind = msg.kind === 'external' ? 'external' : 'inline';
    const src = str(msg.src, 16_384);
    if (kind === 'external' && !src) return;
    const record = compact<DomScriptEvidence>({
      kind,
      src,
      type: str(msg.type, 128),
      textBytes: num(msg.textBytes),
      domPath: str(msg.domPath, 1024) ?? 'unknown',
      frameUrl,
      isMainFrame,
      async: bool(msg.async),
      defer: bool(msg.defer),
      integrity: str(msg.integrity, 1024),
      crossOrigin: str(msg.crossOrigin, 64),
      hasNonce: bool(msg.hasNonce),
      insertedByScript: bool(msg.insertedByScript) ?? false,
      viaDocumentWrite: bool(msg.viaDocumentWrite),
      observedVia: 'mutation',
      timestamp,
    });
    const budget = this.options.budget;
    if (budget && !budget.tryReserve(jsonSize(record) + 64, 'meta')) {
      this.scriptsDropped++;
      return;
    }
    if (kind === 'inline') {
      const text = str(msg.text, this.options.maxInlineChars) ?? '';
      const truncated = (bool(msg.textTruncated) ?? false) || (typeof msg.text === 'string' && msg.text.length > this.options.maxInlineChars);
      // jsonSize accounts for escaping (a control character costs 6 bytes).
      if (budget && !budget.tryReserve(jsonSize(text))) {
        this.contentOverBudget++;
        record.text = '';
        record.textTruncated = true;
        record.textStatus = 'budget-exceeded';
      } else {
        record.text = text;
        record.textTruncated = truncated;
      }
    }
    this.domScripts.push(record);
  }

  private handleBlob(msg: Json, frameUrl: string, isMainFrame: boolean, timestamp: string): void {
    const blobUrl = str(msg.blobUrl, 2048);
    if (!blobUrl?.startsWith('blob:')) return;
    if (msg.missed === true) {
      // The hook saw this blob URL used as a script/worker source but did not
      // hold the Blob (registry full or created in another realm).
      if (this.missedBlobUrls.size < MAX_MISSED_BLOBS) this.missedBlobUrls.add(blobUrl);
      return;
    }
    const record = compact<BlobEvidence>({
      blobUrl,
      mimeType: str(msg.mimeType, 256) ?? '',
      size: num(msg.size) ?? 0,
      truncated: bool(msg.truncated) ?? false,
      frameUrl,
      isMainFrame,
      timestamp,
    });
    const budget = this.options.budget;
    if (this.blobs.length >= this.options.maxEntries || (budget && !budget.tryReserve(jsonSize(record) + 64, 'meta'))) {
      // Blob reports are only sent for JavaScript-like blobs or blobs used as
      // a script/worker source, so a dropped report is lost JS evidence.
      this.blobsDropped++;
      return;
    }
    const b64 = str(msg.textBase64, this.options.maxBlobBase64Chars + 1);
    const tooLong = b64 !== undefined && b64.length > this.options.maxBlobBase64Chars;
    if (b64 !== undefined && !tooLong) {
      if (budget && !budget.tryReserve(b64.length)) {
        this.contentOverBudget++;
        record.bodyStatus = 'budget-exceeded';
      } else {
        record.textBase64 = b64;
      }
    }
    if (tooLong) record.truncated = true;
    this.blobs.push(record);
  }

  private handleWorker(msg: Json, frameUrl: string, timestamp: string): void {
    const url = str(msg.url, 16_384);
    if (!url) return;
    const kind = msg.kind === 'service-worker' ? 'service-worker' : msg.kind === 'shared-worker' ? 'shared-worker' : 'dedicated-worker';
    const source = msg.source === 'registration-hook' ? 'registration-hook' : 'constructor-hook';
    this.addWorker(compact<WorkerEvidence>({ url, kind, source, frameUrl, scope: str(msg.scope, 16_384), timestamp }));
  }

  /**
   * Cumulative drop counters from the in-page instrumentation of one frame.
   * Page-controlled, so they can only add "partial" signals, never remove any.
   */
  private handleStats(msg: Json, frame: Frame): void {
    const cap = (v: unknown): number => Math.min(num(v) ?? 0, 1e9);
    const prev = this.inPageStats.get(frame) ?? { reportsDropped: 0, untrackedBlobs: 0 };
    this.inPageStats.set(frame, {
      reportsDropped: Math.max(prev.reportsDropped, cap(msg.reportsDropped)),
      untrackedBlobs: Math.max(prev.untrackedBlobs, cap(msg.untrackedBlobs)),
    });
  }
}
