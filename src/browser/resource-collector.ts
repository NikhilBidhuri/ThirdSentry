import type { BrowserContext, Frame, Page, Worker } from 'playwright';

interface BindingSource {
  readonly frame: Frame;
  readonly page: Page;
  readonly context: BrowserContext;
}
import { REPORT_BINDING } from './init-script.js';
import type { BlobEvidence, DomScriptEvidence, WorkerEvidence } from '../types/evidence.js';
import { compact } from '../utils/object.js';

/**
 * Receives reports from the in-page instrumentation (script elements, blobs,
 * worker constructions) and Playwright worker events.
 *
 * Messages from the page are untrusted: they are shape-checked and
 * size-limited here, and the frame URL is taken from Playwright (not from the
 * message) whenever possible.
 */

export interface ResourceCollectorOptions {
  readonly maxScripts: number;
  readonly maxInlineChars: number;
  readonly maxBlobBase64Chars: number;
  readonly maxEntries: number;
}

type Json = Record<string, unknown>;

const str = (v: unknown, max: number): string | undefined => (typeof v === 'string' ? v.slice(0, max) : undefined);
const bool = (v: unknown): boolean | undefined => (typeof v === 'boolean' ? v : undefined);
const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : undefined);


export class ResourceCollector {
  readonly domScripts: DomScriptEvidence[] = [];
  readonly blobs: BlobEvidence[] = [];
  readonly workers: WorkerEvidence[] = [];
  scriptsDropped = 0;
  private readonly options: ResourceCollectorOptions;
  private page: Page | undefined;

  constructor(options: ResourceCollectorOptions) {
    this.options = options;
  }

  /** Must be called before any page is created in the context. */
  async install(context: BrowserContext): Promise<void> {
    await context.exposeBinding(REPORT_BINDING, (source: BindingSource, batch: unknown) => {
      this.handleBatch(source, batch);
    });
    context.on('serviceworker', (worker: Worker) => {
      this.addWorker({ url: worker.url(), kind: 'service-worker', source: 'playwright-event', timestamp: new Date().toISOString() });
    });
  }

  attachPage(page: Page): void {
    this.page = page;
    page.on('worker', (worker: Worker) => {
      this.addWorker({ url: worker.url(), kind: 'dedicated-worker', source: 'playwright-event', timestamp: new Date().toISOString() });
    });
  }

  addWorker(worker: WorkerEvidence): void {
    if (this.workers.length >= this.options.maxEntries) return;
    this.workers.push(worker);
  }

  private handleBatch(source: BindingSource, batch: unknown): void {
    if (!Array.isArray(batch)) return;
    let frameUrl: string;
    let isMainFrame: boolean;
    try {
      frameUrl = source.frame.url();
      isMainFrame = this.page !== undefined && source.frame === this.page.mainFrame();
    } catch {
      return;
    }
    for (const raw of batch.slice(0, 1000)) {
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
    const text = str(msg.text, this.options.maxInlineChars);
    const src = str(msg.src, 16_384);
    if (kind === 'external' && !src) return;
    this.domScripts.push(
      compact<DomScriptEvidence>({
        kind,
        src,
        type: str(msg.type, 128),
        text: kind === 'inline' ? (text ?? '') : undefined,
        textTruncated: kind === 'inline' ? (bool(msg.textTruncated) ?? false) || (typeof msg.text === 'string' && msg.text.length > this.options.maxInlineChars) : undefined,
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
      }),
    );
  }

  private handleBlob(msg: Json, frameUrl: string, isMainFrame: boolean, timestamp: string): void {
    if (this.blobs.length >= this.options.maxEntries) return;
    const blobUrl = str(msg.blobUrl, 2048);
    if (!blobUrl?.startsWith('blob:')) return;
    const b64 = str(msg.textBase64, this.options.maxBlobBase64Chars + 1);
    const tooLong = b64 !== undefined && b64.length > this.options.maxBlobBase64Chars;
    this.blobs.push(
      compact<BlobEvidence>({
        blobUrl,
        mimeType: str(msg.mimeType, 256) ?? '',
        size: num(msg.size) ?? 0,
        textBase64: tooLong ? undefined : b64,
        truncated: (bool(msg.truncated) ?? false) || tooLong,
        frameUrl,
        isMainFrame,
        timestamp,
      }),
    );
  }

  private handleWorker(msg: Json, frameUrl: string, timestamp: string): void {
    const url = str(msg.url, 16_384);
    if (!url) return;
    const kind = msg.kind === 'service-worker' ? 'service-worker' : msg.kind === 'shared-worker' ? 'shared-worker' : 'dedicated-worker';
    const source = msg.source === 'registration-hook' ? 'registration-hook' : 'constructor-hook';
    this.addWorker(compact<WorkerEvidence>({ url, kind, source, frameUrl, scope: str(msg.scope, 16_384), timestamp }));
  }
}
