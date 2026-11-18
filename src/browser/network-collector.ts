import type { BrowserContext, Frame, Page, Request, Response } from 'playwright';
import { filterResponseHeaders, redactText } from '../security/redaction.js';
import type { RequestEvidence, ScriptResponseEvidence } from '../types/evidence.js';

/**
 * Observes network activity of a page from *outside* the page (Playwright
 * protocol events), which hostile page scripts cannot tamper with.
 *
 *  - Every request is recorded (up to a limit) for outbound-destination
 *    monitoring. URLs are stored as observed here and redacted by the trusted
 *    analyser before persisting.
 *  - Responses that look like executable code (JavaScript, WebAssembly) have
 *    their bodies captured, subject to a size limit, for hashing.
 */

export interface NetworkCollectorOptions {
  readonly maxRequests: number;
  readonly maxScripts: number;
  readonly maxResourceBytes: number;
  readonly bodyTimeoutMs: number;
}

const SCRIPT_CONTENT_TYPE = /(java|ecma)script|\bjscript\b|application\/wasm|text\/x-javascript/i;
const SCRIPT_EXTENSION = /\.(m?js|cjs|wasm)$/i;

export function isScriptLikeResponse(resourceType: string, contentType: string | undefined, url: string): boolean {
  if (resourceType === 'script') return true;
  if (contentType && SCRIPT_CONTENT_TYPE.test(contentType)) return true;
  if (resourceType === 'document' || resourceType === 'stylesheet' || resourceType === 'image' || resourceType === 'font' || resourceType === 'media') {
    return false;
  }
  try {
    return SCRIPT_EXTENSION.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

function safeFrame(request: Request): Frame | undefined {
  try {
    return request.frame();
  } catch {
    // Service worker requests have no frame.
    return undefined;
  }
}

function redirectChain(request: Request): string[] {
  const chain: string[] = [];
  let current = request.redirectedFrom();
  let guard = 0;
  while (current && guard < 50) {
    chain.unshift(current.url());
    current = current.redirectedFrom();
    guard++;
  }
  return chain;
}

export class NetworkCollector {
  private readonly options: NetworkCollectorOptions;
  private readonly page: Page;
  private readonly requests = new Map<Request, RequestEvidence>();
  private readonly scriptResponses: ScriptResponseEvidence[] = [];
  private readonly pending = new Set<Promise<void>>();
  private requestsDropped = 0;
  private scriptsDropped = 0;
  private scriptCount = 0;
  private detachers: Array<() => void> = [];

  constructor(page: Page, options: NetworkCollectorOptions) {
    this.page = page;
    this.options = options;
  }

  attach(context: BrowserContext): void {
    const onRequest = (request: Request): void => this.onRequest(request, false);
    const onResponse = (response: Response): void => this.onResponse(response, 'page-network');
    const onFailed = (request: Request): void => {
      const rec = this.requests.get(request);
      if (rec) rec.failure = redactText(request.failure()?.errorText ?? 'request failed', 300);
    };
    // Service-worker originated traffic (Chromium only) is reported on the context.
    const onContextRequest = (request: Request): void => {
      if (request.serviceWorker()) this.onRequest(request, true);
    };
    const onContextResponse = (response: Response): void => {
      if (response.request().serviceWorker()) this.onResponse(response, 'context-network');
    };
    this.page.on('request', onRequest);
    this.page.on('response', onResponse);
    this.page.on('requestfailed', onFailed);
    context.on('request', onContextRequest);
    context.on('response', onContextResponse);
    context.on('requestfailed', onFailed);
    this.detachers.push(() => {
      this.page.off('request', onRequest);
      this.page.off('response', onResponse);
      this.page.off('requestfailed', onFailed);
      context.off('request', onContextRequest);
      context.off('response', onContextResponse);
      context.off('requestfailed', onFailed);
    });
  }

  private onRequest(request: Request, viaContext: boolean): void {
    if (this.requests.has(request)) return;
    if (this.requests.size >= this.options.maxRequests) {
      this.requestsDropped++;
      return;
    }
    const frame = safeFrame(request);
    const sw = request.serviceWorker();
    const from = request.redirectedFrom();
    const rec: RequestEvidence = {
      url: request.url(),
      method: request.method(),
      resourceType: request.resourceType(),
      isMainFrame: frame !== undefined && frame === this.page.mainFrame(),
      isNavigation: request.isNavigationRequest(),
      fromServiceWorker: viaContext || sw !== null,
      timestamp: new Date().toISOString(),
      ...(frame ? { frameUrl: frame.url() } : {}),
      ...(from ? { redirectedFrom: from.url() } : {}),
      ...(sw ? { workerUrl: sw.url() } : {}),
    };
    this.requests.set(request, rec);
  }

  private onResponse(response: Response, source: ScriptResponseEvidence['source']): void {
    const request = response.request();
    const rec = this.requests.get(request);
    if (rec) rec.status = response.status();
    const status = response.status();
    if (status >= 300 && status < 400) return; // redirect hop: recorded via the final response's chain
    const task = this.captureScript(response, source).catch(() => undefined);
    this.pending.add(task);
    void task.finally(() => this.pending.delete(task));
  }

  private async captureScript(response: Response, source: ScriptResponseEvidence['source']): Promise<void> {
    const request = response.request();
    const headers = await response.allHeaders().catch(() => response.headers());
    const contentType = headers['content-type'];
    if (!isScriptLikeResponse(request.resourceType(), contentType, response.url())) return;
    if (this.scriptCount >= this.options.maxScripts) {
      this.scriptsDropped++;
      return;
    }
    this.scriptCount++;
    const frame = safeFrame(request);
    const sw = request.serviceWorker();
    const declared = Number(headers['content-length']);
    const requestHeaders = await request.allHeaders().catch(() => request.headers());
    const fetchDest = requestHeaders['sec-fetch-dest']?.slice(0, 32);
    const fetchMode = requestHeaders['sec-fetch-mode']?.slice(0, 32);
    const evidence: ScriptResponseEvidence = {
      url: response.url(),
      redirectChain: redirectChain(request),
      method: request.method(),
      requestResourceType: request.resourceType(),
      status: response.status(),
      responseHeaders: filterResponseHeaders(headers),
      bodyStatus: 'not-attempted',
      isMainFrame: frame !== undefined && frame === this.page.mainFrame(),
      fromServiceWorker: response.fromServiceWorker() || sw !== null,
      source,
      timestamp: new Date().toISOString(),
      ...(contentType ? { contentType } : {}),
      ...(fetchDest ? { fetchDest } : {}),
      ...(fetchMode ? { fetchMode } : {}),
      ...(frame ? { frameUrl: frame.url() } : {}),
      ...(sw ? { workerUrl: sw.url() } : {}),
    };
    if (Number.isFinite(declared) && declared > this.options.maxResourceBytes) {
      evidence.bodyStatus = 'too-large';
      evidence.bodyBytes = declared;
      evidence.bodyNote = `Declared size ${declared} bytes exceeds limits.maxResourceBytes (${this.options.maxResourceBytes})`;
    } else {
      try {
        const body = await withTimeout(response.body(), this.options.bodyTimeoutMs);
        if (body.length > this.options.maxResourceBytes) {
          evidence.bodyStatus = 'too-large';
          evidence.bodyBytes = body.length;
          evidence.bodyNote = `Body size ${body.length} bytes exceeds limits.maxResourceBytes (${this.options.maxResourceBytes})`;
        } else {
          evidence.bodyStatus = 'captured';
          evidence.bodyBytes = body.length;
          evidence.bodyBase64 = body.toString('base64');
        }
      } catch (error) {
        evidence.bodyStatus = 'unavailable';
        evidence.bodyNote = redactText(error instanceof Error ? error.message.split('\n')[0] ?? 'body unavailable' : 'body unavailable', 300);
      }
    }
    this.scriptResponses.push(evidence);
  }

  /** Wait (bounded) for in-flight body captures and detach listeners. */
  async finalize(timeoutMs: number): Promise<{
    requests: RequestEvidence[];
    scriptResponses: ScriptResponseEvidence[];
    requestsDropped: number;
    scriptsDropped: number;
    pendingAbandoned: number;
  }> {
    const deadline = Date.now() + timeoutMs;
    while (this.pending.size > 0 && Date.now() < deadline) {
      await Promise.race([Promise.allSettled([...this.pending]), delay(Math.max(0, deadline - Date.now()))]);
    }
    const abandoned = this.pending.size;
    for (const d of this.detachers) d();
    this.detachers = [];
    return {
      requests: [...this.requests.values()],
      scriptResponses: [...this.scriptResponses],
      requestsDropped: this.requestsDropped,
      scriptsDropped: this.scriptsDropped,
      pendingAbandoned: abandoned,
    };
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms`)), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
