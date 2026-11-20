import { z } from 'zod';

/**
 * Evidence produced by the (untrusted) browser worker.
 *
 * Everything in here may have been influenced by hostile page content (DOM
 * data reported by the init script, URLs, header values, console text). The
 * trusted analysis process validates this schema with hard size limits before
 * using any of it, and never treats evidence as instructions.
 */

export const EVIDENCE_SCHEMA_VERSION = 1;

const MAX_URL = 16_384;
const url = z.string().max(MAX_URL);
const shortText = z.string().max(4_096);
const timestamp = z.string().max(64);
const headers = z.record(z.string().max(256), z.string().max(8_192));

/**
 * `budget-exceeded`: the body was available but the per-page or per-scan
 * evidence budget (limits.maxEvidenceBytesPerPage / PerScan) was exhausted,
 * so only metadata was kept. The page is marked partial.
 */
export const BodyStatusSchema = z.enum(['captured', 'too-large', 'unavailable', 'not-attempted', 'budget-exceeded']);

export const ScriptResponseEvidenceSchema = z.object({
  /** URL of the final response (after redirects). */
  url,
  /** Redirect chain, original request URL first, excluding the final URL. */
  redirectChain: z.array(url).max(50),
  method: z.string().max(16),
  /** Playwright resource type (script, fetch, other, ...). */
  requestResourceType: z.string().max(32),
  status: z.number().int().min(0).max(999),
  contentType: z.string().max(512).optional(),
  responseHeaders: headers,
  /** Fetch metadata request headers (Sec-Fetch-Dest / Sec-Fetch-Mode) when sent by the browser. */
  fetchDest: z.string().max(32).optional(),
  fetchMode: z.string().max(32).optional(),
  bodyStatus: BodyStatusSchema,
  bodyBase64: z.string().optional(),
  /** Body size in bytes when known (captured length or declared content-length). */
  bodyBytes: z.number().int().min(0).optional(),
  bodyNote: shortText.optional(),
  frameUrl: url.optional(),
  isMainFrame: z.boolean(),
  fromServiceWorker: z.boolean(),
  /** URL of the worker that issued the request, when known. */
  workerUrl: url.optional(),
  /** How this response was obtained. */
  source: z.enum(['page-network', 'context-network', 'service-worker-probe', 'worker-network']),
  timestamp,
});

export const DomScriptEvidenceSchema = z.object({
  kind: z.enum(['external', 'inline']),
  /** Resolved absolute src for external scripts. */
  src: url.optional(),
  type: z.string().max(128).optional(),
  /** Inline script text (possibly truncated). */
  text: z.string().optional(),
  textTruncated: z.boolean().optional(),
  textBytes: z.number().int().min(0).optional(),
  /** `budget-exceeded` when the inline text was dropped because the evidence budget was exhausted. */
  textStatus: z.enum(['captured', 'budget-exceeded']).optional(),
  domPath: z.string().max(1024),
  frameUrl: url,
  isMainFrame: z.boolean(),
  async: z.boolean().optional(),
  defer: z.boolean().optional(),
  integrity: z.string().max(1024).optional(),
  crossOrigin: z.string().max(64).optional(),
  hasNonce: z.boolean().optional(),
  /** True when inserted through a DOM API call (appendChild etc.) rather than by the HTML parser. */
  insertedByScript: z.boolean(),
  /** True when inserted via document.write. */
  viaDocumentWrite: z.boolean().optional(),
  observedVia: z.enum(['snapshot', 'mutation']),
  timestamp,
});

export const BlobEvidenceSchema = z.object({
  blobUrl: url,
  mimeType: z.string().max(256),
  size: z.number().int().min(0),
  textBase64: z.string().optional(),
  truncated: z.boolean(),
  /** `budget-exceeded` when the content was dropped because the evidence budget was exhausted. */
  bodyStatus: BodyStatusSchema.optional(),
  frameUrl: url,
  isMainFrame: z.boolean().optional(),
  timestamp,
});

export const WorkerEvidenceSchema = z.object({
  url,
  kind: z.enum(['dedicated-worker', 'shared-worker', 'service-worker']),
  frameUrl: url.optional(),
  scope: url.optional(),
  /** How the worker was observed. */
  source: z.enum(['playwright-event', 'registration-hook', 'constructor-hook']),
  /** For service workers under the `block` strategy: registration was blocked. */
  blocked: z.boolean().optional(),
  timestamp,
});

export const RequestEvidenceSchema = z.object({
  url,
  method: z.string().max(16),
  resourceType: z.string().max(32),
  frameUrl: url.optional(),
  isMainFrame: z.boolean(),
  isNavigation: z.boolean(),
  status: z.number().int().min(0).max(999).optional(),
  failure: shortText.optional(),
  redirectedFrom: url.optional(),
  fromServiceWorker: z.boolean(),
  workerUrl: url.optional(),
  timestamp,
});

export const IssueSchema = z.object({
  level: z.enum(['error', 'warning', 'info']),
  code: z.string().max(64),
  message: shortText,
});

export const PageStatusSchema = z.enum(['complete', 'partial', 'failed']);

/** Counters for evidence that was observed but not recorded (each also reported as an issue). */
export const DroppedEvidenceSchema = z
  .object({
    /** Blob reports beyond the per-page entry limit. */
    blobs: z.number().int().min(0),
    /** Worker reports beyond the per-page entry limit. */
    workers: z.number().int().min(0),
    /** Calls to the in-page reporting binding beyond limits.maxReportCallsPerPage. */
    reportCalls: z.number().int().min(0),
    /** Reports the in-page instrumentation itself discarded (its per-frame cap). */
    inPageReports: z.number().int().min(0),
    /** Blobs the in-page instrumentation stopped tracking (registry full). */
    untrackedBlobs: z.number().int().min(0),
    /** Bodies/texts not stored because the evidence budget was exhausted. */
    budgetExceeded: z.number().int().min(0),
    /** Frames whose DOM was not snapshotted (deadline, snapshot budget or timeout). */
    framesNotInspected: z.number().int().min(0),
  })
  .partial();

export const FrameEvidenceSchema = z.object({
  url,
  parentUrl: url.optional(),
  name: z.string().max(256).optional(),
});

export const PageEvidenceSchema = z.object({
  pageKey: z.string().max(MAX_URL),
  pageUrl: url,
  finalUrl: url.optional(),
  sensitive: z.boolean(),
  status: PageStatusSchema,
  issues: z.array(IssueSchema).max(1_000),
  startedAt: timestamp,
  finishedAt: timestamp,
  documentStatus: z.number().int().optional(),
  documentHeaders: headers,
  /** Raw Content-Security-Policy header values on the main document. */
  cspHeaders: z.array(z.string().max(65_536)).max(32),
  cspReportOnlyHeaders: z.array(z.string().max(65_536)).max(32),
  frames: z.array(FrameEvidenceSchema).max(1_000),
  scriptResponses: z.array(ScriptResponseEvidenceSchema),
  domScripts: z.array(DomScriptEvidenceSchema),
  blobs: z.array(BlobEvidenceSchema).max(1_000),
  workers: z.array(WorkerEvidenceSchema).max(1_000),
  requests: z.array(RequestEvidenceSchema),
  requestsDropped: z.number().int().min(0),
  scriptsDropped: z.number().int().min(0),
  consoleErrors: z.array(shortText).max(200),
  pageErrors: z.array(shortText).max(200),
  screenshotBase64: z.string().optional(),
  /** Optional (absent in evidence written by older versions). */
  dropped: DroppedEvidenceSchema.optional(),
  /** Approximate bytes of evidence recorded for this page (budget accounting). */
  evidenceBytes: z.number().int().min(0).optional(),
});

export const ProxyEventSchema = z.object({
  timestamp,
  host: z.string().max(512),
  port: z.number().int(),
  method: z.string().max(16),
  allowed: z.boolean(),
  reason: shortText.optional(),
  code: z.string().max(64).optional(),
  address: z.string().max(64).optional(),
});

export const SiteEvidenceSchema = z.object({
  name: z.string().max(64),
  url,
  profile: z.string().max(64),
  browserName: z.string().max(64),
  browserVersion: z.string().max(64),
  emulation: shortText,
  status: PageStatusSchema,
  issues: z.array(IssueSchema).max(1_000),
  startedAt: timestamp,
  finishedAt: timestamp,
  pages: z.array(PageEvidenceSchema),
  proxyEvents: z.array(ProxyEventSchema),
  proxyEventsDropped: z.number().int().min(0),
});

export const ScanEvidenceSchema = z.object({
  schemaVersion: z.literal(EVIDENCE_SCHEMA_VERSION),
  scanId: z.string().max(128),
  toolVersion: z.string().max(64),
  startedAt: timestamp,
  finishedAt: timestamp,
  isolation: z.enum(['process', 'none', 'container']),
  serviceWorkerStrategy: z.enum(['block', 'allow']),
  sites: z.array(SiteEvidenceSchema),
  issues: z.array(IssueSchema).max(1_000),
});

export type ScriptResponseEvidence = z.infer<typeof ScriptResponseEvidenceSchema>;
export type DomScriptEvidence = z.infer<typeof DomScriptEvidenceSchema>;
export type BlobEvidence = z.infer<typeof BlobEvidenceSchema>;
export type WorkerEvidence = z.infer<typeof WorkerEvidenceSchema>;
export type RequestEvidence = z.infer<typeof RequestEvidenceSchema>;
export type Issue = z.infer<typeof IssueSchema>;
export type PageStatus = z.infer<typeof PageStatusSchema>;
export type PageEvidence = z.infer<typeof PageEvidenceSchema>;
export type ProxyEvent = z.infer<typeof ProxyEventSchema>;
export type SiteEvidence = z.infer<typeof SiteEvidenceSchema>;
export type ScanEvidence = z.infer<typeof ScanEvidenceSchema>;
export type FrameEvidence = z.infer<typeof FrameEvidenceSchema>;
export type DroppedEvidence = z.infer<typeof DroppedEvidenceSchema>;
export type BodyStatus = z.infer<typeof BodyStatusSchema>;
