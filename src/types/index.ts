import type { Issue, PageStatus, ProxyEvent } from './evidence.js';

export type { Issue, PageStatus, ProxyEvent } from './evidence.js';

/** Classification of an executable resource. */
export type ResourceType =
  | 'script' // classic external script
  | 'module' // ES module (static import, <script type=module>, or import())
  | 'inline-script'
  | 'inline-module'
  | 'dedicated-worker'
  | 'shared-worker'
  | 'service-worker'
  | 'blob-script' // code loaded from a blob: URL
  | 'data-script' // code loaded from a data: URL
  | 'wasm'
  | 'fetched-script'; // JavaScript fetched via fetch/XHR (may or may not be executed)

export const RESOURCE_TYPES: readonly ResourceType[] = [
  'script',
  'module',
  'inline-script',
  'inline-module',
  'dedicated-worker',
  'shared-worker',
  'service-worker',
  'blob-script',
  'data-script',
  'wasm',
  'fetched-script',
];

export type Party = 'first-party' | 'third-party';

export type ContentStatus = 'captured' | 'truncated' | 'too-large' | 'unavailable' | 'not-attempted';

export type NormalizationStatus = 'normalized' | 'parse-error' | 'not-javascript' | 'unavailable' | 'too-large';

export interface ResourceHashes {
  /** SHA-256 (hex) of the exact bytes received. Null when the body could not be captured. */
  readonly sha256: string | null;
  /** Subresource-Integrity form of the raw hash (sha256-<base64>). */
  readonly sri: string | null;
  /** SHA-256 (hex) of the normalised JavaScript, when parsing succeeded. */
  readonly normalizedSha256: string | null;
  /** Version of the normaliser that produced normalizedSha256. */
  readonly normalizerVersion: string | null;
}

export interface SriCheck {
  readonly attribute: string;
  readonly valid: boolean | null; // null when content was not available to verify
}

export interface ScriptResource {
  /** Unique key within a site scan: identity + raw hash. */
  readonly key: string;
  /** Canonical identity used to match the resource across scans. */
  readonly identity: string;
  readonly type: ResourceType;
  /** URL originally requested (first hop of any redirect chain). Undefined for inline code. */
  readonly originalUrl?: string;
  /** URL of the final response after redirects. */
  readonly finalUrl?: string;
  readonly redirectChain: readonly string[];
  readonly hostname?: string;
  readonly registrableDomain?: string;
  readonly origin?: string;
  readonly party: Party;
  readonly frameContext: 'main-frame' | 'iframe' | 'worker' | 'unknown';
  readonly frameUrls: readonly string[];
  /** Page keys where the resource was observed. */
  readonly pages: readonly string[];
  readonly occurrences: number;
  /** Inserted by script at runtime (not by the HTML parser), or loaded without any script element. */
  readonly dynamic: boolean;
  readonly discovery: readonly string[];
  readonly httpStatus?: number;
  readonly contentType?: string;
  readonly size?: number;
  readonly content: { readonly status: ContentStatus; readonly note?: string };
  readonly hashes: ResourceHashes;
  readonly normalization: { readonly status: NormalizationStatus; readonly error?: string };
  readonly sri?: SriCheck;
  readonly fromServiceWorker: boolean;
  readonly responseHeaders?: Readonly<Record<string, string>>;
  /** For inline scripts: DOM location where it was found. */
  readonly domPath?: string;
  readonly firstSeenAt: string;
  /** Static-analysis indicators (Phase 3). */
  indicators?: IndicatorSummary;
}

export interface IndicatorMatch {
  readonly ruleId: string;
  readonly line: number;
  readonly column: number;
  readonly snippet: string;
  readonly detail?: string;
}

export interface IndicatorSummary {
  readonly analyzed: boolean;
  readonly error?: string;
  /** Map of rule id → number of matches. */
  readonly counts: Readonly<Record<string, number>>;
  /** Up to a few example matches per rule, with short source excerpts. */
  readonly matches: readonly IndicatorMatch[];
  /** Hostnames referenced by the code (URL literals, network calls). */
  readonly hosts: readonly string[];
}

export interface OutboundRequest {
  readonly url: string; // redacted
  readonly method: string;
  readonly hostname: string;
  readonly registrableDomain: string;
  readonly party: Party;
  readonly resourceType: string;
  readonly frameUrl?: string;
  readonly isMainFrame: boolean;
  readonly page: string;
  readonly timestamp: string;
  readonly status?: number;
  readonly failure?: string;
  readonly fromServiceWorker: boolean;
  readonly blocked: boolean;
}

export interface DestinationSummary {
  readonly hostname: string;
  readonly registrableDomain: string;
  readonly party: Party;
  readonly methods: readonly string[];
  readonly resourceTypes: readonly string[];
  readonly requestCount: number;
  readonly pages: readonly string[];
  readonly blocked: boolean;
}

export interface PageResult {
  readonly key: string;
  readonly url: string;
  readonly finalUrl?: string;
  readonly sensitive: boolean;
  readonly status: PageStatus;
  readonly issues: readonly Issue[];
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly documentStatus?: number;
  readonly resourceKeys: readonly string[];
  readonly iframeOrigins: readonly string[];
  readonly requests: readonly OutboundRequest[];
  readonly requestsTruncated: number;
  readonly consoleErrorCount: number;
  readonly pageErrors: readonly string[];
  readonly cspHeaders: readonly string[];
  readonly cspReportOnlyHeaders: readonly string[];
  readonly screenshot?: string;
}

export interface SiteResult {
  readonly name: string;
  readonly url: string;
  readonly profile: string;
  readonly browser: { readonly name: string; readonly version: string; readonly emulation: string };
  readonly status: PageStatus;
  readonly issues: readonly Issue[];
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly pages: readonly PageResult[];
  readonly resources: readonly ScriptResource[];
  readonly destinations: readonly DestinationSummary[];
  readonly domains: {
    readonly scripts: readonly string[];
    readonly outbound: readonly string[];
    readonly iframes: readonly string[];
  };
  readonly blockedConnections: readonly ProxyEvent[];
}

export interface ScanSummary {
  readonly sites: number;
  readonly pages: number;
  readonly pagesComplete: number;
  readonly pagesPartial: number;
  readonly pagesFailed: number;
  readonly resources: number;
  readonly firstPartyResources: number;
  readonly thirdPartyResources: number;
  readonly resourcesWithoutContent: number;
  readonly thirdPartyDomains: number;
  readonly blockedConnections: number;
}

export interface ScanResult {
  readonly schemaVersion: 1;
  readonly kind: 'thirdsentry-scan';
  readonly scanId: string;
  readonly toolVersion: string;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly status: PageStatus;
  readonly isolation: string;
  readonly serviceWorkerStrategy: 'block' | 'allow';
  readonly issues: readonly Issue[];
  readonly summary: ScanSummary;
  readonly sites: readonly SiteResult[];
  readonly coverageLimitations: readonly string[];
}
