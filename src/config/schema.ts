import { z } from 'zod';

/**
 * ScriptDrift configuration schema (scriptdrift.yml).
 *
 * All objects are strict: unknown keys are rejected so that typos such as
 * `enable: false` do not silently change behaviour.
 */

export const BROWSER_PROFILES = [
  'desktop-chromium',
  'desktop-firefox',
  'desktop-webkit',
  'mobile-chromium',
  'mobile-webkit',
] as const;

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;

const hostPattern = z
  .string()
  .min(1)
  .regex(/^(\*|(\*\.)?[a-z0-9_.:[\]-]+)$/i, 'must be a hostname, "*.example.com" or "*"');

const siteName = z
  .string()
  .regex(/^[a-z0-9][a-z0-9._-]{0,63}$/i, 'must be 1-64 characters: letters, digits, ".", "_" or "-"');

export const WaitUntilSchema = z.enum(['load', 'domcontentloaded', 'networkidle', 'commit']);

export const ScanOptionsSchema = z
  .object({
    /** Navigation timeout per page in milliseconds. */
    timeout: z.number().int().min(1000).max(600_000).default(60_000),
    /** Load state to wait for. `networkidle` is best-effort and bounded by networkIdleTimeout. */
    waitUntil: WaitUntilSchema.default('networkidle'),
    /** Upper bound for waiting until the network is idle (ms). */
    networkIdleTimeout: z.number().int().min(0).max(120_000).default(15_000),
    /** Extra time to keep observing after load, to catch delayed script injection (ms). */
    settleMs: z.number().int().min(0).max(60_000).default(3_000),
    captureScreenshots: z.boolean().default(false),
    /** Optional user-agent override. The profile's user agent is used otherwise. */
    userAgent: z.string().max(512).optional(),
  })
  .strict();

export const BrowserOptionsSchema = z
  .object({
    profile: z.enum(BROWSER_PROFILES).default('desktop-chromium'),
  })
  .strict();

export const SiteSchema = z
  .object({
    name: siteName,
    url: z.string().min(1),
    enabled: z.boolean().default(true),
    pages: z.array(z.string().min(1)).min(1).default(['/']),
    /** Pages (paths) that handle sensitive data such as payments or logins. Findings there are scored higher. */
    sensitivePages: z.array(z.string().min(1)).default([]),
    /** Additional registrable domains treated as first-party (e.g. your own CDN). */
    firstPartyDomains: z.array(hostPattern).default([]),
    /** Query parameter names ignored when computing canonical resource identity (e.g. cache busters). */
    ignoreQueryParams: z.array(z.string().min(1)).default([]),
    browser: BrowserOptionsSchema.partial().optional(),
    scan: ScanOptionsSchema.partial().optional(),
  })
  .strict();

export const LimitsSchema = z
  .object({
    /** Maximum bytes of a single script/wasm response body to capture and hash. */
    maxResourceBytes: z.number().int().min(1024).max(100 * 1024 * 1024).default(5 * 1024 * 1024),
    /** Maximum bytes of a single inline script to capture. */
    maxInlineScriptBytes: z.number().int().min(1024).max(20 * 1024 * 1024).default(1024 * 1024),
    maxScriptsPerPage: z.number().int().min(1).max(10_000).default(500),
    maxRequestsPerPage: z.number().int().min(1).max(100_000).default(3_000),
    maxPagesPerScan: z.number().int().min(1).max(10_000).default(100),
    /** Hard wall-clock limit for the whole scan (ms). */
    maxScanDurationMs: z.number().int().min(10_000).max(24 * 3600_000).default(30 * 60_000),
    /** Maximum size of the evidence handed from the browser worker to the analyser. */
    maxEvidenceBytes: z.number().int().min(1024 * 1024).max(4 * 1024 * 1024 * 1024).default(512 * 1024 * 1024),
    /** Maximum bytes transferred through a single proxied connection. */
    maxBytesPerConnection: z.number().int().min(1024 * 1024).max(1024 * 1024 * 1024).default(50 * 1024 * 1024),
  })
  .strict();

export const NetworkSecuritySchema = z
  .object({
    allowedPorts: z.array(z.number().int().min(1).max(65535)).min(1).default([80, 443]),
    /**
     * Hosts allowed to resolve to private/loopback/link-local addresses.
     * Use only for deliberately scanning internal sites. Cloud metadata
     * addresses remain blocked regardless.
     */
    allowedPrivateHosts: z.array(hostPattern).default([]),
    blockedHosts: z.array(hostPattern).default([]),
    /** Static hostname → IP overrides (results are still validated). Mainly for tests. */
    resolverOverrides: z.record(z.string(), z.string()).default({}),
    /**
     * Use an external ScriptDrift egress proxy (e.g. the egress-proxy container)
     * instead of starting one inside the browser worker.
     */
    externalProxy: z.string().optional(),
    connectTimeoutMs: z.number().int().min(1000).max(120_000).default(15_000),
    idleTimeoutMs: z.number().int().min(1000).max(600_000).default(60_000),
  })
  .strict();

export const IsolationSchema = z
  .object({
    /**
     * `process` (default): run the browser in a separate child process with a
     * scrubbed environment. `none`: run in the coordinator process (for
     * debugging only; secrets in the environment would be reachable).
     */
    mode: z.enum(['process', 'none']).default('process'),
    /**
     * Keep Chromium's own renderer sandbox enabled (Playwright disables it by
     * default). Disable only inside a container that provides equivalent
     * isolation and cannot support the sandbox (e.g. running as root).
     */
    chromiumSandbox: z.boolean().default(true),
  })
  .strict();

export const SecuritySchema = z
  .object({
    network: NetworkSecuritySchema.prefault({}),
    isolation: IsolationSchema.prefault({}),
  })
  .strict();

export const ServiceWorkerSchema = z
  .object({
    /**
     * `block` (default): service worker registration is blocked so all page
     * traffic stays observable; registered script URLs are recorded and the
     * script is fetched separately for hashing.
     * `allow`: service workers run normally. Their traffic is only partially
     * observable (Chromium only). See docs/limitations.md.
     */
    strategy: z.enum(['block', 'allow']).default('block'),
    /** Fetch the script of blocked service worker registrations to hash it. */
    probeBlockedRegistrations: z.boolean().default(true),
  })
  .strict();

export const RetentionSchema = z
  .object({
    /** Store script bodies in .scriptdrift/cache/content (needed for code diffs). Off by default. */
    storeScriptContent: z.boolean().default(false),
    /** Number of scan reports to keep. */
    maxScanReports: z.number().int().min(1).max(100_000).default(50),
    /** Delete scan reports and cached content older than this many days. */
    maxAgeDays: z.number().int().min(1).max(3650).default(90),
  })
  .strict();

export const RiskSchema = z
  .object({
    /** Minimum score (0-100) for each severity. Scores below `low` are informational. */
    thresholds: z
      .object({
        low: z.number().min(0).max(100).default(15),
        medium: z.number().min(0).max(100).default(30),
        high: z.number().min(0).max(100).default(50),
        critical: z.number().min(0).max(100).default(75),
      })
      .strict()
      .prefault({})
      .refine((t) => t.low <= t.medium && t.medium <= t.high && t.high <= t.critical, 'thresholds must be ascending: low <= medium <= high <= critical'),
    /** Override individual signal weights (signal id → weight). */
    weights: z.record(z.string(), z.number().min(-100).max(100)).default({}),
  })
  .strict();

export const DefaultsSchema = z
  .object({
    browser: BrowserOptionsSchema.prefault({}),
    scan: ScanOptionsSchema.prefault({}),
  })
  .strict();

export const ConfigSchema = z
  .object({
    version: z.literal(1).default(1),
    /** Directory for baselines, reports, state and cache (relative to the config file). */
    storageDir: z.string().min(1).default('.scriptdrift'),
    defaults: DefaultsSchema.prefault({}),
    sites: z.array(SiteSchema).min(1, 'at least one site must be configured'),
    limits: LimitsSchema.prefault({}),
    security: SecuritySchema.prefault({}),
    serviceWorkers: ServiceWorkerSchema.prefault({}),
    retention: RetentionSchema.prefault({}),
    risk: RiskSchema.prefault({}),
    /** Default --fail-on threshold for scan/diff (`none` never fails on findings). */
    failOn: z.enum([...SEVERITIES, 'none']).default('high'),
  })
  .strict()
  .superRefine((cfg, ctx) => {
    const seen = new Set<string>();
    cfg.sites.forEach((site, i) => {
      if (seen.has(site.name)) {
        ctx.addIssue({ code: 'custom', path: ['sites', i, 'name'], message: `duplicate site name "${site.name}"` });
      }
      seen.add(site.name);
    });
  });

export type ScriptDriftConfig = z.infer<typeof ConfigSchema>;
export type SiteConfig = z.infer<typeof SiteSchema>;
export type ScanOptions = z.infer<typeof ScanOptionsSchema>;
export type BrowserProfileName = (typeof BROWSER_PROFILES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type Limits = z.infer<typeof LimitsSchema>;
export type NetworkSecurityConfig = z.infer<typeof NetworkSecuritySchema>;
