import { z } from 'zod';
import { RULES_BY_ID } from '../analysis/indicator-rules.js';
import { checkPolicyNames, ScriptPolicySchema } from '../policies/schema.js';

/**
 * ThirdSentry configuration schema (thirdsentry.yml).
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

/** Query parameters that only bust caches; ignored when matching resources unless a site overrides the list. */
export const DEFAULT_IGNORE_QUERY_PARAMS = ['cb', '_', 't', 'ts', 'timestamp', 'cachebust', 'cachebuster', 'nocache', 'rnd', 'rand', 'random'] as const;

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
    /** Query parameter names ignored when computing canonical resource identity (cache busters by default; set [] to disable). */
    ignoreQueryParams: z.array(z.string().min(1)).default([...DEFAULT_IGNORE_QUERY_PARAMS]),
    /** Script policies for this site (see docs/policies.md); they take precedence over a global policy of equal specificity. */
    scriptPolicies: z.array(ScriptPolicySchema).default([]),
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
    /** Evidence budget per page (captured bodies, inline text, blobs, metadata). Excess bodies are recorded as `budget-exceeded`. */
    maxEvidenceBytesPerPage: z.number().int().min(1024 * 1024).max(1024 * 1024 * 1024).default(64 * 1024 * 1024),
    /** Evidence budget for the whole scan (also capped at 75% of maxEvidenceBytes). */
    maxEvidenceBytesPerScan: z.number().int().min(1024 * 1024).max(4 * 1024 * 1024 * 1024).default(256 * 1024 * 1024),
    /** Calls the page may make to the in-page reporting binding before further reports are ignored. */
    maxReportCallsPerPage: z.number().int().min(100).max(1_000_000).default(5_000),
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
     * Use an external ThirdSentry egress proxy (e.g. the egress-proxy container)
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
    /**
     * Which script bodies to keep in .thirdsentry/cache/content (needed for code diffs):
     * `none`, `findings` (approved versions and versions behind findings; default) or `all`.
     */
    scriptContent: z.enum(['none', 'findings', 'all']).optional(),
    /** Deprecated: `true` = scriptContent `all`, `false` = `none`. */
    storeScriptContent: z.boolean().optional(),
    /** Number of scan reports to keep per site. */
    maxScanReports: z.number().int().min(1).max(100_000).default(50),
    /** Delete scan reports and cached content older than this many days. */
    maxAgeDays: z.number().int().min(1).max(3650).default(90),
  })
  .strict()
  .refine((r) => r.scriptContent === undefined || r.storeScriptContent === undefined, 'set either retention.scriptContent or the deprecated retention.storeScriptContent, not both');

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

export const RuleConfigSchema = z
  .object({
    enabled: z.boolean().default(true),
    /** Override the rule's severity (affects the default weight of its signal). */
    severity: z.enum(SEVERITIES).optional(),
    /** Override the risk weight contributed by a new match of this rule. */
    weight: z.number().min(0).max(100).optional(),
    /** Resource URL globs (e.g. "https://www.googletagmanager.com/*") this rule ignores. */
    ignoreResources: z.array(z.string().min(1)).default([]),
  })
  .strict();

export const AnalysisSchema = z
  .object({
    /** Run static behaviour analysis on captured scripts. */
    enabled: z.boolean().default(true),
    /** Scripts larger than this are not statically analysed. */
    maxScriptBytes: z.number().int().min(1024).max(50 * 1024 * 1024).default(3 * 1024 * 1024),
  })
  .strict();

export const DomainPolicySchema = z
  .object({
    /** Domains/hosts treated as approved everywhere (never reported as new). */
    allow: z.array(hostPattern).default([]),
    /** Domains/hosts that must never be used. Always reported, even if in a baseline. */
    deny: z.array(hostPattern).default([]),
    /** Reputation hints: domains considered suspicious (raise risk when contacted). */
    suspicious: z.array(hostPattern).default([]),
  })
  .strict();

export const SuppressionSchema = z
  .object({
    /** Finding ID (TS-xxxxxxxxxxxx) to suppress. */
    id: z.string().regex(/^TS-[0-9a-f]{12}$/).optional(),
    /** Finding kind (e.g. new-outbound-host) or rule id (e.g. TS-COOKIE-ACCESS). */
    kind: z.string().max(64).optional(),
    rule: z.string().max(64).optional(),
    site: z.string().max(64).optional(),
    /** Resource URL or identity glob. */
    resource: z.string().max(4096).optional(),
    /** Domain/host pattern. */
    domain: hostPattern.optional(),
    /** Name of a script policy (scriptPolicies): matches findings that policy affected. */
    policy: z.string().max(64).optional(),
    /** Why this is suppressed. Required: undocumented suppressions are not allowed. */
    reason: z.string().min(3).max(2_000),
    /** ISO date after which the suppression stops applying. */
    expires: z
      .string()
      .refine((v) => !Number.isNaN(Date.parse(v)), 'must be an ISO date such as 2026-12-31')
      .optional(),
  })
  .strict()
  .refine((s) => s.id ?? s.kind ?? s.rule ?? s.resource ?? s.domain ?? s.policy, 'a suppression needs at least one of id, kind, rule, resource, domain or policy');

/**
 * Alert settings. Values may reference environment variables as ${NAME};
 * they are resolved only by the alert publisher, at send time. Never put
 * credentials directly in the configuration file.
 */
const envString = z.string().min(1).max(4_096);
const alertSeverity = z.enum(SEVERITIES);

export const SlackAlertSchema = z
  .object({
    enabled: z.boolean().default(false),
    webhookUrl: envString.default('${THIRDSENTRY_SLACK_WEBHOOK}'),
    minSeverity: alertSeverity.optional(),
  })
  .strict();

export const WebhookAlertSchema = z
  .object({
    enabled: z.boolean().default(false),
    url: envString.default('${THIRDSENTRY_WEBHOOK_URL}'),
    /** Optional HMAC-SHA256 signing secret (X-ThirdSentry-Signature header). */
    secret: envString.optional(),
    minSeverity: alertSeverity.optional(),
    /** Allow plain-http URLs (e.g. an internal receiver). Off by default. */
    allowInsecureHttp: z.boolean().default(false),
  })
  .strict();

export const GithubAlertSchema = z
  .object({
    enabled: z.boolean().default(false),
    createIssues: z.boolean().default(true),
    /** owner/repo. Defaults to ${GITHUB_REPOSITORY} (set automatically in GitHub Actions). */
    repository: envString.default('${GITHUB_REPOSITORY}'),
    token: envString.default('${GITHUB_TOKEN}'),
    apiUrl: envString.default('https://api.github.com'),
    labels: z.array(z.string().min(1).max(50)).max(10).default(['thirdsentry', 'security']),
    maxIssuesPerRun: z.number().int().min(1).max(100).default(10),
    minSeverity: alertSeverity.optional(),
  })
  .strict();

export const EmailAlertSchema = z
  .object({
    enabled: z.boolean().default(false),
    host: envString.default('${THIRDSENTRY_SMTP_HOST}'),
    port: z.union([z.number().int().min(1).max(65535), envString]).default('${THIRDSENTRY_SMTP_PORT}'),
    /** true = implicit TLS (port 465); false = STARTTLS when offered. */
    secure: z.boolean().default(false),
    /** Require STARTTLS (refuse to send credentials over a plain connection). */
    requireTLS: z.boolean().default(true),
    username: envString.optional(),
    password: envString.optional(),
    from: envString.default('${THIRDSENTRY_SMTP_FROM}'),
    to: z.union([z.array(envString).min(1), envString]).default('${THIRDSENTRY_SMTP_TO}'),
    minSeverity: alertSeverity.optional(),
  })
  .strict();

export const PagerDutyAlertSchema = z
  .object({
    enabled: z.boolean().default(false),
    /** Events API v2 integration (routing) key. */
    routingKey: envString.default('${THIRDSENTRY_PAGERDUTY_ROUTING_KEY}'),
    minSeverity: alertSeverity.default('high'),
    /** Events API endpoint (use https://events.eu.pagerduty.com/v2/enqueue for the EU service region). */
    apiUrl: envString.default('https://events.pagerduty.com/v2/enqueue'),
    /** Send "resolve" when a triggered finding is gone from the latest complete scan of its site. */
    autoResolve: z.boolean().default(false),
    /** Most events (triggers, and separately resolves) sent per run; the rest stays pending. */
    maxEventsPerRun: z.number().int().min(1).max(100).default(20),
    /** Allow a plain-http apiUrl (tests only). Off by default. */
    allowInsecureHttp: z.boolean().default(false),
  })
  .strict();

export const TeamsAlertSchema = z
  .object({
    enabled: z.boolean().default(false),
    /** Workflows (Power Automate) "post to a channel when a webhook request is received" URL. */
    webhookUrl: envString.default('${THIRDSENTRY_TEAMS_WEBHOOK}'),
    minSeverity: alertSeverity.optional(),
    /** Allow a plain-http URL (tests only). Off by default. */
    allowInsecureHttp: z.boolean().default(false),
  })
  .strict();

export const AlertsSchema = z
  .object({
    /** Only findings at or above this severity are sent (per-channel minSeverity overrides). */
    minSeverity: alertSeverity.default('medium'),
    /** Re-send an unchanged finding after this many hours (0 = only alert once per finding). */
    repeatAfterHours: z.number().min(0).max(24 * 365).default(0),
    /** Maximum findings listed in one alert message. */
    maxFindingsPerAlert: z.number().int().min(1).max(100).default(20),
    /** Optional link to the published report (e.g. a CI run URL). May use ${ENV}. */
    reportUrl: envString.optional(),
    timeoutMs: z.number().int().min(1_000).max(120_000).default(15_000),
    retries: z.number().int().min(0).max(5).default(2),
    slack: SlackAlertSchema.prefault({}),
    webhook: WebhookAlertSchema.prefault({}),
    github: GithubAlertSchema.prefault({}),
    email: EmailAlertSchema.prefault({}),
    pagerduty: PagerDutyAlertSchema.prefault({}),
    teams: TeamsAlertSchema.prefault({}),
  })
  .strict();

export const HeartbeatSchema = z
  .object({
    /** Ping URL of a push monitor (healthchecks.io, Cronitor, Uptime Kuma). Usually an ${ENV} reference: the URL is a secret. */
    url: envString.default('${THIRDSENTRY_HEARTBEAT_URL}'),
    /** Explicit URL for failure pings. Default: `url` + `failPath`. */
    failUrl: envString.optional(),
    /** Appended to the URL path for failure pings when failUrl is not set (healthchecks.io convention). Empty string = send no failure ping. */
    failPath: z.string().max(100).default('/fail'),
    /** What an incomplete (partial) scan sends: the failure ping, the success ping, or nothing. */
    onIncomplete: z.enum(['fail', 'success', 'skip']).default('fail'),
    /** Single attempt, no retries. */
    timeoutMs: z.number().int().min(500).max(30_000).default(5_000),
  })
  .strict();

export const HealthSchema = z
  .object({
    /** Raise a `scan-unhealthy` finding after this many consecutive failed (or incomplete) scans of a site. */
    failureThreshold: z.number().int().min(1).max(1_000).default(3),
    /** Count incomplete (partial) scans as failures; false counts only scans that failed outright. */
    countIncomplete: z.boolean().default(true),
    /** Dead-man's-switch ping, sent by the alert step only. Not configured = no heartbeat. */
    heartbeat: HeartbeatSchema.optional(),
  })
  .strict();

export const ReportingSchema = z
  .object({
    /** Report formats written after each scan. */
    formats: z.array(z.enum(['json', 'sarif', 'html'])).min(1).default(['json', 'sarif', 'html']),
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
    storageDir: z.string().min(1).default('.thirdsentry'),
    defaults: DefaultsSchema.prefault({}),
    sites: z.array(SiteSchema).min(1, 'at least one site must be configured'),
    limits: LimitsSchema.prefault({}),
    security: SecuritySchema.prefault({}),
    serviceWorkers: ServiceWorkerSchema.prefault({}),
    retention: RetentionSchema.prefault({}),
    risk: RiskSchema.prefault({}),
    analysis: AnalysisSchema.prefault({}),
    rules: z.record(z.string().regex(/^TS-[A-Z0-9-]+$/, 'rule ids look like TS-EVAL'), RuleConfigSchema).default({}),
    domains: DomainPolicySchema.prefault({}),
    suppressions: z.array(SuppressionSchema).default([]),
    /** Explicit per-script policies for vendors whose scripts rotate (pin, path-versions, domain-only). */
    scriptPolicies: z.array(ScriptPolicySchema).default([]),
    reporting: ReportingSchema.prefault({}),
    alerts: AlertsSchema.prefault({}),
    health: HealthSchema.prefault({}),
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
    checkPolicyNames(cfg.scriptPolicies, cfg.sites, (path, message) => ctx.addIssue({ code: 'custom', path, message }));
    for (const id of Object.keys(cfg.rules)) {
      if (!RULES_BY_ID.has(id)) {
        ctx.addIssue({ code: 'custom', path: ['rules', id], message: `unknown rule "${id}" (known: ${[...RULES_BY_ID.keys()].join(', ')})` });
      }
    }
  });

export type ThirdSentryConfig = z.infer<typeof ConfigSchema>;
export type SiteConfig = z.infer<typeof SiteSchema>;
export type ScanOptions = z.infer<typeof ScanOptionsSchema>;
export type BrowserProfileName = (typeof BROWSER_PROFILES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type Limits = z.infer<typeof LimitsSchema>;
export type NetworkSecurityConfig = z.infer<typeof NetworkSecuritySchema>;
export type RuleConfig = z.infer<typeof RuleConfigSchema>;
export type DomainPolicy = z.infer<typeof DomainPolicySchema>;
export type Suppression = z.infer<typeof SuppressionSchema>;
export type AlertsConfig = z.infer<typeof AlertsSchema>;
export type HealthConfig = z.infer<typeof HealthSchema>;
export type HeartbeatConfig = z.infer<typeof HeartbeatSchema>;
