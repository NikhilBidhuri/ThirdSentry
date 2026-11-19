/**
 * Commented configuration template written by `thirdsentry init`.
 * Every option shown here is validated by src/config/schema.ts.
 */
export const CONFIG_TEMPLATE = `# ThirdSentry configuration
# Docs: docs/configuration.md
version: 1

# Where baselines, reports and state are stored (relative to this file).
storageDir: .thirdsentry

defaults:
  browser:
    # desktop-chromium | desktop-firefox | desktop-webkit | mobile-chromium | mobile-webkit
    # Mobile profiles are *emulation* on desktop engines, not real devices.
    profile: desktop-chromium
  scan:
    timeout: 60000          # navigation timeout per page (ms)
    waitUntil: networkidle  # load | domcontentloaded | networkidle | commit
    networkIdleTimeout: 15000
    settleMs: 3000          # keep observing after load to catch late script injection
    captureScreenshots: false

sites:
  - name: __SITE_NAME__
    url: __SITE_URL__
    enabled: true
    pages:
      - /
    # Pages that handle payments, logins or personal data. Findings there are scored higher.
    sensitivePages: []
    # Extra domains you own (e.g. your CDN) that should count as first-party.
    firstPartyDomains: []
    # Query parameters that only bust caches and should not change resource identity.
    ignoreQueryParams: []

limits:
  maxResourceBytes: 5242880   # largest script body captured and hashed (5 MiB)
  maxPagesPerScan: 100
  maxScanDurationMs: 1800000  # 30 minutes

security:
  network:
    allowedPorts: [80, 443]
    # Hosts allowed to resolve to private/internal IPs. Leave empty unless you
    # deliberately scan an internal site. Cloud metadata IPs are always blocked.
    allowedPrivateHosts: []
    blockedHosts: []
  isolation:
    mode: process          # run the browser in a separate process with a scrubbed environment
    chromiumSandbox: true

serviceWorkers:
  strategy: block          # block | allow (see docs/limitations.md)

retention:
  storeScriptContent: false  # set true to keep script bodies locally for code diffs
  maxScanReports: 50
  maxAgeDays: 90
`;
