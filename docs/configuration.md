# Configuration reference

ScriptDrift reads `scriptdrift.yml` from the current directory (or `scriptdrift.yaml`, `.scriptdrift/config.yml`), or the file passed with `--config`. The configuration is validated strictly: unknown keys are errors, so typos fail loudly instead of silently changing behaviour.

Paths in the file are relative to the directory containing it. When the file lives in `.scriptdrift/config.yml`, paths are relative to the project root (the parent of `.scriptdrift/`).

## Minimal example

```yaml
version: 1
sites:
  - name: production-store
    url: https://www.example.com
    pages:
      - /
      - /checkout
    sensitivePages:
      - /checkout
```

## Full example

```yaml
version: 1
storageDir: .scriptdrift

defaults:
  browser:
    profile: desktop-chromium
  scan:
    timeout: 60000
    waitUntil: networkidle
    networkIdleTimeout: 15000
    settleMs: 3000
    captureScreenshots: false

sites:
  - name: production-store
    url: https://www.example.com
    enabled: true
    pages: [/, /checkout, /contact]
    sensitivePages: [/checkout]
    firstPartyDomains: [examplecdn.net]
    ignoreQueryParams: [v, cb]
    browser:
      profile: mobile-webkit
    scan:
      timeout: 90000

limits:
  maxResourceBytes: 5242880
  maxInlineScriptBytes: 1048576
  maxScriptsPerPage: 500
  maxRequestsPerPage: 3000
  maxPagesPerScan: 100
  maxScanDurationMs: 1800000
  maxEvidenceBytes: 536870912
  maxBytesPerConnection: 52428800

security:
  network:
    allowedPorts: [80, 443]
    allowedPrivateHosts: []
    blockedHosts: []
    resolverOverrides: {}
    connectTimeoutMs: 15000
    idleTimeoutMs: 60000
  isolation:
    mode: process
    chromiumSandbox: true

serviceWorkers:
  strategy: block
  probeBlockedRegistrations: true

retention:
  storeScriptContent: false
  maxScanReports: 50
  maxAgeDays: 90
```

## `sites[]`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | required | Unique identifier (letters, digits, `.`, `_`, `-`; max 64). Used in baseline paths and `--site`. |
| `url` | URL | required | Base URL. Must be `http:` or `https:`, without credentials. |
| `enabled` | boolean | `true` | Disabled sites are skipped unless selected with `--site`. |
| `pages` | string[] | `["/"]` | Paths (starting with `/`) or absolute URLs to visit. Query strings are kept. |
| `sensitivePages` | string[] | `[]` | Pages handling payments, logins or personal data. Findings there score higher. A trailing `*` matches a prefix (`/account/*`). |
| `firstPartyDomains` | host patterns | `[]` | Extra domains you own. Resources there count as first-party. `*.example.com` matches subdomains. |
| `ignoreQueryParams` | string[] | `[]` | Query parameter names removed from the *identity* of a resource (cache busters). The stored URL is never modified. |
| `browser.profile` | enum | from `defaults` | Browser profile (see below). |
| `scan.*` | object | from `defaults` | Per-site overrides of the scan options below. |

### Browser profiles

| Profile | Engine | What it is |
| --- | --- | --- |
| `desktop-chromium` | Chromium | Playwright's Chromium build, desktop viewport. |
| `desktop-firefox` | Firefox | Playwright's patched Firefox build. |
| `desktop-webkit` | WebKit | Playwright's WebKit build. **Not** Apple Safari. |
| `mobile-chromium` | Chromium | Pixel 7 emulation: viewport, touch and mobile user agent on desktop Chromium. Not a real Android device. |
| `mobile-webkit` | WebKit | iPhone 15 emulation: viewport, touch and iOS Safari user agent on Playwright WebKit. **Not a real iOS device or Mobile Safari.** Sites may serve different code to real iPhones. |

### Scan options (`defaults.scan` and `sites[].scan`)

| Key | Default | Description |
| --- | --- | --- |
| `timeout` | `60000` | Navigation timeout per page (ms). |
| `waitUntil` | `networkidle` | `load`, `domcontentloaded`, `commit` or `networkidle`. With `networkidle`, ScriptDrift waits for `load` and then up to `networkIdleTimeout` for the network to go quiet. Not reaching idle is a warning, not a failure. |
| `networkIdleTimeout` | `15000` | Upper bound for the idle wait (ms). |
| `settleMs` | `3000` | Additional observation time after loading, to catch scripts injected with a delay. |
| `captureScreenshots` | `false` | Save a viewport screenshot per page in `reports/screenshots/`. Screenshots can contain personal data shown on the page. |
| `userAgent` | profile UA | Override the user agent. |

## `limits`

Every browser-facing operation is bounded. Exceeding a limit marks the page `partial` and records an issue; it never silently drops data.

| Key | Default | Description |
| --- | --- | --- |
| `maxResourceBytes` | 5 MiB | Largest script/wasm body captured and hashed. Larger resources are tracked by identity with content status `too-large`. |
| `maxInlineScriptBytes` | 1 MiB | Largest inline script captured. |
| `maxScriptsPerPage` | 500 | Script resources recorded per page. |
| `maxRequestsPerPage` | 3000 | Network requests recorded per page. |
| `maxPagesPerScan` | 100 | Pages per scan across all sites. |
| `maxScanDurationMs` | 30 min | Wall-clock budget for the scan. The worker process is killed shortly after it. |
| `maxEvidenceBytes` | 512 MiB | Largest evidence file accepted from the browser worker. |
| `maxBytesPerConnection` | 50 MiB | Bytes per proxied connection before it is cut. |

## `security`

See [security.md](security.md) for the reasoning behind these settings.

| Key | Default | Description |
| --- | --- | --- |
| `network.allowedPorts` | `[80, 443]` | Destination ports the browser may connect to. |
| `network.allowedPrivateHosts` | `[]` | Host patterns allowed to resolve to private, loopback or link-local addresses (for deliberately scanning internal sites). Cloud metadata addresses stay blocked. |
| `network.blockedHosts` | `[]` | Host patterns that are always refused. |
| `network.resolverOverrides` | `{}` | Static `hostname: ip` mappings, still validated by the IP policy. Mainly for tests. |
| `network.externalProxy` | unset | URL of an external ScriptDrift egress proxy (used by the Docker deployment). |
| `network.connectTimeoutMs` | `15000` | Upstream connect timeout. |
| `network.idleTimeoutMs` | `60000` | Idle timeout for proxied connections. |
| `isolation.mode` | `process` | `process` runs the browser in a child process with a scrubbed environment. `none` runs it in the coordinator process (debugging only). |
| `isolation.chromiumSandbox` | `true` | Keep Chromium's renderer sandbox enabled. |

## `serviceWorkers`

| Key | Default | Description |
| --- | --- | --- |
| `strategy` | `block` | `block` refuses service worker registration so all page traffic stays observable. `allow` lets service workers run; their traffic is only partly observable (see [limitations.md](limitations.md)). |
| `probeBlockedRegistrations` | `true` | With `block`, fetch each registered service worker script separately so it is still hashed and tracked. |

## `retention`

See [privacy.md](privacy.md).

| Key | Default | Description |
| --- | --- | --- |
| `storeScriptContent` | `false` | Keep script bodies in `.scriptdrift/cache/content/` (content-addressed). Needed to show code diffs between versions. |
| `maxScanReports` | `50` | Scan result files to keep. |
| `maxAgeDays` | `90` | Delete scan results, screenshots and cached content older than this. |
