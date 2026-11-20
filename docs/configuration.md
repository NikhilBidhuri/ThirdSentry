# Configuration reference

ThirdSentry reads `thirdsentry.yml` from the current directory (or `thirdsentry.yaml`, `.thirdsentry/config.yml`), or the file passed with `--config`. The configuration is validated strictly: unknown keys are errors, so typos fail loudly instead of silently changing behaviour.

Paths in the file are relative to the directory containing it. When the file lives in `.thirdsentry/config.yml`, paths are relative to the project root (the parent of `.thirdsentry/`).

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
storageDir: .thirdsentry

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
  scriptContent: findings
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
| `ignoreQueryParams` | string[] | `[cb, _, t, ts, timestamp, cachebust, cachebuster, nocache, rnd, rand, random]` | Query parameter names removed from the *identity* of a resource (cache busters), so `a.js?cb=123` is the same resource every scan. Setting the key replaces the default list (`[]` disables it; include the defaults you still want). Matching is case-sensitive. The stored URL is never modified. |
| `browser.profile` | enum | from `defaults` | Browser profile (see below). |
| `scan.*` | object | from `defaults` | Per-site overrides of the scan options below. |
| `journeys` | list | `[]` | Logged-in, multi-step journeys such as login, cart, checkout. See [Journeys](#journeys). |

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
| `waitUntil` | `networkidle` | `load`, `domcontentloaded`, `commit` or `networkidle`. With `networkidle`, ThirdSentry waits for `load` and then up to `networkIdleTimeout` for the network to go quiet. Not reaching idle is a warning, not a failure. |
| `networkIdleTimeout` | `15000` | Upper bound for the idle wait (ms). |
| `settleMs` | `3000` | Additional observation time after loading, to catch scripts injected with a delay. |
| `captureScreenshots` | `false` | Save a viewport screenshot per page in `reports/screenshots/`. Screenshots can contain personal data shown on the page. |
| `userAgent` | profile UA | Override the user agent. |

## Journeys

Payment pages usually need a session, so a plain visit cannot reach them. A *journey* is a short declarative script that runs in **one browser context** (cookies persist between steps) and records evidence at `capture` checkpoints. Each capture is a normal page for everything downstream: its key is `journey:<journey>/<capture>`, so baselines, comparison, findings, reports and `sensitive` scoring work unchanged. Journeys run after the plain `pages` of the site, each in a fresh context; one journey failing never stops other journeys or pages.

```yaml
sites:
  - name: shop
    url: https://www.example.com
    pages: ["/"]
    journeys:
      - name: purchase
        sensitive: true            # findings on all its captures are scored as sensitive
        timeoutMs: 120000          # whole journey (default 120000, max 600000); also bounded by limits.maxScanDurationMs
        # storageState: sessions/shop.json   # optional: start from a saved authenticated session
        # allowedHosts: [checkout.partner.example]   # extra hosts goto/navigation may use
        steps:
          - { type: goto, url: /login }
          - { type: fill, selector: "#email", value: "qa-monitor@example.com" }
          - { type: fill, selector: "#password", value: "${THIRDSENTRY_SECRET_SHOP_PASSWORD}" }
          - { type: click, selector: "button[type=submit]" }        # a login submit is fine
          - { type: waitFor, url: "**/account" }
          - { type: capture, name: account, sensitive: false }
          - { type: goto, url: /cart }
          - { type: capture, name: cart }
          - { type: click, selector: "#checkout-button" }
          - { type: waitFor, selector: "form#payment" }
          - { type: capture, name: checkout }                      # key: journey:purchase/checkout
```

### Step types

| `type` | Keys | Notes |
| --- | --- | --- |
| `goto` | `url` | Path or URL of the site. Must stay on the site's registrable domain or a host in `allowedHosts`; checked when the configuration loads. |
| `click` | `selector`, `allowSubmit` | Playwright selector, must match exactly one element. See the [submit guard](#submit-guard). |
| `fill` | `selector`, `value` | `value` is literal text or may contain `${THIRDSENTRY_SECRET_<NAME>}`. See [secrets](#journey-secrets). |
| `select` | `selector`, `value` | Selects an `<option>` by value or label. |
| `check` | `selector`, `checked` (default `true`) | Checks or unchecks a checkbox or radio button. |
| `press` | `key`, `selector` (optional), `allowSubmit` | A key such as `Enter` or `Control+A`, in the selected or focused element. |
| `waitFor` | exactly one of `selector`, `url` (glob, e.g. `**/checkout`), `loadState` | Waits for a visible element, a URL, or a load state. |
| `capture` | `name`, `sensitive` | Records evidence. Names are unique per journey. |

Every step except `capture` accepts `timeoutMs` (500-120000, default `scan.timeout`), always cut short by the journey and scan deadlines. A journey has at most 100 steps, a site at most 20 journeys, and needs at least one `capture`. There is no step that evaluates code or reads values.

**What a capture contains.** Network and script activity since the previous capture (or the start of the journey) plus a DOM snapshot at capture time, built by the same collectors as a plain page. After the capture the page keeps its session and the next segment starts empty.

**Starting from a saved session.** `storageState` is the path (relative to the config file) of a Playwright storage-state JSON file. Use it instead of, or before, scripted login, for example for accounts with MFA. The file must exist where the browser runs (the scanner container in the Docker setup), contains live session cookies, and must be treated like a password: dedicated test account, restricted file permissions, never committed.

**Failures.** If a step fails, the next capture of that journey is reported `failed` with a `journey-step-failed` issue naming the step number, type and selector (never values, never raw browser error text), and the remaining captures are `failed` with `journey-not-reached`. Captures taken before the failure stay valid. Failed captures are not compared and cannot be baselined, so a broken login never looks like "all checkout scripts were removed".

### Journey secrets

Logging in requires credentials in the browser. This is the one place where the browser worker receives a secret, so it is deliberately narrow:

- Only the `value` of a `fill` step may reference a secret, and only as `${THIRDSENTRY_SECRET_<NAME>}` (uppercase letters, digits, `_`). Any other `${...}` (for example `${HOME}` or `${GITHUB_TOKEN}`) is rejected when the configuration loads, as is a reference anywhere else in a journey.
- The configuration and the worker request only ever hold the reference. The worker's allowlisted environment receives exactly the variables the journeys reference, and never alert credentials.
- A missing variable fails the journey immediately (the issue names the variable). A resolved secret shorter than 8 characters is refused, because it could not be redacted reliably.
- The typed value never appears in evidence, logs, reports or error messages: step issues carry only index, type and selector, and every capture is scrubbed of the secret (also URL-encoded and base64 forms) before it is written. If scrubbing had to remove something, the capture gets a `secret-redacted` warning (the site echoed the credential). Screenshots mask typed fields. Request bodies are never recorded.
- **Use dedicated test accounts with least privilege**: no admin rights, no stored payment methods, no real personal data, a password used nowhere else. Rotate it like any credential.

### Submit guard

A scan must never complete a purchase by accident. A `click` on a submit button, or `press` of `Enter` in a field, of a form that looks like a payment form (card fields or `autocomplete="cc-*"`, hosted card or payment iframes, or an action containing pay, payment, charge, purchase or place-order) is refused unless the step sets `allowSubmit: true`. Login forms are not affected. The check is a heuristic on the DOM: when it does not recognise a form, nothing stops you, so do not point a journey at a button that charges money. **Never use live payment credentials.** If a journey must submit a payment form, use a payment sandbox with test cards and `allowSubmit: true`.

### Safety summary

- Each step and each journey has a timeout, within the scan deadline (`limits.maxScanDurationMs`); captures count toward `limits.maxPagesPerScan`.
- Top-level navigation (`goto`, clicks, redirects) is limited to the site's registrable domain plus `allowedHosts`. Other navigations are aborted and fail the step.
- All traffic still goes through the egress proxy and its network policy.
- Works in `process`, `none` and container isolation (`collect`). See [docker.md](docker.md#journeys-and-credentials).

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
| `network.externalProxy` | unset | URL of an external ThirdSentry egress proxy (used by the Docker deployment). |
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
| `scriptContent` | `findings` | Which script bodies to keep in `.thirdsentry/cache/content/` (content-addressed): `none`, `findings` (approved versions and versions involved in findings, so `diff` can show code changes) or `all`. The deprecated `storeScriptContent: true/false` means `all`/`none`. See [privacy.md](privacy.md). |
| `maxScanReports` | `50` | Scan result files to keep per site. |
| `maxAgeDays` | `90` | Delete scan results, screenshots and cached content older than this. |

## `risk`

Risk scoring is explained in [rules.md](rules.md#risk-scoring). Every finding lists the signals that produced its score.

| Key | Default | Description |
| --- | --- | --- |
| `thresholds.low` | `15` | Minimum score for `low`. Lower scores are `info`. |
| `thresholds.medium` | `30` | Minimum score for `medium`. |
| `thresholds.high` | `50` | Minimum score for `high`. |
| `thresholds.critical` | `75` | Minimum score for `critical`. |
| `weights` | `{}` | Override the weight of individual signals, e.g. `{ new-outbound-host: 0 }`. |

## `failOn`

Default `--fail-on` threshold for `scan` and `diff`: `info`, `low`, `medium`, `high` (default), `critical` or `none`.

## `analysis` and `rules`

Static behaviour analysis is described in [rules.md](rules.md).

| Key | Default | Description |
| --- | --- | --- |
| `analysis.enabled` | `true` | Analyse captured scripts. |
| `analysis.maxScriptBytes` | 3 MiB | Larger scripts are not analysed. |
| `rules.<id>.enabled` | `true` | Turn a rule off. |
| `rules.<id>.severity` | rule default | Override the rule's severity. |
| `rules.<id>.weight` | from severity | Risk weight of a new match. |
| `rules.<id>.ignoreResources` | `[]` | URL/identity globs the rule ignores. |

## `domains`

| Key | Default | Description |
| --- | --- | --- |
| `allow` | `[]` | Domains/hosts never reported as new. |
| `deny` | `[]` | Domains/hosts always reported (critical), even if approved. |
| `suspicious` | `[]` | Reputation hints; raise the risk of new destinations that match. |

## `suppressions`

A list of documented suppressions. Each entry needs a `reason` and at least one of `id`, `kind`, `rule`, `resource`, `domain`; `site` and `expires` are optional. See [rules.md](rules.md#suppressing-false-positives).

## `reporting`

| Key | Default | Description |
| --- | --- | --- |
| `formats` | `[json, sarif, html]` | Report formats written after each scan. |

## `alerts`

See [alerts.md](alerts.md) for every option and the environment variables they use. Credentials must be `${ENV_VAR}` references; they are resolved only when alerts are sent.
