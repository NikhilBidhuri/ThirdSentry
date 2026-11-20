# Known limitations

ThirdSentry tries to be explicit about what it cannot see. Every scan report repeats the relevant limitations so that "no findings" is never mistaken for "nothing there".

## Coverage of a single scan

- **Only configured pages, once, without interaction.** ThirdSentry does not click, scroll, log in, accept consent banners or submit forms. Scripts loaded only after interaction, on unlisted pages, or for authenticated users are not observed.
- **Variants.** Vendors can serve different code by geography, user agent, time, consent state, A/B bucket or bot detection. A scan observes one variant. Malicious code that deliberately hides from automated or headless browsers may not be served at all.
- **Timing.** Pages are observed for a bounded time (`timeout`, `networkIdleTimeout`, `settleMs`). Code that loads later, or sends data later, is not seen.

## Script discovery

| Resource | Coverage |
| --- | --- |
| External `<script src>` (classic or module) | Full: network response bytes are captured outside the page. |
| Inline `<script>` | Captured from the DOM by a MutationObserver (including scripts removed again) and by an end-of-scan DOM snapshot. Limited to `maxInlineScriptBytes`. |
| Runtime-injected scripts | Detected by hooking DOM insertion APIs in the page. A hostile script can detect or bypass these hooks; the network-level record of the request remains. |
| `import()` and static module imports | Captured from the network. Classified as `module` using `Sec-Fetch-Mode` (sent only to HTTPS origins), the `.mjs` extension, or import/export syntax in the body. A module with neither import nor export loaded over plain HTTP may be classified as `script`. |
| Scripts inside iframes | Captured, including cross-origin iframes. |
| Dedicated and shared workers | Worker scripts are captured from the network; `importScripts()` requests are captured where the browser reports them. |
| Service workers | See below. |
| `blob:` scripts | Captured best-effort by hooking `URL.createObjectURL` in the page. Blobs created before the hook (impossible in practice) or by tampered page code may be missed. Blob URLs are random, so blob scripts are identified by page, frame and content hash. |
| `data:` scripts | Decoded from the script element. |
| WebAssembly | Captured as `wasm` when loaded over the network with `application/wasm` or a `.wasm` URL. Not parsed or analysed. |
| `eval()`, `new Function()`, string timers | Not captured as separate resources. The creating script is captured and the static analysis flags these patterns. |
| Inline event handlers (`onclick="..."`), `javascript:` URLs | Not captured. |
| Browser extensions, OS-level software | Out of scope. |

### Service workers

Playwright only partly exposes service workers:

- **Chromium** reports service worker creation and the requests they make.
- **Firefox and WebKit** do not expose service-worker network traffic, and responses served from a service worker's cache may hide network activity.

ThirdSentry therefore defaults to `serviceWorkers.strategy: block`:

- Registration is refused, so every request is made by the page and observable.
- Registrations are recorded via an in-page hook, and each registered script is fetched separately (through the same egress proxy) so it is still hashed and tracked over time.
- **Behavioural difference:** the site runs without its service worker. Offline caching, push and background sync do not run, and some sites behave differently. The service worker's own runtime behaviour, including requests it would make, is not exercised.

With `strategy: allow`, service workers run normally. Their script and traffic are observed in Chromium only, and some requests can be served from service-worker caches without reaching the network.

## Content capture

- Bodies larger than `limits.maxResourceBytes` are tracked by identity only (`too-large`).
- Some responses do not expose a body to Playwright (for example certain cached or aborted responses). These are tracked with content status `unavailable`.
- Captured content is used for hashing and analysis and is discarded afterwards unless `retention.storeScriptContent` is enabled.

## In-page instrumentation and evidence limits

- The end-of-scan DOM snapshot runs through `frame.evaluate`, which executes in the page's main JavaScript world. It is not tamper-proof: a hostile page can alter the DOM APIs it uses. Snapshot and mutation-observer data (inline script text, `integrity`, "inserted by script") is therefore treated as page-reported context. It can add signals, never remove network-derived ones: any report of runtime injection marks a script dynamic, and an `integrity` value is only used for an SRI check when the snapshot corroborates it. A CDP isolated world would be stronger but is Chromium-only and has not been implemented.
- Evidence per page and per scan is bounded (`limits.maxEvidenceBytesPerPage`, `limits.maxEvidenceBytesPerScan`, `limits.maxReportCallsPerPage`). Once exhausted, bodies are recorded with content status `budget-exceeded` (identity and network facts are kept) and the page is marked partial with an issue. Reports beyond the per-page worker/blob entry limits, blobs the instrumentation could not capture, and frames the snapshot could not inspect before the time budget are counted and also mark the page partial.
- Evidence is written incrementally by the browser worker (one file per page). If the worker crashes or times out, completed pages and sites are kept; the page in progress and the not-yet-scanned pages are marked failed with an issue, and the scan carries a `worker-incomplete` issue. On timeout the worker gets SIGTERM and a grace period, then the whole process tree (including browsers) is killed.

## Network monitoring

The browser is observed through Playwright and through ThirdSentry's egress proxy. This does **not** capture every possible way data can leave a browser:

- WebRTC data channels and QUIC are disabled at launch so they cannot bypass the proxy; a site that depends on them will behave differently.
- DNS-based exfiltration (encoding data into hostnames) appears only as requests to unusual hostnames; DNS queries made by the proxy itself are not monitored.
- Data sent after the observation window, or only after user interaction, is not seen.
- HTTPS request and response bodies are not recorded (by design, for privacy).

## Static analysis

Rules are heuristics over the syntax tree. They highlight behaviour worth reviewing; they do not prove intent. Analytics and payment libraries legitimately read cookies, use storage and send beacons, and malicious code can be written to avoid every rule. Obfuscated code may hide what it does.

## Browser emulation

Mobile profiles are emulation on desktop engines. `mobile-webkit` is not a real iPhone and `desktop-webkit` is not Safari. Real-device-only code paths are not exercised.

## Isolation

In `process` isolation mode the browser runs as the same operating-system user as ThirdSentry. Secrets are kept out of its environment, but it is not filesystem-isolated. For strong isolation use the container deployment in [docker.md](docker.md). See [security.md](security.md).
