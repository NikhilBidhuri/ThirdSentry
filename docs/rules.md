# Detection rules and risk scoring

ThirdSentry analyses every captured script statically, using Babel to parse it into a syntax tree (it is never executed for analysis). Rules look for **behaviour worth reviewing**. None of them is proof of malicious intent: analytics libraries read cookies, chat widgets open WebSockets, payment SDKs touch card fields. What matters is **what changed**, **where** and **in which combination**.

## How indicators become findings

1. Every scanned script gets an indicator summary: how often each rule matched, a few example matches with line numbers and short excerpts (never the whole script), and the hostnames the code references.
2. When a script is approved, its indicator counts are stored in the baseline.
3. When the script changes (or a new script appears), only **new** behaviour contributes to the risk score: a rule that matches more often than in the approved version, or a rule that did not match before. An analytics script that always read cookies does not become suspicious because of a routine update; the same script suddenly reading card fields and sending beacons does.
4. If the approved version was never analysed (for example a baseline created before analysis was enabled), present behaviour counts at half weight.

Rule matches on unchanged, approved scripts never produce findings. They are visible in the scan output (`--verbose` lists all indicators per resource) for review when creating a baseline.

## Rules

| Rule | Name | Severity | Confidence | Default weight |
| --- | --- | --- | --- | --- |
| `TS-EVAL` | eval() usage | medium | high | 12 |
| `TS-NEW-FUNCTION` | Function constructor | medium | high | 12 |
| `TS-STRING-TIMER` | String passed to setTimeout/setInterval | low | high | 6 |
| `TS-SCRIPT-INJECTION` | Dynamic script injection | low | high | 6 |
| `TS-REMOTE-SCRIPT-LOAD` | Loads script from a remote URL | medium | medium | 12 |
| `TS-COOKIE-ACCESS` | document.cookie access | low | high | 6 |
| `TS-WEB-STORAGE` | localStorage/sessionStorage access | info | high | 2 |
| `TS-SENSITIVE-FIELD-ACCESS` | Accesses payment or password fields | high | medium | 22 |
| `TS-FORM-FIELD-ACCESS` | Reads form fields | low | medium | 6 |
| `TS-KEYSTROKE-CAPTURE` | Keystroke capture | medium | medium | 12 |
| `TS-CLIPBOARD` | Clipboard access | medium | high | 12 |
| `TS-BEACON` | navigator.sendBeacon | low | high | 6 |
| `TS-WEBSOCKET` | WebSocket connection | low | high | 6 |
| `TS-REMOTE-ENDPOINT` | Sends requests to absolute URLs | info | medium | 2 |
| `TS-NETWORK-API-HOOK` | Overrides network or form APIs | medium | high | 12 |
| `TS-SOURCE-REFLECTION` | Reads its own source code | info | medium | 2 |
| `TS-OBFUSCATION` | Obfuscated or heavily encoded code | medium | medium | 12 |
| `TS-EXFIL-COMBINATION` | Sensitive data access combined with data transmission | high | medium | 22 |

### TS-EVAL: eval() usage

Code is executed from a string with eval().

- **Why it matters:** eval() runs code that is only known at runtime, so the code that actually executes cannot be reviewed from the script itself. Skimmers often decode and eval their payload.
- **How to investigate:** Find what string is passed to eval and where it comes from (a constant, a decoded blob, a network response?). Code fetched or decoded at runtime deserves close review.
- **Common false positives:** Old libraries and some tag managers use eval for JSON parsing or template compilation.

### TS-NEW-FUNCTION: Function constructor

Code is compiled from a string with new Function() / Function().

- **Why it matters:** Like eval, the Function constructor turns strings into executable code, hiding it from static review.
- **How to investigate:** Check the arguments passed to the Function constructor and whether they are constant or derived from decoded or remote data.
- **Common false positives:** Template engines and some polyfills (e.g. for globalThis detection: Function("return this")()) use it legitimately.

### TS-STRING-TIMER: String passed to setTimeout/setInterval

A timer is given a string of code instead of a function.

- **Why it matters:** Timers called with a string evaluate it like eval().
- **How to investigate:** Look at the string passed to the timer and where it is built.
- **Common false positives:** Very old code sometimes uses string timers out of habit.

### TS-SCRIPT-INJECTION: Dynamic script injection

The script creates <script> elements or writes script tags into the page.

- **Why it matters:** Injecting scripts lets this code load further code that never appears in your page source. It is how tag managers work, and also how skimmers load their payload.
- **How to investigate:** Identify which scripts this code loads (they appear as runtime-injected resources in the scan) and whether they are expected.
- **Common false positives:** Tag managers, analytics loaders and widget bootstrappers all inject scripts.

### TS-REMOTE-SCRIPT-LOAD: Loads script from a remote URL

The script loads further code from an absolute URL (script src, importScripts or import()).

- **Why it matters:** Remote code loaded at runtime is outside your review and can change at any moment.
- **How to investigate:** Check that the referenced host belongs to the expected vendor. Unknown or look-alike domains are a strong warning sign.
- **Common false positives:** Vendor loaders typically fetch their main bundle from their own CDN.

### TS-COOKIE-ACCESS: document.cookie access

The script reads or writes cookies via document.cookie.

- **Why it matters:** Cookies can contain session identifiers. Scripts that read them and send data elsewhere can leak sessions (HttpOnly cookies are not readable).
- **How to investigate:** Check which cookies are read and whether their values are sent to another domain.
- **Common false positives:** Analytics, consent management and A/B testing tools read and write their own cookies.

### TS-WEB-STORAGE: localStorage/sessionStorage access

The script uses Web Storage.

- **Why it matters:** Web Storage can hold tokens or personal data that any script on the page can read.
- **How to investigate:** Check which keys are read and whether they belong to this vendor.
- **Common false positives:** Very common: analytics, consent and personalisation tools persist state this way.

### TS-SENSITIVE-FIELD-ACCESS: Accesses payment or password fields

The script selects form fields whose names suggest passwords, card numbers, CVV or similar.

- **Why it matters:** Reading payment-card or password fields is the core behaviour of form-jacking (Magecart-style) skimmers.
- **How to investigate:** Find out why this script needs these fields. Payment providers normally isolate card fields in their own iframe; a third-party script reading card fields on your page is highly unusual.
- **Common false positives:** Your own checkout code, form validation libraries and payment SDKs that are designed to wrap card inputs.

### TS-FORM-FIELD-ACCESS: Reads form fields

The script selects form inputs or listens to form submission.

- **Why it matters:** Reading form values (names, e-mail, addresses) and sending them elsewhere is how data is skimmed from checkout and login forms.
- **How to investigate:** Check which fields are read and where their values go.
- **Common false positives:** Form analytics, validation, address autocomplete and chat widgets read form fields.

### TS-KEYSTROKE-CAPTURE: Keystroke capture

The script listens to keyboard or input events.

- **Why it matters:** Listening to every keystroke can capture what users type, including passwords and card numbers, before the form is submitted.
- **How to investigate:** Check which element the listener is attached to (document-wide listeners are most concerning) and what is done with the captured keys.
- **Common false positives:** Keyboard shortcuts, search-as-you-type, accessibility tools and input masking libraries.

### TS-CLIPBOARD: Clipboard access

The script reads or writes the clipboard or listens to copy/paste events.

- **Why it matters:** Clipboard contents can include passwords, card numbers or crypto wallet addresses; clipboard writes can swap pasted values.
- **How to investigate:** Check whether the script reads pasted data or replaces copied content.
- **Common false positives:** "Copy to clipboard" buttons and rich-text editors.

### TS-BEACON: navigator.sendBeacon

The script sends data with navigator.sendBeacon.

- **Why it matters:** Beacons send data in the background, even while the page is closing, which makes them convenient for exfiltration.
- **How to investigate:** Check the destination URL and what data is sent.
- **Common false positives:** Analytics and performance monitoring commonly use beacons.

### TS-WEBSOCKET: WebSocket connection

The script opens a WebSocket connection.

- **Why it matters:** WebSockets provide a persistent two-way channel to a server, which can be used to receive commands or send collected data.
- **How to investigate:** Check the WebSocket URL and whether it belongs to the expected vendor.
- **Common false positives:** Chat widgets, live updates and collaboration tools.

### TS-REMOTE-ENDPOINT: Sends requests to absolute URLs

The script calls fetch/XMLHttpRequest or sets image URLs pointing at absolute remote endpoints.

- **Why it matters:** Requests to remote endpoints are how data leaves the page. On its own this is normal; it matters when combined with access to sensitive data, or when the endpoint is new or unknown.
- **How to investigate:** Compare the referenced hosts with the vendors you expect.
- **Common false positives:** Almost every third-party script talks to its own backend.

### TS-NETWORK-API-HOOK: Overrides network or form APIs

The script replaces fetch, XMLHttpRequest, sendBeacon, form submission or addEventListener.

- **Why it matters:** Wrapping network or form APIs lets a script see (and alter) every request and form submission on the page, including those of other scripts.
- **How to investigate:** Determine why the script needs to intercept other code's requests. Monitoring tools do this; so do skimmers.
- **Common false positives:** Real-user-monitoring, error tracking and some analytics SDKs instrument fetch/XHR.

### TS-OBFUSCATION: Obfuscated or heavily encoded code

The script shows several signs of deliberate obfuscation.

- **Why it matters:** Obfuscation hides what code does. Legitimate vendors usually minify, but rarely obfuscate with encoded string tables, hex-named variables and runtime decoding.
- **How to investigate:** Try a deobfuscator or beautifier on the retained content, look for decoded URLs and eval/Function usage, and ask the vendor why the code is obfuscated.
- **Common false positives:** Some commercial anti-fraud, bot-detection and licensing scripts are obfuscated on purpose.

### TS-EXFIL-COMBINATION: Sensitive data access combined with data transmission

The same script both reads sensitive input (form fields, keystrokes, clipboard) and sends data to remote endpoints.

- **Why it matters:** Each behaviour alone is common. Together, reading what users type and sending data elsewhere is the pattern of a data skimmer.
- **How to investigate:** Trace whether values read from inputs flow into the outgoing requests. Check the destination hosts. On payment or login pages, treat this as urgent until explained.
- **Common false positives:** Form analytics and session-replay tools legitimately capture input (often masked) and upload it. Verify the vendor and its masking configuration.


### Coverage limits of static analysis

- Code that is built and executed at runtime (`eval`, `new Function`, code fetched from a server) is only visible as the call that executes it, which is why the dynamic-code rules exist.
- Property names computed at runtime (`window[atob('ZG9jdW1lbnQ=')]`) cannot be resolved statically. The obfuscation rule flags code that relies heavily on such tricks.
- Simple aliases are resolved (`var d = document`, `var e = eval; e(p)`, `(function (w, d) { ... })(window, document)`); arbitrary data flow is not tracked.
- Evasions that are recognised: optional calls and members (`eval?.(p)`, `document?.cookie`), tagged templates (``Function`x` ``, ``setTimeout`x` ``), constructor gadgets (`(function(){}).constructor(p)()`, `[]["filter"]["constructor"](p)()`), constant-folded computed names (`window['ev' + 'al']`, `document['coo' + 'kie']`, names held in a `const`), and hooking `fetch`, `XMLHttpRequest` or `sendBeacon` through assignment or `Object.defineProperty`.
- Scripts are parsed the way the browser runs them: classic scripts with Annex B HTML-like comments (`<!--` and a line-leading `-->` start a comment), modules as modules, and resources of unknown type (code fetched by `fetch`/XHR) as classic script first. Parsing with the wrong goal would let a payload hide in what one side thinks is a comment.
- Comment- and whitespace-only changes are normally "formatting only". If the script reads its own source (`TS-SOURCE-REFLECTION`) or runs strings as code (`TS-EVAL`, `TS-NEW-FUNCTION`, `TS-STRING-TIMER`), such a change is reported with the `formatting-with-reflection` signal and medium confidence instead.
- Scripts larger than `analysis.maxScriptBytes` (default 3 MiB) are not analysed; their hashes are still compared.

## Configuring rules

```yaml
rules:
  TS-WEB-STORAGE:
    enabled: false              # turn a rule off everywhere
  TS-EVAL:
    severity: high              # change severity (and therefore default weight)
  TS-KEYSTROKE-CAPTURE:
    weight: 25                  # set the risk weight directly
    ignoreResources:            # resources (URL or identity globs) this rule ignores
      - https://widget.chat-vendor.example/*

analysis:
  enabled: true
  maxScriptBytes: 3145728
```

Unknown rule IDs are configuration errors.

## Risk scoring

Every finding has a **score** (0-100), a **severity** derived from the score, a separate **confidence**, and a **category**:

- **Severity** answers "how bad would this be if it were malicious?" Thresholds are configurable (`risk.thresholds`, defaults: low 15, medium 30, high 50, critical 75).
- **Confidence** answers "how sure are we about the facts?" It is high when content was captured and compared byte for byte, medium for heuristics, and low when content could not be captured.
- **Category**: `high-priority` (severity high or critical), `suspicious` (behavioural signals present), `review` (a change that needs a human decision) or `informational`.

The score is the sum of the weights of the signals that apply, capped at 100. Each finding lists its signals, so the rating is always explainable. Example:

```
HIGH confidence high  Third-party script changed on a sensitive page  TS-3f1c0a9b2e7d
    https://js.payments.example/v3/
    why: +25 content of an approved third-party script changed; +15 observed on a page marked as sensitive;
         +22 new behaviour: accesses payment or password fields; +25 the changed script itself references
         the new outbound destination (score 87)
```

### Signals

| Signal | Default weight | Meaning |
| --- | --- | --- |
| `hash-changed-third-party` | 25 | Content of an approved third-party script changed |
| `hash-changed-first-party` | 15 | Content of an approved first-party script changed |
| `inline-changed` | 18 | An approved inline script changed |
| `formatting-only` | 3 | Only formatting/comments changed; the parsed code is identical |
| `new-third-party-script` | 25 | A third-party script that is not in the baseline started loading |
| `new-first-party-script` | 10 | A first-party script that is not in the baseline started loading |
| `new-inline-script` | 12 | A new inline script appeared |
| `new-script-domain` | 25 | Scripts are now loaded from a domain never approved for this site |
| `runtime-injection` | 10 | The script was injected at runtime by another script |
| `sensitive-page` | 15 | Observed on a page marked as sensitive (payments, login or personal data) |
| `unexpected-resource-type` | 15 | A resource type that is rarely needed (WebAssembly, blob/data script, service or shared worker) |
| `type-changed` | 15 | The resource is now loaded as a different type |
| `redirect-changed` | 12 | The script URL now redirects to a different destination |
| `redirect-cross-host` | 15 | The new redirect destination is on a different host |
| `moved-cross-domain` | 20 | Approved code is now served from a different domain |
| `moved-same-domain` | 3 | Approved code is now served from a different URL on the same domain |
| `sri-mismatch` | 45 | The Subresource Integrity attribute does not match the served content (behavioural) |
| `content-unavailable` | 10 | The script content could not be captured, so changes cannot be ruled out |
| `analysis-unavailable` | 10 | The script could not be analysed (parse error or too large), so behaviour changes cannot be ruled out |
| `analysis-regression` | 20 | The previous version could be analysed but this one cannot (obfuscation or unusual syntax is a common reason) (behavioural) |
| `formatting-with-reflection` | 12 | Only formatting changed, but the script reads its own source or runs strings as code, where formatting is observable |
| `page-failed` | 20 | The page could not be scanned, so none of its scripts were verified |
| `coverage-degraded` | 15 | The page was only partly scanned (budget limit, timeout or dropped data), so changes may be hidden |
| `resource-removed` | 4 | An approved resource no longer loads |
| `new-outbound-domain-third-party` | 25 | The page now sends requests to a third-party domain never approved for this site |
| `new-outbound-domain-first-party` | 8 | The page now sends requests to a new first-party domain |
| `new-outbound-host` | 6 | A new hostname under an already approved domain is contacted |
| `data-sending-request` | 10 | Requests to the new destination send data (POST, beacon or similar) |
| `blocked-destination` | 15 | The page tried to reach a blocked (internal or disallowed) address (behavioural) |
| `iframe-origin-added` | 18 | A new iframe origin is embedded in the page |
| `iframe-origin-removed` | 3 | An approved iframe origin is no longer embedded |
| `correlated-new-destination` | 20 | On the same page, a new outbound destination appeared in the same scan (behavioural) |
| `denylisted-domain` | 80 | The domain is on the configured denylist (behavioural) |
| `suspicious-domain` | 30 | The domain matches a configured reputation warning (domains.suspicious) (behavioural) |
| `ip-address-destination` | 15 | The destination is a raw IP address rather than a domain name (behavioural) |
| `pinned-hash-mismatch` | 55 | A pinned script does not match any allowed hash, whatever the baseline says (behavioural) |
| `policy-accepted-update` | 0 | The content changed, which a script policy explicitly accepts |
| `script-references-new-destination` | 25 | The changed script itself references the new outbound destination (behavioural) |

Rule matches add signals named `new-rule:<rule id>` (or `rule:<rule id>` at half weight when the previous version was not analysed). Rules with a weight of 10 or more count as behavioural and move a finding into the `suspicious` category.

Override any weight in the configuration:

```yaml
risk:
  thresholds: { low: 15, medium: 30, high: 50, critical: 75 }
  weights:
    new-outbound-host: 0           # never care about new hosts under approved domains
    hash-changed-third-party: 30
```

## Outbound domain policy

```yaml
domains:
  allow: [googletagmanager.com, '*.google-analytics.com']  # never reported as new
  deny: [known-bad.example]                               # always reported (critical), even if in a baseline
  suspicious: ['*.top', '*.xyz']                          # reputation hints: +30 when a new destination matches
```

Patterns match the hostname or the registrable domain; `*.example.com` matches subdomains. Requests to raw IP addresses add the `ip-address-destination` signal.

## Suppressing false positives

Suppressions live in the configuration, require a reason, and can expire:

```yaml
suppressions:
  # Remove one rule's contribution for one vendor (the change itself is still reported)
  - rule: TS-KEYSTROKE-CAPTURE
    resource: https://widget.chat-vendor.example/*
    reason: Chat widget listens to keystrokes for typing indicators (reviewed 2026-11-02)
  # Accept a specific finding until a date
  - id: TS-3f1c0a9b2e7d
    reason: Vendor confirmed release 4.2, ticket SEC-118
    expires: 2026-12-31
  # Ignore all new hosts under one vendor
  - kind: new-outbound-host
    domain: '*.cdn-vendor.example'
    reason: Vendor rotates edge hostnames
```

- A suppression with `rule` removes only that rule's signal from matching findings and re-scores them, so it cannot hide unrelated problems in the same change.
- Any other suppression (`id`, `kind`, `site`, `resource`, `domain`) marks the whole finding as **suppressed**. Suppressed findings stay in reports (marked as such) but do not trigger alerts or fail builds.
- Expired suppressions stop applying and produce a warning.
- A suppression may name a script policy (`policy: <name>`) to match every finding that policy affected. For vendors whose scripts rotate, prefer a [script policy](policies.md), which never hides new suspicious behaviour.

## Coverage findings

A page that fails to scan, is scanned only partly (time budget, script/request limits, navigation timeout) or is in the baseline but was not scanned at all (page limit, unreachable site) produces a `page-failed` or `coverage-degraded` finding. Without it, every script change on that page would be invisible. On `sensitivePages` the `sensitive-page` signal is added, so these rate higher. The ID is derived from site, page, kind and the sorted list of reasons (issue codes), so the same ongoing problem alerts once; a different reason, or escalation from partial to failed, is a new finding.

## Inline scripts

Inline and blob scripts are matched per page and frame without relying on DOM position: an exact (or formatting-only) content match anywhere on the page means unchanged, and leftover new and removed scripts on the same page are paired by position and size and reported as one modified script. A body that was truncated at the capture limit can never match: it is reported as "content could not be verified".

## Repeated findings

Finding IDs are fingerprints of the site, change kind, resource, host (where the finding is about a specific host) and current content hash. The same unchanged problem keeps the same ID across scans and is marked `recurring` after its first appearance (`new`). If the script changes again, the ID changes and the finding is `new` again. Alerts use this to avoid repeating themselves (see [alerts.md](alerts.md)). The state is kept in `.thirdsentry/state/findings.json`.
