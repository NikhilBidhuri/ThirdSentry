# Demo: catching a Magecart-style attack

`npm run demo` starts a small online shop, **Acme Outfitters**, scans it, approves what it saw, simulates a compromise and scans again. The whole run takes under a minute and stays on your machine: the shop answers for fake `.test` hostnames on `127.0.0.1`, and ThirdSentry reaches them through its egress proxy via `security.network.resolverOverrides`.

```bash
npm ci && npx playwright install chromium
npm run demo                      # build if needed, run the scenario, print the report path
npm run demo -- --open            # ...and open the HTML report
npm run demo -- --keep-server     # keep the shop running to try other commands yourself
npm run demo -- --port 8484       # use a fixed port
npm run demo -- --scenario snippet-hijack   # the Optimizely-style attack instead (see below)
```

## The shop

| Host | Role |
| --- | --- |
| `shop.demo.test` | the merchant: `/` (products) and `/checkout` (a payment form, marked as a sensitive page) |
| `cdn.payvendor.test` | the payment provider's SDK, `/v3/pay.js` |
| `tags.analytics.test` | an analytics tag that sends a page-view beacon |
| `cdn.experiments.test` | an A/B-testing vendor's snippet, `/js/1029384756.js`, on every page. It contains the vendor code plus the customer's "project JavaScript" |
| `c2.attacker.test` | the attacker's server in the `snippet-hijack` scenario. It is this same local server and **discards everything it receives** |
| `cdn-assets-cloud.test` | the attacker's lookalike "CDN" (only used once the shop is compromised) |
| `collect.exfil.test` | the attacker's collection endpoint. It is this same local server and **discards everything it receives** |

## Scenario 1: Magecart-style attack (default)

After the baseline is approved, the shop switches to its `compromised` state, and five things change at once:

| # | What changes | Real-world pattern | What ThirdSentry reports |
| - | --- | --- | --- |
| 1 | A card skimmer is appended to the payment vendor's `pay.js`. It reads card fields on `change`/`submit` and beacons them out as an image request. | Supply-chain compromise of a vendor script (British Airways 2018, Ticketmaster 2018) | **critical** `resource-modified`: content of an approved third-party script changed on a sensitive page, with new behaviour `TS-SENSITIVE-FIELD-ACCESS`, `TS-FORM-FIELD-ACCESS` and `TS-EXFIL-COMBINATION` |
| 2 | A new `jquery.min.js` is loaded from `cdn-assets-cloud.test`. It is obfuscated (string table, hex identifiers, base64) and runs `eval`. | Lookalike or hijacked CDN domain (polyfill.io 2024) | **critical** `resource-added` with `TS-EVAL` and `TS-OBFUSCATION`; **medium** `new-script-domain` |
| 3 | The page talks to `collect.exfil.test` | Exfiltration endpoint | **medium** `new-outbound-domain` |
| 4 | The checkout form now posts to `collect.exfil.test` and asks for a "card PIN" | Form-jacking / fake payment form | **critical** `payment-form-changed` (PCI DSS 11.6.1) |
| 5 | `Content-Security-Policy` and `X-Frame-Options` are no longer sent on `/checkout` | Attacker or misconfiguration weakens defences | **critical** `security-header-changed` (PCI DSS 11.6.1) |

The analytics tag and the shop's own `app.js` don't change, and they are not flagged. The compromised scan exits with code `1` (`--fail-on high`), so it would fail a CI job or cron check.

## Scenario 2: Optimizely-style snippet hijack (`--scenario snippet-hijack`)

This scenario is modelled on the [November 2026 Optimizely incident](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/). The attacker added code to the "project JavaScript" of customers' A/B-testing snippets, so a trusted vendor URL started serving a loader. Here, only one thing changes in the shop: the A/B-testing snippet. Its URL is unchanged, but code is appended to its project JavaScript. That code:

1. decodes a script URL from base64 and injects `<script src="http://c2.attacker.test/track.js">`;
2. if that script is blocked, runs an inline copy through `eval` (here only a stub that sets a flag).

`track.js` then:
- swaps crypto wallet addresses when text is copied and in outgoing `fetch`/XHR bodies;
- reads card fields on submit and sends them with `sendBeacon`;
- checks in with the page URL and cookies.

| What ThirdSentry reports | Severity |
| --- | --- |
| `resource-added` for `track.js`, with new behaviour `TS-CLIPBOARD`, `TS-NETWORK-API-HOOK`, `TS-SENSITIVE-FIELD-ACCESS`, `TS-EXFIL-COMBINATION`, injected at runtime by another script | critical |
| `resource-modified` for the snippet (same URL, new content) on a sensitive page, with new `TS-EVAL` and `TS-SCRIPT-INJECTION` | critical |
| `new-outbound-domain` `attacker.test`, receiving POSTs and beacons | high |
| `new-script-domain` `attacker.test` | medium |

On `/checkout`, the shop's CSP (`script-src` without `c2.attacker.test` and without `'unsafe-eval'`) stops `track.js` and the `eval` fallback, so the scan lists that copy as `unavailable`. On `/`, which has no CSP, the payload runs. That is the case for a strict CSP and a scheduled scan together: CSP limits the damage, and the scan tells you the vendor snippet changed.

All the "malicious" code in both scenarios is a harmless re-implementation of publicly documented patterns. It runs only against the local shop and sends nothing off your machine.

## Exploring further

With `--keep-server`, the shop stays up after the run. The generated config lives in `demo/.work/thirdsentry.yml`:

```bash
node dist/cli/bin.js --config demo/.work/thirdsentry.yml diff            # code diff of pay.js
node dist/cli/bin.js --config demo/.work/thirdsentry.yml inventory       # PCI DSS 6.4.3 script inventory
curl http://127.0.0.1:<port>/__state/clean                                # undo the attack (or: compromised, snippet-hijack)
node dist/cli/bin.js --config demo/.work/thirdsentry.yml scan
```

## Files

- [`site/server.mjs`](site/server.mjs): the shop, both states, and `demoConfig(port)`, the `thirdsentry.yml` used for scanning.
- [`run.mjs`](run.mjs): the `npm run demo` script.
- [`../tests/integration/demo.test.ts`](../tests/integration/demo.test.ts): asserts that every attack above is detected, so the demo and the README stay true.
- [`../scripts/demo/update-assets.mjs`](../scripts/demo/update-assets.mjs): `npm run demo:assets` regenerates `docs/assets/demo.gif`, `sample-report.html` and `report-screenshot.png` from a real run.
