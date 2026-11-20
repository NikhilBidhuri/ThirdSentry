# PCI DSS v4.0 support

ThirdSentry helps with two requirements that concern scripts and HTTP headers on payment pages. It **supports** compliance work; it does not make you compliant and its output is not an attestation. Your QSA decides what evidence is sufficient.

| Requirement | What ThirdSentry gives you |
| --- | --- |
| 6.4.3: every script on payment pages is authorized, its integrity assured, and an inventory with written justification is kept | `thirdsentry inventory`, the inventory file, baseline approval state, SRI/hash information, `script-unjustified` findings |
| 11.6.1: a change- and tamper-detection mechanism alerts on unauthorized changes to HTTP headers and payment page content, evaluated at least weekly | `security-header-changed` and `payment-form-changed` findings on every scheduled scan |

Mark your payment pages as `sensitivePages` in `thirdsentry.yml`. Everything below applies to those pages (header baselines apply to all scanned pages).

## Script inventory (6.4.3)

One YAML file per site, edited by humans and committed to Git: `.thirdsentry/inventory/<site>.yml`.

```yaml
version: 1
scripts:
  - url: "https://js.stripe.com/v3/*"      # URL pattern (* wildcard); survives version changes
    purpose: Card entry iframe; required for payment processing
    owner: payments-team
    authorizedBy: Jane Doe (CISO)
    authorizedAt: 2026-01-10
    reviewBy: 2027-01-10
    notes: Reviewed with vendor SOC 2 report
  - identity: "url:https://shop.example/js/checkout.js"   # exact resource identity
    purpose: First-party checkout logic
    owner: web-team
    authorizedBy: Jane Doe
    authorizedAt: 2026-01-10
```

An entry matches by `identity` (exact, `*` allowed) or `url` (matched against the final, requested and identity URL). The most specific entry wins. An entry counts as a justification when `purpose`, `owner`, `authorizedBy` and `authorizedAt` are all set. Inline scripts have no URL: match them with an `identity` glob such as `inline:/checkout|*`.

### Commands

```
thirdsentry inventory                      # scripts on sensitive pages of the latest scan
thirdsentry inventory --all                # every script
thirdsentry inventory --format csv|json|markdown|table [-o file]
thirdsentry inventory --check              # exit 1 if a script on a sensitive page lacks justification or is overdue
thirdsentry inventory add "<identity|url>" --purpose ... --owner ... --authorized-by ... [--review-by YYYY-MM-DD] [--site shop]
thirdsentry inventory set "<identity|url>" --purpose ...   # update fields of an existing entry
```

`add` and `set` edit only the inventory file (comments are preserved); they never touch baselines. Approving a script's content (`thirdsentry baseline`) and authorizing its purpose (inventory) are separate decisions.

Statuses: `authorized` (justified, review not overdue, current hash approved in the baseline), `missing-justification`, `review-overdue`, `not-approved` (content not in the baseline). Each row also shows the approved SHA-256, the current SHA-256 and SRI value, and whether the page's `integrity` attribute is valid. The CSV export neutralises spreadsheet formulas; entries that match no script are listed as stale.

### In the analysis report

When a site has an inventory file, or `pci.requireJustification: true`, the report gains a `pci` section (JSON, HTML) with counts and gaps. With `pci.requireJustification: true` each unjustified script or overdue review on a sensitive page also becomes a `script-unjustified` finding (info/low, stable ID per script and status), which flows through suppressions, alerts and SARIF. The default is `false`.

## Header change detection (11.6.1)

For every page ThirdSentry records, and the baseline approves, the normalised values of: Content-Security-Policy, CSP-Report-Only, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP and CORP. Re-ordering or re-casing is not a change. Findings of kind `security-header-changed` are rated by impact:

- CSP: compared semantically with the CSP analyzer. A new `'unsafe-inline'`/`'unsafe-eval'`, a wildcard or scheme source, a new script host or a removed directive is *weakened*; removed sources, added directives and resolved analyzer problems are *strengthened* (info).
- A removed header rates higher than an added one; a CSP removal rates highest.
- On sensitive pages the `sensitive-page` signal is added to weakening changes.

## Payment form integrity (11.6.1)

On sensitive pages a structural snapshot of all forms is taken (`src/browser/form-snapshot.ts`): form action origin/path (query strings are ignored), method, fields (name, type, autocomplete, payment-like) and the origins of iframes that host payment fields. Field values are never read. "Payment-like" is computed by trusted code (`cc-number`, `cc-csc`, `cc-exp` autocomplete tokens, names matching card, cvv, cvc, pan, expiry). The baseline stores a fingerprint per page. `payment-form-changed` findings:

| Change | Severity (sensitive page) |
| --- | --- |
| action origin changed (critical if the new origin was never part of the page) | high / critical |
| new payment form (injected fake form) | high / critical |
| new payment-like input | high |
| payment field removed or renamed | medium |
| payment iframe from a new origin | medium / high |
| order, whitespace, query string | none |

## Baselines

Header and form state is approved through the normal flow: `thirdsentry baseline` (full) or `thirdsentry baseline --approve <finding-id>` (selective, per page and per part). Baseline format version 2 adds `pageSecurity`. Baselines created before this feature are read unchanged; their pages produce one low-severity `security-baseline-missing` notice per site, not a flood of changes, until the current state is approved.

## What this does not cover

- ThirdSentry scans from outside with a synthetic browser, on the schedule you run it (use at least weekly for 11.6.1). It does not see what real customers' browsers receive, personalised content, or pages behind a login unless you can scan them.
- It detects *changes* against what a human approved. If a malicious script was approved, or was present when the baseline was created, it is not flagged. It does not judge whether a justification is adequate.
- Attackers can serve scanners clean pages (cloaking). Scripts or forms that appear only after user interaction, in closed shadow roots or in cross-origin frames that cannot be inspected are not captured.
- 6.4.3 also requires integrity *assurance* in the browser; ThirdSentry reports SRI status and hashes but does not enforce them. Use SRI and a CSP for enforcement.
- 11.6.1 asks for alerts to *responsible personnel*; configure [alerts](alerts.md) and an on-call process. Retain reports and baseline Git history as evidence.
- Header baselines cover the main document response only, not API or asset responses.
