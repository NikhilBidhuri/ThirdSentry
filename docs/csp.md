# CSP analysis

`thirdsentry csp-lint` analyses Content-Security-Policy headers and explains weaknesses in plain language. A good CSP limits what injected or compromised scripts can do; ThirdSentry's change monitoring tells you when the scripts you allow change. The two complement each other.

> CSP linting checks the policy text for known weaknesses. A clean result does **not** guarantee protection: a policy can still allow compromised third-party code from trusted hosts, and CSP does not stop malicious code served from a source you allow.

## Usage

```bash
npx thirdsentry csp-lint https://www.example.com https://www.example.com/checkout
npx thirdsentry csp-lint --from-scan            # headers captured by the latest scan, no network
npx thirdsentry csp-lint --json https://www.example.com
npx thirdsentry csp-lint --fail-on error https://www.example.com   # for CI
```

| Option | Description |
| --- | --- |
| `[urls...]` | URLs to fetch. Each is fetched twice (to detect static nonces). |
| `--from-scan` | Analyse the `Content-Security-Policy` headers recorded for each page in the latest scan. |
| `-s, --site <names>` | With `--from-scan`, only these sites. |
| `--fail-on <level>` | Exit `1` if any finding is at this level or worse: `error`, `warning`, `info`, `none` (default). Exit `3` if a URL could not be fetched. |

URLs are fetched with the same SSRF protections as the scanner: every request and redirect hop is checked against the network policy, DNS is resolved once and the connection goes to the validated address, and only `http:`/`https:` are allowed. If a `thirdsentry.yml` is present, its `security.network` settings apply.

## Levels

| Level | Meaning |
| --- | --- |
| **error** | A policy defect that leaves a known attack path open (e.g. `'unsafe-inline'` honoured, scripts from any host, missing `object-src` restriction, static nonce). |
| **warning** | A recommendation that needs review (e.g. missing `form-action`, allowlist without nonces, hosts known to enable bypasses). |
| **info** | Informational, including configurations that are correct but often misunderstood (e.g. `'strict-dynamic'` with nonces). |

## What is checked

| Check | Level |
| --- | --- |
| No policy at all / only report-only policies | error |
| Missing `default-src` | warning |
| No script restriction (no `script-src`, no `default-src`) | error |
| `'unsafe-inline'` honoured (no nonce or hash) | error |
| `'unsafe-inline'` present but neutralised by nonce/hash | info |
| `'unsafe-eval'` | warning |
| Wildcard (`*`) or scheme-only (`https:`) script sources | error |
| `data:` in script sources | error |
| `'strict-dynamic'` without nonce or hash | error |
| `'strict-dynamic'` with nonce/hash | info (recommended setup) |
| Host allowlist without nonces/hashes | warning |
| Allowed hosts known for JSONP/user-content bypasses (e.g. `*.googleapis.com`, `cdn.jsdelivr.net`, `*.cloudfront.net`) | warning |
| More than 15 allowed script hosts | warning |
| `'unsafe-hashes'` | warning |
| Nonce shorter than 16 characters | warning |
| Same nonce in two consecutive responses | error |
| `object-src` not `'none'` (after fallback) | error |
| Missing `base-uri` | warning (error for nonce/strict-dynamic policies) |
| Missing `form-action` | warning |
| No `report-to` / `report-uri` | warning |
| Missing `frame-ancestors` | info |
| No `require-trusted-types-for` | info |
| Duplicate or unknown directives, invalid sources (e.g. unquoted `self`) | warning / error |

## Semantics ThirdSentry gets right

- **Directive fallback.** `script-src-elem` → `script-src` → `default-src`; `worker-src` → `child-src` → `script-src` → `default-src`; `frame-src` → `child-src` → `default-src`; and so on. `base-uri`, `form-action`, `frame-ancestors`, `sandbox` and reporting directives **never** fall back to `default-src`.
- **Multiple policies.** Several `Content-Security-Policy` headers, or comma-separated policies in one header, are all enforced: a resource must satisfy every policy. A weakness in one policy that another enforced policy blocks is reported as *mitigated* (info) rather than as an error.
- **Report-only policies** never count as protection.
- **First directive wins.** Browsers ignore repeated directives; duplicates are reported.
- **Nonces and hashes neutralise `'unsafe-inline'`** in CSP Level 2+ browsers.
- **`'strict-dynamic'`** makes CSP3 browsers ignore host allowlists, `'self'` and `'unsafe-inline'`, trusting only nonce/hash-approved scripts and the scripts they load. This is the recommended modern configuration, not a weakness. It does mean that a trusted loader (for example a tag manager) can load any script, which is exactly why monitoring those scripts for changes matters.

## Limits

- Only HTTP response headers are analysed. `<meta http-equiv="Content-Security-Policy">` policies are not parsed (they also cannot carry `frame-ancestors`, reporting or `sandbox`).
- The linter does not check that your pages actually use the nonces correctly, or which scripts your allowlist really needs. Compare the allowlist with the script domains in your ThirdSentry scan report.
- Browser support differs for some directives (`trusted-types`, `script-src-elem`). Recommendations assume a current browser.
