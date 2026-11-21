# Privacy and data retention

ThirdSentry visits your pages as an anonymous visitor (fresh browser context, no cookies, no login) and records metadata about the code that runs. Third-party scripts can contain proprietary code and configuration, and URLs can contain identifiers, so ThirdSentry stores as little as possible by default.

## What is stored, and where

| Data | Default | Location | Notes |
| --- | --- | --- | --- |
| Script URLs (original and final), resource identity, type, party, pages, frame | stored | scan results, baselines, reports | Script URLs keep their query strings because they are part of a script's identity (e.g. `gtm.js?id=GTM-XXXX`). |
| SHA-256, SRI and normalised hashes; size | stored | scan results, baselines, reports | |
| Allowlisted response headers of scripts (content type, cache, ETag, server, CORS, CSP) | stored | scan results | Cookies, `Set-Cookie`, `Authorization` and every header not on the allowlist are dropped. |
| DOM position of inline scripts | stored | scan results | |
| Behaviour indicators: rule counts, up to 5 matches per rule with a short excerpt (≈140 characters) and line number, referenced hostnames | stored | scan results, reports | Excerpts are not sent in alerts. |
| Outbound requests: URL, method, host, type, frame, status, timestamp | stored, capped at 1000 per page | scan results | Values of query parameters whose names suggest secrets or personal data (`token`, `session`, `email`, `card`, `password`, `key`, ...) are replaced by `[REDACTED]`; fragments and URL credentials are removed. |
| Page errors | up to 20 per page, redacted | scan results | Bearer tokens and JWT-like strings are removed. Console messages are counted, not stored. |
| CSP headers of scanned pages | stored | scan results | |
| Blocked connection attempts | stored | scan results | Host, port, reason. |
| **Script bodies** | **only some** | `.thirdsentry/cache/content/` | By default (`retention.scriptContent: findings`): bodies of approved versions and of versions behind findings (and, for a site with no baseline yet, all of its scripts, because each awaits approval). Needed for code diffs. `none` stores nothing, `all` stores every body. Content-addressed, git-ignored; may contain proprietary vendor code and any secrets embedded in scripts. |
| Screenshots | **not taken** | `reports/screenshots/` | Only with `captureScreenshots: true`. Screenshots can show personal data displayed on the page. |
| Finding/alert state | stored | `state/findings.json` | Finding IDs, timestamps, severities. |
| Raw worker evidence | transient | temporary directory | Includes captured bodies for hashing; deleted after each scan (process mode) or kept in the evidence volume until the next scan (Docker). |

**Never collected or stored:** cookies, authentication headers, session tokens in headers, request bodies, response bodies of non-script resources, form contents, keystrokes, or anything from a logged-in session (ThirdSentry does not log in).

## Reports and alerts

- **Reports** (`report.json`, `report.sarif`, `report.html`) contain findings with URLs, hashes, signals and evidence, plus the scan summary. The HTML report additionally lists every script and outbound host.
- **Alerts** contain the finding title, explanation, affected resource URL, hashes, compact evidence, next steps and a report location. Code excerpts and script bodies are never included.
- Treat reports as internal security documents. In public repositories, do not publish them; the GitHub Action uploads them as workflow artifacts, which follow your repository's access rules.

## What goes into Git

`thirdsentry init` creates `.thirdsentry/.gitignore`, which excludes `reports/`, `cache/`, `state/` and `evidence/`. Only `thirdsentry.yml` and `.thirdsentry/baselines/` are meant to be committed. Baselines contain approved script identities, URLs, hashes, domains and indicator counts and the names and versions of recognised libraries, but no code. The downloaded vulnerability database (`.thirdsentry/cache/vulndb/`) is public data and contains nothing about your sites.

## Retention

| Setting | Default | Effect |
| --- | --- | --- |
| `retention.maxScanReports` | 50 | Scan results kept **per site**; older ones (and their per-scan report directories) are deleted after each scan. |
| `retention.maxAgeDays` | 90 | Scan results, screenshots and cached script bodies older than this are deleted after each scan. Cached bodies still referenced by an approved baseline are kept so that future code diffs remain possible. |
| `retention.scriptContent` | `findings` | `none`, `findings` or `all` (see above). The deprecated `storeScriptContent: true/false` still works and means `all`/`none`. Content seen again has its age refreshed, so it only expires after `maxAgeDays` without being observed. Set `none` if you must not keep any third-party code on disk. |

Manual cleanup:

```bash
npx thirdsentry cleanup                                   # apply retention now
npx thirdsentry cleanup --older-than 7 --keep 10
npx thirdsentry cleanup --all-content                     # delete cached bodies (keeps baseline-referenced ones)
npx thirdsentry cleanup --all-content --include-referenced
npx thirdsentry cleanup --reset-state                     # forget which findings were seen/alerted
npx thirdsentry cleanup --dry-run
```

To remove everything ThirdSentry has stored, delete `.thirdsentry/reports`, `.thirdsentry/cache` and `.thirdsentry/state` (and, in Docker, the `reports`, `state`, `cache` and `evidence` volumes: `docker compose down -v`). Baselines are only removed if you delete them yourself.

## Third parties contacted

ThirdSentry itself contacts only the sites you configure (and whatever those pages load), and the alert destinations you enable. It sends no telemetry. In the browser, background networking, component updates, sync, DNS prefetching and DNS-over-HTTPS are disabled (Chromium), and telemetry, safe-browsing and update features are disabled (Firefox).
