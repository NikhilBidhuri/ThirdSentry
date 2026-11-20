# ThirdSentry

**Watch the code you don't control.** ThirdSentry is an open-source, self-hostable monitor that detects unexpected or suspicious changes in the third-party JavaScript running on your websites.

Your pages load code from analytics vendors, tag managers, payment providers, chat widgets and ad networks. You do not control that code, and it can change at any moment: a vendor ships a bad update, its CDN is compromised, or a script starts sending data somewhere new. Your own repository has not changed, yet your users are running different code.

ThirdSentry visits your pages in a real browser, records every script that runs, hashes it, and compares it with a baseline you approved. When something changes, it tells you what changed, where, and why it might matter.

> ThirdSentry is a **monitoring and detection** tool. It does not block or remove malicious code, it cannot prove that code is safe, and it does not by itself make you PCI DSS compliant. It gives you evidence and early warning so that people can investigate.

## What it does

- **Real-browser scanning** with Playwright (Chromium, Firefox, WebKit, and mobile emulation).
- **Discovers executable code**: external and inline scripts, ES modules and `import()`, runtime-injected scripts, scripts inside iframes, web/shared/service workers, `blob:` and `data:` scripts, and WebAssembly.
- **Hashes everything**: SHA-256 of the exact bytes, an SRI value, and a second hash of conservatively normalised code, so formatting-only changes can be told apart from code changes.
- **Approved baselines** stored as Git-friendly JSON. Scans never approve anything automatically.
- **Change detection**: new, removed and modified scripts, new third-party domains, redirect changes, iframe origin changes and new outbound destinations.
- **Script policies** (pin, path-versions, domain-only) for vendors whose scripts rotate: explicit, expiring and reviewable, and they never hide new suspicious behaviour ([docs/policies.md](docs/policies.md)).
- **Static analysis** with Babel ASTs for behaviours worth reviewing (eval, script injection, cookie/storage/form access, beacons, WebSockets, obfuscation, and sensitive-data-plus-transmission combinations), with explainable risk scoring.
- **Known libraries and CVEs**: recognises libraries and versions (jQuery, Lodash, Bootstrap, ...) offline from banners, code and URLs, explains version changes, and flags known vulnerabilities from the retire.js database ([docs](docs/libraries.md)).
- **Reports** in JSON, SARIF (GitHub Code Scanning) and HTML; **alerts** via Slack, Microsoft Teams, PagerDuty, webhooks, GitHub Issues and email.
- **CSP linter** for Content-Security-Policy headers.
- **Hardened by design**: the browser is treated as hostile. All browser traffic goes through an egress proxy that blocks private, loopback, link-local and cloud-metadata addresses per connection (defeating DNS rebinding), and the browser runs in a separate process (or container) without access to your secrets.

## Quick start

Requirements: Node.js 20.11 or newer.

```bash
npm install --save-dev thirdsentry
npx playwright install chromium        # browser used for scanning

npx thirdsentry init --url https://www.example.com --name my-store
# edit thirdsentry.yml: add the pages you care about (e.g. /checkout)

npx thirdsentry scan                   # see which scripts your pages load
npx thirdsentry baseline               # review, then approve the current state
npx thirdsentry scan --fail-on high    # later: detect drift; non-zero exit on findings
npx thirdsentry diff                   # review findings (and code diffs, if content retention is on)
npx thirdsentry baseline --approve <finding-id>   # approve a reviewed change
npx thirdsentry csp-lint https://www.example.com  # analyse your Content-Security-Policy
```

A scan prints what it found:

```
Scan 20261118T101500Z-3f2a9c1d: complete
  1 site(s), 2 page(s) [2 complete, 0 partial, 0 failed], 14 script resource(s) (5 first-party, 9 third-party), 6 third-party domain(s)

my-store https://www.example.com/ — complete (chromium 140.0.7339.16)
  complete   /          9 scripts, 61 requests
  complete   /checkout  7 scripts, 44 requests

  TYPE             PARTY  SHA-256        RESOURCE
  script           3rd    9f2c4b1e07aa   https://www.googletagmanager.com/gtm.js?id=GTM-XXXX
  inline-script    1st    41d0c3a99e12   inline:/|main|html:nth-of-type(1)>head:nth-of-type(1)>script:nth-of-type(2)
  script           3rd    c7e1aa04b3f9   https://js.payments.example/v3/ [dynamic]
  ...
```

## Documentation

| Topic | |
| --- | --- |
| [Installation](docs/installation.md) | npm, Docker, browsers |
| [Configuration](docs/configuration.md) | every `thirdsentry.yml` option |
| [CLI reference](docs/cli.md) | commands, flags and exit codes |
| [Baselines](docs/baselines.md) | approving and updating what is expected |
| [Script policies](docs/policies.md) | pin / path-versions / domain-only for rotating vendor scripts |
| [Detection rules](docs/rules.md) | static-analysis rules and risk scoring |
| [Libraries and CVEs](docs/libraries.md) | library detection and the vulnerability database |
| [Alerts](docs/alerts.md) | Slack, Teams, PagerDuty, webhook, GitHub Issues, email |
| [GitHub Actions](docs/github-actions.md) | scheduled scans in CI |
| [Docker](docs/docker.md) and [cron](docs/cron.md) | self-hosted scheduled scans |
| [Health and monitoring](docs/monitoring.md) | failed-scan alerts, heartbeat (dead-man's switch), Prometheus metrics, `status` |
| [CSP analysis](docs/csp.md) | `thirdsentry csp-lint` |
| [Security model](docs/security.md) | threat model and isolation boundaries |
| [Privacy and data retention](docs/privacy.md) | exactly what is collected and stored |
| [Known limitations](docs/limitations.md) | what ThirdSentry cannot see |
| [Architecture](docs/architecture.md) | how the pieces fit together |
| [Troubleshooting](docs/troubleshooting.md) | common problems |
| [Contributing](CONTRIBUTING.md) | development setup and guidelines |

## Project status

ThirdSentry is a young project. The scanner, baselines, change detection, static analysis, reports, alerts, CSP linter, Docker pipeline and GitHub Action are implemented and covered by automated tests that run against local fixture servers. The alert integrations are tested against local mock servers, not against live Slack, GitHub or SMTP services, and the GitHub Action is not exercised by this repository's test suite. See [docs/limitations.md](docs/limitations.md) for an honest list of what ThirdSentry does not cover.

## License

Apache License 2.0. See [LICENSE](LICENSE).
