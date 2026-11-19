# Alerts

ThirdSentry can notify you about new findings through **Slack**, a **generic HTTP webhook**, **GitHub Issues** and **e-mail**. Alerts are sent after a scan (`thirdsentry scan`) or on demand (`thirdsentry alert`).

## Principles

- **Credentials come from environment variables.** Settings reference them as `${NAME}`. Only the alert publisher resolves them, at send time. The browser worker never receives them, and they are redacted from logs and error messages. ThirdSentry warns if a credential is written literally in `thirdsentry.yml`.
- **No script bodies in alerts.** Alerts contain the site, affected resource, severity and confidence, the explanation, previous and current hashes, compact evidence, a report location and suggested next steps. Code excerpts from behaviour matches are left out (only the rule names and line numbers are listed).
- **No alert spam.** A finding is alerted once. It is alerted again only if its severity increases, or after `repeatAfterHours` if you configure that. If a script changes again, that is a new finding with a new ID. Suppressed findings are never alerted.
- **Failures never affect scan results.** Reports are written before alerts are sent. Delivery errors are retried (except GitHub issue creation, to avoid duplicates), logged and shown, but do not change the scan's exit code. `thirdsentry alert` itself exits with code `4` if a channel failed, so you can monitor alert delivery separately.

## Configuration

```yaml
alerts:
  minSeverity: medium        # only findings at or above this severity
  repeatAfterHours: 0        # 0 = alert once per finding
  maxFindingsPerAlert: 20
  reportUrl: ${THIRDSENTRY_REPORT_URL}   # optional link shown in alerts (e.g. CI run URL)
  timeoutMs: 15000
  retries: 2

  slack:
    enabled: true
    webhookUrl: ${THIRDSENTRY_SLACK_WEBHOOK}
    minSeverity: high        # optional per-channel threshold

  webhook:
    enabled: false
    url: ${THIRDSENTRY_WEBHOOK_URL}
    secret: ${THIRDSENTRY_WEBHOOK_SECRET}   # optional HMAC signing
    allowInsecureHttp: false

  github:
    enabled: false
    createIssues: true
    repository: ${GITHUB_REPOSITORY}       # owner/repo (set automatically in GitHub Actions)
    token: ${GITHUB_TOKEN}
    labels: [thirdsentry, security]
    maxIssuesPerRun: 10

  email:
    enabled: false
    host: ${THIRDSENTRY_SMTP_HOST}
    port: ${THIRDSENTRY_SMTP_PORT}
    secure: false            # true for implicit TLS (port 465)
    requireTLS: true         # refuse to send credentials without STARTTLS
    username: ${THIRDSENTRY_SMTP_USER}
    password: ${THIRDSENTRY_SMTP_PASS}
    from: ${THIRDSENTRY_SMTP_FROM}
    to: ${THIRDSENTRY_SMTP_TO}             # comma separated, or a YAML list
```

### Environment variables

| Variable | Used by | Required when |
| --- | --- | --- |
| `THIRDSENTRY_SLACK_WEBHOOK` | Slack | `slack.enabled` (default reference) |
| `THIRDSENTRY_WEBHOOK_URL` | Webhook | `webhook.enabled` (default reference) |
| `THIRDSENTRY_WEBHOOK_SECRET` | Webhook | you reference it in `webhook.secret` |
| `GITHUB_TOKEN` | GitHub Issues | `github.enabled`; needs `issues: write` |
| `GITHUB_REPOSITORY` | GitHub Issues | `github.enabled`; `owner/repo` |
| `THIRDSENTRY_SMTP_HOST`, `_PORT`, `_FROM`, `_TO` | E-mail | `email.enabled` |
| `THIRDSENTRY_SMTP_USER`, `_PASS` | E-mail | your server requires authentication |
| `THIRDSENTRY_REPORT_URL` | all | you reference it in `reportUrl` |

The names are only defaults: any `${NAME}` works. A referenced variable that is not set makes that channel fail with a clear message; other channels still run.

## Channels

### Slack

Uses an [incoming webhook](https://api.slack.com/messaging/webhooks). Messages use Block Kit: a header, the plain-language summary, one section per finding (severity, confidence, resource, reason, hashes, why, next step) and a footer with the scan ID and report location. Slack markup in finding text is escaped, so a hostile URL cannot trigger `@channel` mentions.

### Generic webhook

`POST`s the alert payload as JSON (`kind: "thirdsentry-alert"`). Redirects are not followed. When `secret` is set, requests carry:

```
X-ThirdSentry-Timestamp: 1763459000
X-ThirdSentry-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<raw body>">
```

Verify on the receiver (Node.js example):

```js
import { createHmac, timingSafeEqual } from 'node:crypto';
function verify(rawBody, timestamp, signature, secret) {
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false; // replay window
  const expected = `sha256=${createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex')}`;
  return expected.length === signature.length && timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}
```

### GitHub Issues

Creates one issue per finding with the configured labels. Each issue body contains a hidden marker (`<!-- thirdsentry-finding: TS-... -->`); before creating issues, open issues with the first label are listed and findings that already have an open issue are skipped, so re-runs never duplicate issues. At most `maxIssuesPerRun` issues are created per run.

In GitHub Actions grant only what is needed:

```yaml
permissions:
  contents: read
  issues: write
```

### E-mail

Sends through your SMTP server using nodemailer (file and URL access in message content are disabled). By default `requireTLS: true`: if the server does not offer STARTTLS, nothing is sent rather than sending credentials in clear text. Use `secure: true` for implicit TLS on port 465.

## Commands

```bash
npx thirdsentry scan                 # scans, writes reports, then alerts (unless --no-alerts)
npx thirdsentry alert                # alerts for .thirdsentry/reports/report.json
npx thirdsentry alert --dry-run      # show what would be sent
npx thirdsentry alert --channel slack,github
```

`alert --json` prints per-channel results.

## Testing status

The Slack, webhook, GitHub and e-mail integrations are covered by automated tests against **local mock servers** (an HTTP receiver and a minimal SMTP server) that check payloads, signatures, retries, de-duplication and secret redaction. They have **not** been tested against the live Slack, GitHub or a production SMTP service in this repository's test suite. Verify your own setup with `thirdsentry alert --dry-run` followed by a real run against a test channel.
