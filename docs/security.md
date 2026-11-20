# Security model

ThirdSentry visits websites and runs their JavaScript in a real browser. Those websites, and the third parties they load, are **not trusted**: monitoring for compromised scripts means deliberately running potentially compromised code. This document describes the threat model, the trust boundaries and the protections in place, including their limits.

## Assets to protect

1. **Credentials**: alert credentials (Slack webhook URLs, SMTP passwords, webhook signing secrets, GitHub tokens), Git credentials and cloud credentials on the machine running ThirdSentry.
2. **Internal network**: services reachable from the scanner host (databases, admin panels, cloud metadata endpoints, other containers).
3. **Integrity of approved baselines**: an attacker who could edit the baseline could make a malicious script look "approved".
4. **Integrity of findings and alerts**: results must not be forgeable by the scanned page.
5. **The scanner host itself**: CPU, memory and disk.

## Threats considered

| Threat | Example |
| --- | --- |
| Server-side request forgery (SSRF) through the browser | A compromised script calls `fetch('http://169.254.169.254/latest/meta-data/iam/...')`, or redirects the page to `http://10.0.0.5/admin`. |
| DNS rebinding | `evil.example` resolves to a public IP when checked, then to `127.0.0.1` when the browser connects. |
| Credential theft | Code reaching environment variables or files of the process that runs the browser. |
| Evidence tampering | Page scripts disable or feed false data to the in-page instrumentation, or try to hide from it. |
| Resource exhaustion | Infinite redirects, huge responses, endless requests, memory bombs. |
| Browser exploitation | A browser vulnerability exploited by a malicious page. |
| Baseline poisoning | A malicious change approved automatically. |

## Architecture and trust boundaries

```
 ┌──────────────────────────── trusted ─────────────────────────────┐
 │  Coordinator (thirdsentry scan)                                    │
 │   - loads config, validates URLs, pre-flight DNS checks            │
 │   - spawns the browser worker with a scrubbed environment          │
 │   - validates worker evidence (schema + size limits)               │
 │   - analysis: hashing, normalisation, AST rules, comparison        │
 │   - writes reports; reads baselines (never written by scans)       │
 └───────────────▲───────────────────────────────┬──────────────────┘
                 │ evidence JSON (untrusted)      │ finished report
 ┌───────────────┴──────── untrusted ────────┐  ┌──▼──────────── trusted ─────┐
 │  Browser worker (separate process/       │  │  Alert publisher            │
 │  container)                              │  │  (separate process/         │
 │   - Playwright + browser                 │  │  container)                 │
 │   - no secrets, no baseline paths        │  │   - only component given    │
 │   - all traffic via egress proxy ────────┼─►│     alert credentials       │
 └──────────────────────────────────────────┘  └─────────────────────────────┘
                 │
          ┌──────▼───────────────┐
          │  Egress proxy         │  resolves DNS once, validates every IP,
          │                       │  connects to the validated IP only
          └──────┬───────────────┘
                 ▼  internet (public addresses only)
```

### 1. Egress proxy: per-connection SSRF protection

All browser traffic (HTTP, HTTPS, WebSocket) is forced through ThirdSentry's egress proxy:

- For **every connection**, including every redirect hop and every subresource, the proxy resolves the hostname **once**, checks **every** returned address, and then opens the TCP connection to **that validated address**. The browser never resolves names itself for proxied traffic. A DNS answer that changes between check and use (DNS rebinding, TOCTOU) therefore cannot redirect the connection.
- If any resolved address is disallowed, the destination is refused. This prevents mixed public and private record sets.
- Blocked ranges: loopback (`127.0.0.0/8`, `::1`), private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`), link-local (`169.254/16`, `fe80::/10`), carrier-grade NAT (`100.64/10`), multicast, reserved, documentation and unspecified ranges, and cloud metadata endpoints (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `192.0.0.192`, `168.63.129.16` (Azure WireServer), `169.254.170.23` (EKS Pod Identity), `fd00:ec2::254`, `fd00:ec2::23`). These are never unlockable through `allowedPrivateHosts`.
- IPv6 forms that embed IPv4 (IPv4-mapped `::ffff:a.b.c.d`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) are evaluated by their embedded IPv4 address. Teredo is blocked. IPv6 is allowlisted: only global unicast (`2000::/3`) is reachable, so unassigned and special space such as `3fff::/20` or SRv6 `5f00::/16` is refused.
- DNS lookups are bounded (5 s); a lookup that does not answer refuses the destination.
- The proxy treats everything from clients and upstream servers as hostile: invalid upstream status lines or headers produce a 502, upgrades (101) are refused, and an error guard around each connection means no single connection can stop the proxy process.
- In the container pipeline the proxy records connections per run and site on its own volume, and the analyzer uses that record instead of the scanner's report (see [docker.md](docker.md)).
- Hostnames such as `localhost`, `*.localhost` and `metadata.google.internal` are refused before resolution.
- Only ports in `security.network.allowedPorts` (default 80 and 443) are reachable.
- Per-connection byte caps and connect/idle timeouts bound resource use.
- Blocked attempts are recorded and appear in the scan result (`blockedConnections`).

`security.network.allowedPrivateHosts` lets you deliberately scan an internal site. It applies only to the listed hostnames, and cloud metadata addresses stay blocked.

### 2. Browser launch hardening

- **QUIC/HTTP3 is disabled** and **WebRTC is restricted to proxied connections** (Chromium) or disabled (Firefox), so UDP traffic cannot bypass the proxy.
- DNS prefetching, DNS-over-HTTPS, background networking, component updates, sync and pings are disabled.
- Loopback traffic is not exempted from the proxy (Playwright's `<-loopback>` rule for Chromium; `network.proxy.allow_hijacking_localhost` for Firefox).
- Downloads are refused, dialogs dismissed, popups closed and no permissions granted.
- Chromium's renderer sandbox stays **enabled** (`security.isolation.chromiumSandbox: true`; Playwright disables it by default).
- Every page is loaded in a fresh browser context: no shared cookies, storage or cache.

### 3. Process isolation of the browser worker

In the default `process` mode the browser runs in a separate Node.js process that:

- receives an **allowlisted environment** (`PATH`, locale, `PLAYWRIGHT_BROWSERS_PATH` and a few OS variables). Alert credentials, `GITHUB_TOKEN`, cloud credentials and every other variable are **not** inherited;
- gets `HOME`/`TEMP` pointing at a disposable directory that is deleted afterwards;
- is told only the sites, limits and network policy. It does not know where baselines, reports or state are stored;
- is killed if it exceeds the scan time budget.

**Limitation:** the worker process runs as the same OS user, so this mode does not provide filesystem isolation. If the browser and its sandbox were both compromised, the attacker could read files that user can read. Use the [container deployment](docker.md) for strong isolation in production. There the browser container has no secrets (the optional journey test-account credentials in `journeys.env` are the one exception, see [Journey credentials](#journey-credentials)), no baseline mount, a read-only root filesystem, dropped capabilities and network access **only** to the egress proxy, so network restrictions are enforced at the container network layer as well as by the proxy. `tests/docker/verify.sh` checks these properties against a running deployment (no direct internet from the scanner, metadata/private/port blocks at the proxy, no network for the analyzer, no credentials in the scanner).

### 4. Evidence is untrusted

Everything produced by the browser worker is validated against a strict schema with hard size limits before use. In-page instrumentation (dynamic-injection hooks, blob capture) runs in the same JavaScript realm as hostile code and **can be detected, disabled or fed false data**. Authoritative facts (which scripts were fetched, their bytes and their hashes) come from browser protocol events observed outside the page, which page scripts cannot tamper with. Page-reported data only adds context.

### 5. Baselines are never modified by scans

Scans only write to `reports/`, `state/` and (optionally) `cache/`. Baselines change only through the explicit `thirdsentry baseline` command, which shows a summary and asks for confirmation. Nothing is approved automatically. In CI, commit baseline changes through code review.

### 6. Alert credentials

Alert credentials are read from environment variables (`${VAR}` interpolation is applied **only** inside the `alerts` section of the config). Only the alert publisher receives them; they are never passed to the browser worker and are redacted from logs.

## Journey credentials

Logged-in journeys (see [configuration.md](configuration.md#journeys)) are the single exception to "the browser worker has no secrets": a login needs a password in the browser. The exception is kept explicit and minimal.

- **Declared, not ambient.** Only `${THIRDSENTRY_SECRET_<NAME>}` references in `fill` values are accepted; every other `${...}` is rejected at config load. The worker environment (src/security/worker-sandbox.ts) gets exactly the variables the journeys reference. Alert credentials, Git tokens and cloud credentials are never passed.
- **Not persisted by ThirdSentry.** The configuration and the worker request contain references only. Resolved values live in the worker's memory and the browser. They are never logged, never part of an error message (step failures name index, type and selector only; Playwright's own messages are not forwarded because their call logs echo typed text), and every capture is scrubbed of the values (raw, URL-encoded, base64) before it is written. Screenshots mask the typed fields and password inputs; request bodies are never recorded.
- **What a hostile page can still do.** The scanned site receives the credential, as for any login, and a compromised browser worker can read it. Therefore: use **dedicated test accounts with least privilege** (no admin rights, no stored cards, no real personal data, a unique password) and expect to rotate them. A `storageState` file is a live session and equally sensitive.
- **Navigation is fenced.** A journey may only navigate within the site's registrable domain and an explicit `allowedHosts` list, so a redirect cannot carry the session to another site. The egress proxy still enforces the network policy on every connection.
- **No accidental purchases.** Submit buttons of payment-like forms need `allowSubmit: true`. **Never use live payment credentials**; use a payment sandbox and test cards.
- **Container setup.** Put the secrets in a separate env file that only the scanner container reads (`journeys.env`, see [docker.md](docker.md#journeys-and-credentials)); the analyzer and alerter never see them.

## Resource limits

| Limit | Default |
| --- | --- |
| Navigation timeout per page | 60 s |
| Total scan duration | 30 min (worker killed shortly after) |
| Script body captured | 5 MiB |
| Bytes per proxied connection | 50 MiB |
| Scripts / requests recorded per page | 500 / 3000 |
| Pages per scan | 100 |
| Evidence accepted from the worker | 512 MiB |
| Worker V8 heap / page V8 heap | 2 GiB / 1 GiB |

### 7. Server-side fetches

`csp-lint` fetches URLs from Node.js rather than the browser. It uses an HTTP client that applies the same network policy: each request and each redirect hop is validated, DNS is resolved once by the policy and the socket connects to the validated address (custom `lookup`), TLS certificates are still verified for the original hostname, redirects are limited and bodies are capped.

### 8. Reports are inert

The HTML report embeds strings that originate from scanned pages (URLs, hostnames, error text). All of them are HTML-escaped, the report loads no external resources and carries a `Content-Security-Policy` that forbids scripts. Slack and GitHub messages escape their respective markup, so hostile URLs cannot trigger mentions or formatting tricks.

## Residual risks

- **Browser 0-days**: a full browser plus sandbox escape compromises the worker. In process mode that means the local user account; in container mode, the container. Keep Playwright up to date.
- **Cloaking**: malicious code that hides from automated browsers will not be detected.
- **Instrumentation tampering**: dynamic-injection flags and blob capture are best-effort.
- **Local development**: on Windows and macOS there is no container network layer unless you run Docker, so the egress proxy is the only network control.

## Reporting vulnerabilities

See [SECURITY.md](../SECURITY.md).
