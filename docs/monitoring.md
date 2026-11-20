# Health and monitoring

A scheduled scanner can fail quietly: the site is down, the browser crashes, the cron job stops. A security tool that silently stops scanning is worse than none, so ThirdSentry watches itself:

| Mechanism | Answers | Where |
| --- | --- | --- |
| Scan health and `scan-unhealthy` finding | "Has scanning this site been broken for several runs?" | `state/health.json`, report, alerts |
| Heartbeat | "Did the job run at all, and did it succeed?" (dead-man's switch) | healthchecks.io, Cronitor, Uptime Kuma, ... |
| `thirdsentry metrics` | "Show me the numbers" | Prometheus, node_exporter textfile collector, Pushgateway |
| `thirdsentry status` | "Is everything OK right now?" | terminal, scripts, CI (exit code) |

```yaml
health:
  failureThreshold: 3        # alert after this many failed scans in a row (default 3)
  countIncomplete: true      # incomplete (partial) scans count as failures (default true)
  heartbeat:                 # optional
    url: ${THIRDSENTRY_HEARTBEAT_URL}
    # failUrl: ${THIRDSENTRY_HEARTBEAT_FAIL_URL}
    # failPath: /fail        # appended to url when failUrl is not set ("" = send no failure ping)
    onIncomplete: fail       # fail | success | skip
    # timeoutMs: 5000
```

## Scan health and the `scan-unhealthy` finding

After every scan, the analysis step (`scan`, and `analyze` in the container pipeline, both through the same code) updates `state/health.json`, per site:

- `lastScanAt`, `lastCompleteAt`, `lastStatus` (`complete`, `partial`, `failed`)
- `consecutiveFailures` and `streakStart` (the start of the first scan of the current streak)
- `lastError` (a short, single-line summary of the first error or warning, never page content), `lastDurationSeconds`
- counters used by the metrics (pages by status, scripts by party, blocked connections)
- per alert channel: last attempt, last success and consecutive delivery failures (written by `alert`, or by `scan` when it alerts)

A scan counts as a failure when its status is `failed`, or `partial` while `health.countIncomplete` is true. Any other scan resets the streak. Analysing the same scan twice does not count it twice, and read-only commands (`diff`, `report`) never change the health state.

When `consecutiveFailures` reaches `health.failureThreshold`, the report contains a finding of kind **`scan-unhealthy`**, severity `high`, for that site. It goes through the normal pipeline: it is listed in the report (all formats), counted for `--fail-on`, can be suppressed, and is alerted through every channel subject to `alerts.minSeverity` (default `medium`, so it is delivered by default). It does not need a baseline.

- **Once per outage.** The finding ID is derived from the site and the start of the streak. While the outage lasts the ID is unchanged, so each channel alerts once.
- **Escalation.** When the streak reaches three times the threshold the severity becomes `critical`; the alert state re-sends a finding whose severity increased, so there is exactly one more alert.
- **A new outage** has a new streak start, a new ID and alerts again.
- **Recovery.** When a site that had reached the threshold scans without failing again, the report of that scan has a recovery note in its headline (`Recovered: scanning of <site> works again after N failed scans (since ...)`) and in `report.health.recoveries`, and the finding disappears. No separate recovery alert is sent (keep it simple; the heartbeat turns green on the same run, and a push monitor can notify on recovery).

**How this differs from `page-failed` and `coverage-degraded`.** Those are per page and per scan: "this page was not (fully) scanned in this scan". They appear when it happens, vanish on the next good scan, and one flaky page can produce them once in a while without anything being wrong. `scan-unhealthy` is per site and streak-based: "scanning this site has been broken for N runs in a row". It is the escalation for a persistent problem and is deliberately quiet for a single bad run. The per-page findings stay as they are and still explain which pages failed and why.

If a run crashes before it produces a scan result (browser cannot start, host out of memory), no health update is possible; that case is what the heartbeat and `thirdsentry_last_scan_timestamp_seconds` are for.

## Heartbeat (dead-man's switch)

Push monitors such as [healthchecks.io](https://healthchecks.io), Cronitor or Uptime Kuma expect a ping after every run and alarm when it is missing. This catches what ThirdSentry cannot report itself: a stopped cron job, a dead host, a crash.

- After a **complete** run, ThirdSentry sends a `GET` to `health.heartbeat.url`.
- After a **failed** run it sends the failure ping: `failUrl` if set, otherwise `url` with `failPath` (default `/fail`, the healthchecks.io convention) appended to the path. For Uptime Kuma set `failUrl` explicitly (for example `.../api/push/<token>?status=down`). An empty `failPath` without `failUrl` sends nothing on failure, so the monitor's timeout raises the alarm.
- After an **incomplete** (`partial`) run, `onIncomplete` decides: `fail` (default), `success` or `skip`.
- A failed alert delivery also sends the failure ping.
- If the run crashes or `alert` throws, nothing is sent; the missing ping is the signal.
- `thirdsentry alert --test` and `--dry-run` never ping. `--no-heartbeat` (on `scan` and `alert`) skips it for one run.

**Who sends it.** Only a component that has network access and credentials: the `alert` command (the `alerter` container in the Docker pipeline), and `scan` when alerts are enabled (not with `--no-alerts`). Never the analyzer, which has no network. If you run both `scan` and `alert` yourself, you send two pings per cycle, which is harmless.

**Safety.** One attempt, no retries, a 5 second timeout by default (`timeoutMs`), no redirects followed. The ping URL is a secret: use an `${ENV}` reference (set it in the environment of the alerter, like other alert credentials), it is never logged, and any URL, path or token fragment is redacted from error messages. A heartbeat problem (unset variable, HTTP error, timeout) is logged as a warning and never changes the exit code or fails the scan.

## Prometheus metrics

`thirdsentry metrics` renders metrics (Prometheus text exposition format 0.0.4) from the files on disk: the latest `reports/report.json`, `state/health.json` and the finding state. It is **read-only**, never takes the storage lock and never scans.

```bash
thirdsentry metrics                                   # stdout
thirdsentry metrics --textfile /var/lib/node_exporter/textfile/thirdsentry.prom
thirdsentry metrics --serve 127.0.0.1:9464            # HTTP exporter
thirdsentry metrics --push http://pushgateway:9091    # Pushgateway
```

| Metric | Labels | Meaning |
| --- | --- | --- |
| `thirdsentry_info` | `version` | Always 1. |
| `thirdsentry_last_scan_timestamp_seconds` | `site` | End of the last scan, complete or not. |
| `thirdsentry_last_complete_scan_timestamp_seconds` | `site` | End of the last complete scan (absent until there was one). |
| `thirdsentry_scan_duration_seconds` | `site` | Duration of the last scan. |
| `thirdsentry_pages` | `site`, `status` (`complete`, `partial`, `failed`) | Pages in the last scan. |
| `thirdsentry_scripts` | `site`, `party` (`first-party`, `third-party`) | Script resources in the last scan. |
| `thirdsentry_findings` | `site`, `severity`, `suppressed` | Findings in the latest report. |
| `thirdsentry_consecutive_failed_scans` | `site` | Current failure streak. |
| `thirdsentry_blocked_connections` | `site` | Connections blocked by the network policy in the last scan. |
| `thirdsentry_baseline_present` | `site` | 1 if the latest report found an approved baseline. |
| `thirdsentry_report_timestamp_seconds` | none | When the latest report was generated. |
| `thirdsentry_alert_delivery_failures` | `channel` | Consecutive failed deliveries (gauge, 0 after a success). |
| `thirdsentry_alert_pending_findings` | `channel` | Findings in the latest report not yet delivered through the channel. |

All metrics are gauges. Label values are escaped; cardinality is bounded by design: configured sites, fixed severities/statuses/parties and enabled alert channels. There are no per-script, per-page or per-finding labels (use the report for those). `examples/prometheus-alerts.yml` has example alert rules (stale scans, failure streak, open high findings, delivery failures).

### Textfile collector (recommended for batch jobs)

ThirdSentry is a batch job, so there is usually nothing to scrape between runs. The recommended setup is node_exporter's [textfile collector](https://github.com/prometheus/node_exporter#textfile-collector): render the file after each scan (or on a short timer, the values only change when a scan ran) and let node_exporter serve it.

```bash
node_exporter --collector.textfile.directory=/var/lib/node_exporter/textfile
thirdsentry metrics --textfile /var/lib/node_exporter/textfile/thirdsentry.prom
```

The file is written atomically (temp file in the same directory, then rename; the temporary name does not end in `.prom`, so node_exporter never reads a partial file). The file name must end in `.prom`. See `examples/cron/crontab` and `examples/systemd/thirdsentry-metrics.{service,timer}`. Because the timestamps are exported as values, alert on `time() - thirdsentry_last_complete_scan_timestamp_seconds`, not on the file's mtime.

### HTTP exporter (`--serve`)

`--serve [host:]port` starts a tiny read-only HTTP server that renders from the files on every request: `GET /metrics` (and `HEAD`), and `GET /healthz`, which answers `200 ok` while the files can be read and `503` when they cannot (it says nothing about scan health: that is `status`). Everything else is `404`, other methods `405`. It writes nothing.

**There is no authentication and no TLS.** It binds to `127.0.0.1` by default; ThirdSentry prints a warning when you bind elsewhere. If Prometheus is on another host, keep the exporter on loopback and put a reverse proxy or an SSH/WireGuard tunnel in front, or use the textfile collector. The metrics reveal site names and finding counts, not URLs or script contents.

### Pushgateway (`--push`)

`--push <url>` sends the same text with `PUT` to `<url>/metrics/job/thirdsentry` (or to the URL as given if it already contains `/metrics/job/`). `PUT` replaces the group, so removed sites disappear. Credentials in the URL (`http://user:pass@host`) are sent as HTTP Basic authentication and redacted from errors. Prefer the textfile collector: a Pushgateway never forgets a stale group, so a stopped job keeps looking fine unless you alert on the timestamp metrics.

## `thirdsentry status`

```bash
thirdsentry status [--site <names>] [--max-age <hours>] [--json]
```

Per site: last scan, last complete scan, consecutive failures and streak start, last error, open (unsuppressed) findings by severity from the latest report, whether an approved baseline exists; plus the health of each enabled alert channel. It is read-only and takes no lock.

A site is `healthy`, `degraded` (some failures below the threshold, last scan incomplete, or no approved baseline), `unhealthy` (streak at `health.failureThreshold`, or with `--max-age` the last scan finished longer ago than that many hours) or `unknown` (nothing recorded yet). A channel is `unhealthy` when its deliveries failed `failureThreshold` times in a row.

| Exit code | Meaning |
| --- | --- |
| `0` | Every selected site is healthy or degraded and no channel is unhealthy. |
| `1` | A site or an alert channel is unhealthy. |
| `2` | Configuration or usage error. |
| `3` | No scan has been recorded yet for a selected site (and nothing is unhealthy). |

Open findings never make `status` fail; use `--fail-on` on `scan` for that.

## Docker

The optional `metrics` service (profile `metrics`) runs the HTTP exporter in the slim image:

```bash
docker compose --profile metrics up -d metrics
curl http://127.0.0.1:9464/metrics
```

It mounts `thirdsentry.yml`, `reports` and `state` **read-only**, has no credentials, runs hardened like the other containers, and sits on its own network with outbound masquerading disabled, so the only way in is the port published on the host's loopback (`THIRDSENTRY_METRICS_PORT`, default 9464). Prometheus on the same host can scrape it; for other hosts see the warning above. For the textfile collector, use `docker compose run --rm -v /var/lib/node_exporter/textfile:/textfile tools metrics --textfile /textfile/thirdsentry.prom` (the directory must be writable by uid 1001). The heartbeat is sent by the `alerter` container; put `THIRDSENTRY_HEARTBEAT_URL` in the `.env` file next to the other alert credentials. See [docker.md](docker.md) and [cron.md](cron.md).
