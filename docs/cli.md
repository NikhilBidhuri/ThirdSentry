# CLI reference

```
thirdsentry [global options] <command> [command options]
```

## Global options

| Option | Description |
| --- | --- |
| `-c, --config <path>` | Configuration file (default: `thirdsentry.yml`, `thirdsentry.yaml` or `.thirdsentry/config.yml`). |
| `-v, --verbose` | Debug logging (to stderr). |
| `--json` | Machine-readable JSON on stdout. Logs stay on stderr. |
| `-q, --quiet` | Only warnings and errors are logged. |
| `--lock-timeout <seconds>` | Wait up to this long for another ThirdSentry command using the same storage directory (default 0: fail immediately). |
| `-V, --version` | Print the version. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, and no finding met the `--fail-on` threshold. |
| `1` | At least one finding met or exceeded the `--fail-on` threshold. |
| `2` | Configuration, usage or input error. |
| `3` | The scan was incomplete (at least one page was `partial` or `failed`), **or a scanned site has no approved baseline** (nothing was compared, so a green result would be meaningless). Results are still saved. Pass `--allow-missing-baseline` for the first run. |
| `4` | Unexpected internal error; also alert delivery failure for `thirdsentry alert`, and for `scan` with `--fail-on-alert-error`. |

When several conditions occur, `1` takes precedence, because findings are the more urgent signal; then `4` (with `--fail-on-alert-error`), then `3`. The report still lists the incomplete pages. `scan` and the container `analyze` command share this logic.

`--site`, `--finding` and similar selectors fail with exit `2` when they name something unknown (a site that is not configured, a finding that is not in the scan); they never silently select nothing.

## Storage lock

Every command that writes the storage directory (`scan`, `analyze`, `baseline`, `alert`, `cleanup`, `report`) holds a lock (`.thirdsentry/state/thirdsentry.lock`, created exclusively; records pid, host, start time and command) for its whole run, so a cron scan and a manual `baseline` cannot interleave. If the lock is held, the command exits `2` naming the holder. Locks of crashed processes (dead pid on this host, or no heartbeat for 10 minutes) are taken over automatically. Use the global `--lock-timeout <seconds>` to wait instead of failing at once. "Latest" files (`reports/latest-scan.json`, `reports/report.*`) are replaced atomically (temp file + rename).

## `thirdsentry init`

Create `thirdsentry.yml` and the `.thirdsentry/` directory.

| Option | Description |
| --- | --- |
| `--url <url>` | Site URL to pre-fill. |
| `--name <name>` | Site name to pre-fill (default `my-site`). |
| `--force` | Overwrite an existing configuration and `.thirdsentry/.gitignore` (an existing `.gitignore` is otherwise kept). |

## `thirdsentry scan`

Visit the configured pages in a browser, discover executable resources, hash them and save the result to `.thirdsentry/reports/scans/<scan-id>.json` (also copied to `reports/latest-scan.json`).

| Option | Description |
| --- | --- |
| `-s, --site <names>` | Only scan these sites (comma separated). |
| `-o, --output <dir>` | Directory for reports (default `.thirdsentry/reports`). |
| `-f, --format <formats>` | Report formats: `json`, `sarif`, `html` (comma separated; default `reporting.formats`). |
| `--no-alerts` | Do not send alerts even if channels are enabled. |
| `--fail-on <severity>` | Exit with code 1 if any unsuppressed finding is at least this severe: `info`, `low`, `medium`, `high`, `critical` or `none`. Default: `failOn` from the config (`high`). |
| `--skip-preflight` | Skip DNS pre-flight checks. Every connection is still validated by the egress proxy. |
| `--allow-missing-baseline` | Exit 0 instead of 3 when a scanned site has no baseline yet (first run). |
| `--fail-on-alert-error` | Exit 4 if an alert could not be delivered (default: scan results are kept and the exit code is unchanged). |

After scanning, the result is compared with each site's baseline, reports are written and alerts are sent for new findings. The scan result is stored in `.thirdsentry/reports/scans/<scan-id>.json` (saved before static analysis runs, then updated with the analysis), and the reports of that scan in `.thirdsentry/reports/scans/<scan-id>/report.{json,sarif,html}`. `reports/report.*` and `reports/latest-scan.json` are atomically updated copies of the latest ones. Scans never modify baselines. Without a baseline the scan exits 3 and prints first-run guidance.

## `thirdsentry baseline`

Approve the current state (or selected findings) as expected. See [baselines.md](baselines.md) for the full workflow.

| Option | Description |
| --- | --- |
| `-s, --site <names>` | Only these sites. |
| `--from-scan <file>` | Scan result to approve (default: latest). |
| `--scan-id <id>` | Refuse (exit 2, nothing written) unless the scan being approved has this ID. `diff` prints it. |
| `--approve <finding-ids>` | Approve only the changes behind these findings. |
| `--keep-variants` | Keep previously approved hashes too. |
| `--allow-partial` | Allow approving from an incomplete scan (complete pages only). |
| `--reason <text>`, `--approved-by <name>` | Recorded in the approval history. `--approved-by` defaults to the Git `user.name`, else the OS user name. |
| `--dry-run` | Show the summary without writing. |
| `-y, --yes` | Do not prompt. Required when stdin is not a terminal. |

## `thirdsentry diff`

Compare the latest scan (or `--scan <file>`) with the baselines without scanning again, and print findings and, where both versions are in the content cache, code diffs.

| Option | Description |
| --- | --- |
| `-s, --site <names>` | Only these sites. |
| `--scan <file>` | Scan result to compare. |
| `--finding <ids>` | Show only these findings (comma separated). Unknown IDs are an error. |
| `--context <lines>` | Context lines in code diffs (whole number, default 3; `0` is allowed). |
| `--fail-on <severity>` | As for `scan`. |

## `thirdsentry report`

Regenerate reports from the latest (or a given) scan without scanning again.

| Option | Description |
| --- | --- |
| `--scan <file>` | Scan result to report on. |
| `-f, --format <formats>` | `json`, `sarif`, `html` (default `reporting.formats`). |
| `-o, --output <dir>` | Output directory (default `.thirdsentry/reports`). |
| `--fail-on <severity>` | Exit with code 1 if a finding is at least this severe (default `none`). |

| File | Purpose |
| --- | --- |
| `report.json` | Complete machine-readable report (`kind: thirdsentry-report`). |
| `report.sarif` | SARIF 2.1.0 for GitHub Code Scanning. Results are anchored to the site's entry in `thirdsentry.yml`. |
| `report.html` | Self-contained, script-free HTML report for people. |

## `thirdsentry alert`

Send alerts for new findings in `report.json`. See [alerts.md](alerts.md).

| Option | Description |
| --- | --- |
| `--report <file>` | Report to alert on. |
| `--channel <names>` | Only these channels: `slack`, `webhook`, `github`, `email`. |
| `--dry-run` | Show what would be sent. |
| `--no-heartbeat` | Do not send the `health.heartbeat` ping. |

Exit code `4` if any channel failed.

Besides alerting, `alert` records per-channel delivery health in `state/health.json` and, when `health.heartbeat` is configured, sends the heartbeat ping (success after a complete run, failure otherwise; see [monitoring.md](monitoring.md)). `--no-heartbeat` skips the ping. `--test` and `--dry-run` never ping. `scan` has the same `--no-heartbeat` flag and pings when alerts are enabled.

## `thirdsentry metrics`

Render Prometheus metrics from the latest report, scan health and alert state. Read-only; takes no storage lock. See [monitoring.md](monitoring.md) for the metric list.

| Option | Description |
| --- | --- |
| *(none)* | Print the metrics to stdout. |
| `--textfile <path>` | Write the metrics atomically to a file (node_exporter textfile collector; name it `*.prom`). |
| `--serve <[host:]port>` | Serve `GET /metrics` and `GET /healthz` over HTTP until stopped. Read-only, **no authentication**, binds to `127.0.0.1` by default. |
| `--push <url>` | `PUT` the metrics to a Pushgateway (`<url>/metrics/job/thirdsentry`). |

`--textfile` and `--push` can be combined. Exit `4` if a push fails.

## `thirdsentry status`

Summarise scan health, open findings by severity, baseline presence and alert channel health per site. Read-only; takes no storage lock. Use `--json` for machine-readable output.

| Option | Description |
| --- | --- |
| `-s, --site <names>` | Only these sites. |
| `--max-age <hours>` | Treat a site whose last scan finished longer ago than this as unhealthy. |

Exit codes: `0` healthy (or only degraded), `1` a site or alert channel is unhealthy, `2` usage or configuration error, `3` no scan recorded yet.

## `thirdsentry csp-lint`

Analyse Content-Security-Policy headers. See [csp.md](csp.md).

```bash
thirdsentry csp-lint https://www.example.com [more URLs...]
thirdsentry csp-lint --from-scan [--site <names>]
```

| Option | Description |
| --- | --- |
| `--from-scan` | Use headers captured by the latest scan (no network). |
| `-s, --site <names>` | With `--from-scan`, only these sites. |
| `--fail-on <level>` | `error`, `warning`, `info` or `none` (default). |

Works without a configuration file (default network policy). Exit `1` when `--fail-on` is exceeded, `3` when a URL could not be fetched.

## `thirdsentry cleanup`

Delete old scan results, screenshots and cached script bodies. Baselines are never touched. See [privacy.md](privacy.md#retention).

| Option | Description |
| --- | --- |
| `--older-than <days>` | Age limit (default `retention.maxAgeDays`). |
| `--keep <n>` | Scan results to keep (default `retention.maxScanReports`). |
| `--all-content` | Delete all cached script bodies, except those referenced by baselines. |
| `--include-referenced` | With `--all-content`, delete baseline-referenced bodies too. |
| `--reset-state` | Delete finding/alert state. |
| `--dry-run` | Only report what would be deleted. |

## Container pipeline commands

Used by the [Docker deployment](docker.md), where each step runs in its own container. You normally do not run them by hand.

| Command | Purpose |
| --- | --- |
| `thirdsentry egress-proxy [--listen 0.0.0.0:3128]` | Run the egress proxy that enforces the network policy. |
| `thirdsentry collect --out <file> [--proxy <url>] [--no-chromium-sandbox] [--site]` | Browser collection only; writes untrusted evidence. |
| `thirdsentry analyze --evidence <file> [--format] [--output] [--fail-on]` | Validate evidence, compare with baselines and write reports. No network, no alerts. |
