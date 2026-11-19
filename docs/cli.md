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
| `-V, --version` | Print the version. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, and no finding met the `--fail-on` threshold. |
| `1` | At least one finding met or exceeded the `--fail-on` threshold. |
| `2` | Configuration, usage or input error. |
| `3` | The scan was incomplete: at least one page was `partial` or `failed`. Results are still saved. |
| `4` | Unexpected internal error. |

When both findings and incomplete pages occur, `1` takes precedence, because findings are the more urgent signal; the report still lists the incomplete pages.

## `thirdsentry init`

Create `thirdsentry.yml` and the `.thirdsentry/` directory.

| Option | Description |
| --- | --- |
| `--url <url>` | Site URL to pre-fill. |
| `--name <name>` | Site name to pre-fill (default `my-site`). |
| `--force` | Overwrite an existing configuration. |

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

After scanning, the result is compared with each site's baseline (if one exists), reports are written (`report.json`, `report.sarif`, `report.html`) and alerts are sent for new findings. The scan result itself is stored in `.thirdsentry/reports/scans/`. Scans never modify baselines.

## `thirdsentry baseline`

Approve the current state (or selected findings) as expected. See [baselines.md](baselines.md) for the full workflow.

| Option | Description |
| --- | --- |
| `-s, --site <names>` | Only these sites. |
| `--from-scan <file>` | Scan result to approve (default: latest). |
| `--approve <finding-ids>` | Approve only the changes behind these findings. |
| `--keep-variants` | Keep previously approved hashes too. |
| `--allow-partial` | Allow approving from an incomplete scan (complete pages only). |
| `--reason <text>`, `--approved-by <name>` | Recorded in the approval history. |
| `--dry-run` | Show the summary without writing. |
| `-y, --yes` | Do not prompt. Required when stdin is not a terminal. |

## `thirdsentry diff`

Compare the latest scan (or `--scan <file>`) with the baselines without scanning again, and print findings and, where both versions are in the content cache, code diffs.

| Option | Description |
| --- | --- |
| `-s, --site <names>` | Only these sites. |
| `--scan <file>` | Scan result to compare. |
| `--finding <id>` | Show a single finding. |
| `--context <lines>` | Context lines in code diffs (default 3). |
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

Exit code `4` if any channel failed.

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
