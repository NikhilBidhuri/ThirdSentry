# CLI reference

```
scriptdrift [global options] <command> [command options]
```

## Global options

| Option | Description |
| --- | --- |
| `-c, --config <path>` | Configuration file (default: `scriptdrift.yml`, `scriptdrift.yaml` or `.scriptdrift/config.yml`). |
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

## `scriptdrift init`

Create `scriptdrift.yml` and the `.scriptdrift/` directory.

| Option | Description |
| --- | --- |
| `--url <url>` | Site URL to pre-fill. |
| `--name <name>` | Site name to pre-fill (default `my-site`). |
| `--force` | Overwrite an existing configuration. |

## `scriptdrift scan`

Visit the configured pages in a browser, discover executable resources, hash them and save the result to `.scriptdrift/reports/scans/<scan-id>.json` (also copied to `reports/latest-scan.json`).

| Option | Description |
| --- | --- |
| `-s, --site <names>` | Only scan these sites (comma separated). |
| `-o, --output <dir>` | Directory for reports (default `.scriptdrift/reports`). |
| `-f, --format <formats>` | Report formats: `json`, `sarif`, `html` (comma separated; default `reporting.formats`). |
| `--no-alerts` | Do not send alerts even if channels are enabled. |
| `--fail-on <severity>` | Exit with code 1 if any unsuppressed finding is at least this severe: `info`, `low`, `medium`, `high`, `critical` or `none`. Default: `failOn` from the config (`high`). |
| `--skip-preflight` | Skip DNS pre-flight checks. Every connection is still validated by the egress proxy. |

After scanning, the result is compared with each site's baseline (if one exists), reports are written (`report.json`, `report.sarif`, `report.html`) and alerts are sent for new findings. The scan result itself is stored in `.scriptdrift/reports/scans/`. Scans never modify baselines.

## `scriptdrift baseline`

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

## `scriptdrift diff`

Compare the latest scan (or `--scan <file>`) with the baselines without scanning again, and print findings and, where both versions are in the content cache, code diffs.

| Option | Description |
| --- | --- |
| `-s, --site <names>` | Only these sites. |
| `--scan <file>` | Scan result to compare. |
| `--finding <id>` | Show a single finding. |
| `--context <lines>` | Context lines in code diffs (default 3). |
| `--fail-on <severity>` | As for `scan`. |

## `scriptdrift report`

Regenerate reports from the latest (or a given) scan without scanning again.

| Option | Description |
| --- | --- |
| `--scan <file>` | Scan result to report on. |
| `-f, --format <formats>` | `json`, `sarif`, `html` (default `reporting.formats`). |
| `-o, --output <dir>` | Output directory (default `.scriptdrift/reports`). |
| `--fail-on <severity>` | Exit with code 1 if a finding is at least this severe (default `none`). |

| File | Purpose |
| --- | --- |
| `report.json` | Complete machine-readable report (`kind: scriptdrift-report`). |
| `report.sarif` | SARIF 2.1.0 for GitHub Code Scanning. Results are anchored to the site's entry in `scriptdrift.yml`. |
| `report.html` | Self-contained, script-free HTML report for people. |

## `scriptdrift alert`

Send alerts for new findings in `report.json`. See [alerts.md](alerts.md).

| Option | Description |
| --- | --- |
| `--report <file>` | Report to alert on. |
| `--channel <names>` | Only these channels: `slack`, `webhook`, `github`, `email`. |
| `--dry-run` | Show what would be sent. |

Exit code `4` if any channel failed.
