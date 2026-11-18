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
| `-o, --output <file>` | Also write the scan result JSON here. |
| `--skip-preflight` | Skip DNS pre-flight checks. Every connection is still validated by the egress proxy. |
