# GitHub Actions

ThirdSentry ships a composite action (`action.yml` at the repository root) that installs ThirdSentry and the browser, runs a scan, uploads SARIF to GitHub Code Scanning, uploads the reports as an artifact and fails the job when findings exceed your threshold.

## Example workflow

Put `thirdsentry.yml` and the reviewed baselines (`.thirdsentry/baselines/`) in a repository, then add `.github/workflows/thirdsentry.yml` (also in `examples/github-workflow.yml`):

```yaml
name: ThirdSentry Security Monitoring

on:
  schedule:
    - cron: '17 */6 * * *'
  workflow_dispatch:
  push:
    branches: [main]
    paths: [thirdsentry.yml, .thirdsentry/baselines/**]

permissions:
  contents: read
  security-events: write

concurrency:
  group: thirdsentry
  cancel-in-progress: false

jobs:
  scan:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - uses: <owner>/thirdsentry@<ref>      # pin a tag or, better, a commit SHA
        with:
          fail-on: high
        env:
          THIRDSENTRY_SLACK_WEBHOOK: ${{ secrets.THIRDSENTRY_SLACK_WEBHOOK }}
          THIRDSENTRY_REPORT_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `config` | `thirdsentry.yml` | Configuration path (relative to `working-directory`). |
| `working-directory` | `.` | Directory with the configuration and `.thirdsentry/baselines`. |
| `site` | all | Comma-separated sites to scan. |
| `fail-on` | config `failOn` | Fail the job at this severity (`none` never fails on findings). |
| `formats` | `json,sarif,html` | Report formats. |
| `browsers` | `chromium` | Browsers to install, e.g. `chromium firefox webkit`. |
| `upload-sarif` | `true` | Upload to Code Scanning (needs `security-events: write`). |
| `sarif-category` | `thirdsentry` | Code Scanning category. |
| `upload-artifact` | `true` | Upload `report.json`, `report.sarif`, `report.html` as an artifact. |
| `artifact-retention-days` | `14` | Artifact retention. |
| `alerts` | `true` | Send alerts for enabled channels. |
| `persist-state` | `true` | Keep finding/alert state between runs in the Actions cache (see below). |
| `state-key` | derived | Cache key prefix for the state. Default derives from `working-directory`, `config` and `site`. |

Outputs: `exit-code` and `report-dir`.

All inputs reach shell scripts through environment variables, never through `${{ }}` expansion inside `run:`, so a crafted input cannot inject commands. `browsers` is also validated against `^[a-z][a-z0-9-]*$`.

### Persisted state

Alert state lives in the state directory resolved from your configuration (`storageDir`), which is on the ephemeral runner. Without persistence every scheduled run would alert again on the same findings. With `persist-state: true` the action restores the newest state for its key prefix with `actions/cache/restore` (restore-keys) and saves it afterwards under a unique key (`<prefix><run_id>-<run_attempt>`), even if the scan failed. Caveats: GitHub evicts caches not accessed for 7 days and when the repository exceeds its cache quota, and caches saved on one branch are not visible to unrelated branches. After an eviction the action warns, and findings may be alerted once more (GitHub issues are still de-duplicated by marker). Use different `state-key` values for different configs that share a repository.

### Reports location

Reports are written to `$RUNNER_TEMP/thirdsentry-reports` through `scan --output`, regardless of `storageDir` or a config in a subdirectory (this is the `report-dir` output). The directory is not hidden, so `upload-artifact` v4.4+ (which skips hidden files by default) includes them.

### SARIF

Artifact paths in SARIF are relative to the repository root (`GITHUB_WORKSPACE`, or the enclosing Git work tree), so results link to `thirdsentry.yml` even if it is in a subdirectory. No `automationDetails.id` is set: the `sarif-category` input identifies the analysis, so scanning a subset with `site` does not create a separate analysis. Use a distinct `sarif-category` per site subset or config.

## Security notes

- **Least privilege.** The workflow needs `contents: read` and, for SARIF upload, `security-events: write`. Add `issues: write` only if `alerts.github` is enabled. Use `persist-credentials: false` on checkout so the Git token is not left on disk for the scan.
- **Secrets.** Pass alert credentials as `env` on the action step from repository secrets. ThirdSentry resolves them only in the alert publisher; the browser worker runs with an allowlisted environment that excludes them and `GITHUB_TOKEN`. GitHub masks secret values in logs, and ThirdSentry redacts them from its own error messages.
- **No automatic approval or commits.** The action never commits anything and never updates baselines. Approve changes locally with `thirdsentry baseline`, review the diff of `baseline.json` and merge it through a pull request.
- **What is uploaded.** The artifact contains only `report.json`, `report.sarif` and `report.html`. Raw scan results stay on the ephemeral runner (state is only stored in the Actions cache when `persist-state` is on). Reports contain URLs and metadata of third-party resources (sensitive query values redacted) but no script bodies. Restrict artifact access accordingly in public repositories.
- **Chromium sandbox.** Ubuntu 23.10+ runners restrict unprivileged user namespaces, which Chromium's sandbox needs. The action relaxes this setting on the ephemeral runner (`kernel.apparmor_restrict_unprivileged_userns=0`) so that the sandbox can stay enabled.
- **Pin the action.** Reference the action by commit SHA rather than a moving tag.

## Scheduling caveats

- GitHub's `schedule` trigger is best-effort: runs are commonly delayed by several minutes and can be delayed longer, or dropped, at times of high load. Avoid the top of the hour (`17 */6 * * *` instead of `0 */6 * * *`).
- The shortest supported interval is 5 minutes, but each scan loads every page, so hourly or 6-hourly is usually more appropriate.
- Scheduled workflows are disabled automatically in repositories with no activity for 60 days.
- If you need dependable timing, use the [Docker deployment](docker.md) with cron or a systemd timer.

## Manual runs

`workflow_dispatch` adds a "Run workflow" button. Scans triggered by `push` to `thirdsentry.yml` or the baselines verify that a configuration or baseline change is consistent.

## Testing status

This repository's CI runs the unit and integration tests on GitHub-hosted runners. The composite action itself is not exercised by the automated test suite; test it in your repository with `workflow_dispatch` before relying on it.
