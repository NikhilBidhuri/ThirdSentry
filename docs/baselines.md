# Baseline management

A **baseline** is the set of scripts, script hashes and domains that a person has reviewed and approved for a site. Every scan is compared with it. ThirdSentry **never approves anything automatically**: scans never write baselines, and every baseline change goes through the explicit `thirdsentry baseline` command.

## Where baselines live

```
.thirdsentry/baselines/<site>/baseline.json
```

Baselines are stable, sorted JSON designed to be committed and reviewed in pull requests. Each file contains:

| Field | Meaning |
| --- | --- |
| `resources[]` | Approved resources by **identity**, each with one or more `approvedHashes` (raw SHA-256, normalised SHA-256, size, approval time), type, party, pages, original and final URL. |
| `domains.scripts` | Registrable domains approved to serve scripts. |
| `domains.outbound` / `outboundHosts` | Domains and hostnames the pages are approved to contact. |
| `domains.iframes` | Approved iframe origins. |
| `pages` | Pages covered by the baseline. |
| `approvals[]` | Audit trail: when, from which scan, scope (`initial`, `full`, `selected`), optional reason and approver. |

Baselines are validated on every load (schema, hash format, duplicate identities, site name). A hand-edited or tampered file that does not validate is rejected rather than trusted.

## Creating the first baseline

```bash
npx thirdsentry scan           # look at what your pages load
npx thirdsentry baseline       # shows a summary and asks for confirmation
```

Review the scan output first. If a script you do not recognise is listed, find out where it comes from **before** approving it: approving makes it "expected".

Only pages that were scanned **completely** are approved. If the scan was partial, `baseline` refuses unless you pass `--allow-partial`, in which case only the complete pages are approved.

## What happens when something changes

On the next scan, every difference becomes a finding with the previous and current hashes, an explanation and a recommended action. The baseline is not modified. Findings remain until you approve the change or the change goes away.

```bash
npx thirdsentry diff                     # list findings again, with code diffs where available
npx thirdsentry diff --finding TS-1a2b3c4d5e6f
```

Code diffs require both versions of the script. By default (`retention.scriptContent: findings`) ThirdSentry keeps, in the git-ignored `.thirdsentry/cache/content/`, the bodies of approved versions and of versions behind findings, so the first incident already has a "before" and an "after". `none` keeps nothing (hashes, sizes and behaviour indicators are still compared); `all` keeps every body. See [privacy.md](privacy.md).

`diff` prints the scan ID and a ready-to-run approve command for the findings shown.

## Approving changes

After reviewing, approve in one of two ways.

**Selected findings only** (recommended):

```bash
npx thirdsentry baseline --approve TS-1a2b3c4d5e6f,TS-9f8e7d6c5b4a --reason "Vendor A release 2.4, confirmed with vendor"
```

Only the resources or domains behind those findings change; everything else in the baseline stays as it is. Finding IDs include the content hash, and the approval is bound to exactly that hash: if the same URL serves a benign version on one page and a different one on another, approving one finding never approves the other.

Bind the approval to the scan you reviewed with `--scan-id` (printed by `diff`); if a newer scan has replaced the latest one in the meantime, `baseline` refuses and writes nothing:

```bash
npx thirdsentry baseline --scan-id 20261120T101500Z-ab12cd --approve TS-1a2b3c4d5e6f
```

**Everything in the latest scan**:

```bash
npx thirdsentry baseline --reason "Quarterly review"
```

This replaces the approved state of the completely scanned pages with what the scan observed. Resources of pages that were not scanned completely are kept.

Both forms print a summary (newly approved, changed, no longer approved, domain changes) and ask for confirmation. If you are about to approve high-priority or suspicious findings, the summary says so explicitly.

| Option | Description |
| --- | --- |
| `--approve <ids>` | Approve only the changes behind these finding IDs. |
| `--keep-variants` | Keep previously approved hashes as well. Use this for vendors that legitimately serve several variants (A/B tests, regional builds). |
| `--from-scan <file>` | Approve a specific scan result instead of the latest. |
| `--scan-id <id>` | Refuse unless the scan being approved has this ID. |
| `--allow-partial` | Allow approving from an incomplete scan (only complete pages are used). |
| `--reason <text>` / `--approved-by <name>` | Recorded in the approval history. The approver defaults to the Git `user.name`, else the OS user name. |
| `--dry-run` | Show what would change without writing. |
| `-y, --yes` | Skip the confirmation prompt. Required in non-interactive environments. |

In non-interactive environments (CI), `baseline` refuses to run without `--yes`. Do **not** run `baseline --yes` automatically in scheduled jobs: approving must be a deliberate human decision. In CI, let a person run it locally, review the diff of `baseline.json` and merge it through a pull request.

## File format versions

Baselines and scan results carry an integer `schemaVersion` (currently 2 for baselines, 1 for scan results). Baseline version 2 adds the optional `pageSecurity` map (approved security headers and form fingerprint per page, see [pci.md](pci.md)); a version 1 baseline is upgraded in memory unchanged, and pages without a `pageSecurity` entry produce a single low-severity `security-baseline-missing` notice instead of changes until their state is approved. A file written by an **older** ThirdSentry is upgraded in memory by the migrations registered in `src/storage/migrations.ts` and is rewritten in the current format only when it is saved again (for example by the next approval). A file written by a **newer** ThirdSentry is refused with an "upgrade ThirdSentry" error; it is never guessed at or downgraded. Changing a schema requires a migration from the previous version and a test that reads the old format.

## A missing baseline is not a pass

A site without a baseline cannot be compared, so `scan` and `analyze` exit `3` (not `0`) and print first-run guidance. Review the scan, run `thirdsentry baseline`, commit the baseline, or pass `--allow-missing-baseline` deliberately for the first run.

## How matching works

| Situation | Result |
| --- | --- |
| Raw SHA-256 matches an approved hash for the identity | unchanged |
| Raw hash differs, normalised hash matches | `resource-formatting-changed` (informational) |
| Hashes differ | `resource-modified` |
| Identity not in baseline, content equals a disappeared approved resource | `resource-moved` |
| Identity not in baseline | `resource-added` |
| Approved identity not observed on a completely scanned page | `resource-removed` |
| Same requested URL now redirects elsewhere | `redirect-changed` |
| Content no longer capturable | `content-unavailable` |
| `integrity` attribute does not match | `sri-mismatch` |
| New script, outbound or iframe domain/origin | `new-script-domain`, `new-outbound-domain`, `new-outbound-host`, `iframe-origin-added` |

**Resource identity** is the URL the page requested (first redirect hop), with the fragment removed and query parameters sorted, so that "the same script" is recognised even when its content changes. Inline scripts are identified by page, frame and DOM position, falling back to content matching when their position shifts. Blob scripts are identified by page, frame and content, because blob URLs are random.

If a vendor appends a cache-busting parameter (`?v=1699999999`), list the parameter name in the site's `ignoreQueryParams` so that the identity stays stable. The stored URL still contains the full query string.
