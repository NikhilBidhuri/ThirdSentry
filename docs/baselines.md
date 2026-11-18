# Baseline management

A **baseline** is the set of scripts, script hashes and domains that a person has reviewed and approved for a site. Every scan is compared with it. ScriptDrift **never approves anything automatically**: scans never write baselines, and every baseline change goes through the explicit `scriptdrift baseline` command.

## Where baselines live

```
.scriptdrift/baselines/<site>/baseline.json
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
npx scriptdrift scan           # look at what your pages load
npx scriptdrift baseline       # shows a summary and asks for confirmation
```

Review the scan output first. If a script you do not recognise is listed, find out where it comes from **before** approving it: approving makes it "expected".

Only pages that were scanned **completely** are approved. If the scan was partial, `baseline` refuses unless you pass `--allow-partial`, in which case only the complete pages are approved.

## What happens when something changes

On the next scan, every difference becomes a finding with the previous and current hashes, an explanation and a recommended action. The baseline is not modified. Findings remain until you approve the change or the change goes away.

```bash
npx scriptdrift diff                     # list findings again, with code diffs where available
npx scriptdrift diff --finding SD-1a2b3c4d5e6f
```

Code diffs require both versions of the script. Script bodies are **not** stored by default (privacy); enable `retention.storeScriptContent: true` to keep them in the git-ignored `.scriptdrift/cache/content/` so that future changes can be shown as code diffs. Without retained content, ScriptDrift still compares hashes, sizes and behaviour indicators.

## Approving changes

After reviewing, approve in one of two ways.

**Selected findings only** (recommended):

```bash
npx scriptdrift baseline --approve SD-1a2b3c4d5e6f,SD-9f8e7d6c5b4a --reason "Vendor A release 2.4, confirmed with vendor"
```

Only the resources or domains behind those findings change; everything else in the baseline stays as it is.

**Everything in the latest scan**:

```bash
npx scriptdrift baseline --reason "Quarterly review"
```

This replaces the approved state of the completely scanned pages with what the scan observed. Resources of pages that were not scanned completely are kept.

Both forms print a summary (newly approved, changed, no longer approved, domain changes) and ask for confirmation. If you are about to approve high-priority or suspicious findings, the summary says so explicitly.

| Option | Description |
| --- | --- |
| `--approve <ids>` | Approve only the changes behind these finding IDs. |
| `--keep-variants` | Keep previously approved hashes as well. Use this for vendors that legitimately serve several variants (A/B tests, regional builds). |
| `--from-scan <file>` | Approve a specific scan result instead of the latest. |
| `--allow-partial` | Allow approving from an incomplete scan (only complete pages are used). |
| `--reason <text>` / `--approved-by <name>` | Recorded in the approval history. |
| `--dry-run` | Show what would change without writing. |
| `-y, --yes` | Skip the confirmation prompt. Required in non-interactive environments. |

In non-interactive environments (CI), `baseline` refuses to run without `--yes`. Do **not** run `baseline --yes` automatically in scheduled jobs: approving must be a deliberate human decision. In CI, let a person run it locally, review the diff of `baseline.json` and merge it through a pull request.

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
