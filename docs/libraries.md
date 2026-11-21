# Known libraries and vulnerabilities

ThirdSentry recognises well-known JavaScript libraries (jQuery, Lodash, Bootstrap, ...) and their versions in the scripts it captures, and reports known vulnerabilities (CVEs) in the versions it finds. This answers a different question from drift detection: not "did this script change?" but "is the code I run known to be vulnerable?".

Recognition is **offline and deterministic**. Nothing is fetched while a scan or analysis runs.

## What you see

- A **Libraries** section in the HTML report, in the terminal output of `scan`/`diff`, and `libraries` in `report.json` (inventory per site plus the vulnerability database status).
- `thirdsentry diff` also lists library changes since the approved baseline (`jQuery 3.5.1 → 3.7.1`).
- `resource-modified` findings for a known library name the version change in their title, reason and evidence ("Third-party script changed (jQuery 3.5.1 → 3.7.1)"). A version *downgrade* is called out, because it is unusual and a classic way to reintroduce a vulnerable version.
- `vulnerable-library` findings (see [rules.md](rules.md#vulnerable-library)).

The detected libraries of an approved resource are stored in the baseline (name and version only) so that later version changes can be explained.

## How detection works

Four sources, strongest first. Every detection has a method and a confidence.

| Method | Confidence | Example |
| --- | --- | --- |
| `content-hash` | high | The file's SHA-256 matches an entry in `libraries.knownHashes`, or its SHA-1 matches a hash in the vulnerability database. |
| `banner` | high (known libraries), medium (generic banner) | `/*! jQuery v3.5.1 \| (c) JS Foundation ... */` |
| `code` | medium | `jquery:"3.5.1"`, `Handlebars.VERSION = "4.0.5"`, and, only when a library-specific marker is present in the same file, `var VERSION = '4.17.20'` (Lodash needs `__lodash_hash_undefined__`; a bare `VERSION = '1.2.3'` is never attributed to a library) |
| `url` | medium (`name@version`, `/ajax/libs/<name>/<version>/`, `jquery-3.5.1.min.js`), low (`/<known-name>/<version>/`) | `https://cdn.jsdelivr.net/npm/lodash@4.17.20/lodash.min.js` |

The URL patterns understand cdnjs, Google Hosted Libraries, jsDelivr (`/npm/pkg@ver`, `/gh/owner/repo@ver`), unpkg and generic `name@version` paths. File names are only trusted for known library names, so `app-1.2.3.min.js` is not reported as a library.

If content and URL disagree (the URL says 3.5.1, the banner says 3.6.0) the content wins and the URL detection is dropped. The same library and version found by several methods is reported once, with the strongest method. A bundle that contains several libraries can yield several detections.

The detectors cover a built-in set (jQuery, jQuery UI, Bootstrap, Lodash, Moment.js, AngularJS, Handlebars, DOMPurify, Underscore.js, plus a generic banner reader) **and** every `filecontent`, `filename`, `uri` and `hashes` extractor in the vulnerability database. The database's `func` extractors need a live browser page and are not used. A script is only inspected up to its first 2 MiB.

Detection runs as part of script analysis, so it needs `analysis.enabled: true` and `libraries.detect: true` (both default). Content-based detection is cached per script hash.

## Limits: what detection cannot do

- **Minified bundles without banners.** Webpack/Rollup bundles usually strip comments and rename everything. A library inside such a bundle is often invisible, or only visible through the URL (`bundle.4f3a.js` says nothing). Absence of a library in the report is **not** evidence that it is not there.
- **The URL can lie.** `jquery-3.5.1.min.js` may contain a patched, older or different file. URL detections have only medium or low confidence, and findings based on them say so.
- **Patched and forked copies.** Distributions that backport security fixes without changing the version string (some Linux packages, CMS bundles) produce false positives; forks that keep the original banner after changes produce wrong versions.
- **False positives from the generic banner reader** are possible for unusual banners; they carry medium confidence and never match an advisory unless the name equals a database library.
- **Reachability is not assessed.** An advisory affects a version range; whether your pages use the vulnerable function is not checked.
- **Only the versions the database knows.** The bundled seed holds a handful of libraries (below); the full retire.js database covers about seventy and is still not exhaustive. Advisories without a usable version range are skipped.
- **Dynamic probes** (`window.jQuery.fn.jquery` at run time) are not used; ThirdSentry reads static content.

## Vulnerability data

The format and data are those of the [retire.js](https://github.com/RetireJS/retire.js) repository (`repository/jsrepository.json`): per library, `extractors` (regexes with a `§§version§§` placeholder) and `vulnerabilities` (`atOrAbove` inclusive, `below` exclusive, `severity`, CVE identifiers, `info` links).

**Licensing.** retire.js and its vulnerability repository are licensed under the Apache License 2.0, copyright the retire.js authors. The bundled seed (`src/analysis/libraries/seed-data.ts`) is a small verbatim subset and carries that notice; a database you download with `vulndb update` stays under its upstream license and is stored unmodified in your cache. ThirdSentry contains no other retire.js code.

### The bundled seed

Used when no database was downloaded. It contains 37 advisories for jQuery, jQuery UI, Bootstrap, Lodash, Moment.js, AngularJS, Handlebars and DOMPurify. Every entry (version ranges, severity, CVE IDs) was copied from the upstream file and checked against it; entries that could not be verified were left out. It is deliberately small, not current, and every report carries a warning saying so. Run `vulndb update` for real use.

### `thirdsentry vulndb update`

Downloads the database into `.thirdsentry/cache/vulndb/jsrepository.json` and writes `meta.json` next to it (`sourceUrl`, `fetchedAt`, `sha256`, `bytes`, library and advisory counts).

- Uses the SSRF-safe client (`src/security/safe-http.ts`): every redirect hop is validated, private/loopback/metadata addresses are refused, the connection is pinned to the validated IP. A redirect to an internal address aborts the update.
- The download is capped (16 MiB). A truncated download is an error, never installed.
- The JSON is validated against a strict Zod schema (see below) and compiled before anything is written. Invalid JSON, schema violations and empty databases are refused.
- Both files are written atomically (temp file, fsync, rename), database first. A failed update leaves the previous database untouched.
- `--url <url>` selects another source (a mirror or an internal copy). The default is the upstream raw GitHub URL.

`thirdsentry vulndb status` shows which database would be used and its age.

**Where to run it.** The analyzer has no network by design, and neither does the `tools` container. Only components with egress may run `vulndb update`: in Docker this is a dedicated, short-lived `vulndb-updater` service (see [docker.md](docker.md#vulnerability-database-updates)); on a host or in CI, run the command wherever the scan runs and cache `.thirdsentry/cache/vulndb`.

### Freshness

The analyzer reads the cached database if there is one (and its SHA-256 matches `meta.json`), else the seed. Every report records the database source, fetch time and age. When the cached database is older than `libraries.maxDbAgeDays` (default 30) a warning is logged and added to the report. A damaged, edited or oversized cache is ignored with a warning (the seed is used instead); the analyzer never uses the network to repair it.

Advisories are matched when a scan is analysed, against the database present at that time. Updating the database changes the set of advisories of a finding (and so its ID, see below): a library that was clean yesterday can alert today without any change to your site.

## Treating the database as untrusted input

The file comes from the internet and is read by the analyzer, so it is validated like hostile input:

- **Strict schema.** Types, enumerations and sizes are checked: at most 2,000 libraries, 1,000 advisories per library, bounded string, list and URL lengths; `severity` must be `low|medium|high|critical`; hashes must be hex; the library names `__proto__`, `constructor` and `prototype` are rejected. Unknown fields are ignored (never used). Only `https:` links without credentials are ever shown; CVE links are generated from the CVE ID.
- **Version ranges** that do not parse are skipped (and counted).
- **Regular expressions** (the only executable-like content) are compiled with safeguards against catastrophic backtracking. JavaScript cannot interrupt a running regex, and a time box would also make results non-deterministic, so the defence is preventive:
  1. pattern length is capped (600 characters);
  2. a structural check rejects the classic ReDoS shapes: a repeated group that contains an unbounded quantifier (`(a+)+`, `(a*){2,}`, `(.*x)*`), an alternation inside an unbounded repeated group (`(a|aa)+`), a backreference inside one, more than six unbounded quantifiers in one pattern, and repeat bounds above 10,000;
  3. patterns must compile, without flags;
  4. each regex only sees the first 2 MiB of a script, so the work of even a quadratic pattern is bounded;
  5. at most 2,000 regexes per database are used.

  Rejected patterns are skipped and counted ("N detection patterns were skipped"). The check is conservative: a few legitimate upstream patterns (16 of about 600 in the retire.js file at the time of writing) are skipped, which can only reduce detection, never produce a false match.
- Nothing from the database is evaluated as code; it only supplies regexes, version bounds and text.

## Findings

See [rules.md](rules.md#vulnerable-library) for severity, confidence, finding IDs and suppression. In short: one finding per resource and library version listing every matching advisory, with the fixed-in version and links; the ID changes only when the site, resource, library, version or the set of advisories changes, so it alerts once and again when new advisories appear.

## Configuration

```yaml
libraries:
  detect: true            # recognise libraries (offline)
  vulnerabilities: true   # raise vulnerable-library findings
  minSeverity: low        # ignore advisories below this severity
  maxDbAgeDays: 30        # warn when the cached database is older
  knownHashes:            # optional exact matches for files you know
    - { sha256: "<64 hex>", name: acme-widgets, version: 2.1.0 }
```

See [configuration.md](configuration.md#libraries).
