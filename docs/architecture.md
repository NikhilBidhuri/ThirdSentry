# Architecture

ScriptDrift is a TypeScript (Node.js, ESM) application organised around explicit trust boundaries: untrusted evidence is produced by an isolated browser worker and turned into findings by trusted code that never executes it.

## Data flow

```
scriptdrift.yml ──► config (Zod, strict) ──► resolved sites/pages
                                               │
                     ┌─────────────────────────▼────────────────────────┐
                     │ browser worker (separate process or container)   │
                     │  egress proxy ◄── all browser traffic            │
                     │  Playwright: network events, DOM instrumentation │
                     └─────────────────────────┬────────────────────────┘
                                               │ ScanEvidence (untrusted JSON)
                     ┌─────────────────────────▼────────────────────────┐
                     │ trusted analysis                                  │
                     │  schema + size validation                         │
                     │  discovery → identity → hashing → normalisation   │
                     │  static analysis (Babel AST rules)                │
                     │  → ScanResult (reports/scans/<id>.json)           │
                     │  comparison with baselines (read-only)            │
                     │  findings + explainable risk + suppressions       │
                     │  → AnalysisReport (report.json/.sarif/.html)      │
                     └─────────────────────────┬────────────────────────┘
                                               │
                     ┌─────────────────────────▼────────────────────────┐
                     │ alert publisher (only holder of credentials)      │
                     └──────────────────────────────────────────────────┘
```

## Source layout

| Directory | Responsibility |
| --- | --- |
| `src/cli/` | Commander program, commands (`init`, `scan`, `baseline`, `diff`, `report`, `alert`, `csp-lint`, `cleanup`, and the container pipeline `egress-proxy`, `collect`, `analyze`), terminal output. |
| `src/config/` | Configuration schema (Zod), loader, defaults/template. |
| `src/browser/` | Browser profiles, hardened launch, per-page scanner, network collector (protocol events), resource collector (in-page reports), in-page instrumentation, worker entry point. |
| `src/discovery/` | Turning evidence into resource candidates: external scripts (network ↔ DOM correlation), inline scripts, workers and blobs, iframes; resource identity and classification. |
| `src/analysis/` | Hashing, normalisation, structural diffs, Babel parsing, rule catalogue and AST analyser, domain policy, risk scoring, evidence processing, coverage notes. |
| `src/baseline/` | Baseline schema, validation, creation and approval. |
| `src/monitoring/` | Scan orchestration, comparison engine, finding engine, suppressions, finding state, analysis runner. |
| `src/reporting/` | JSON, SARIF and HTML reporters. |
| `src/alerts/` | Alert payloads, Slack, webhook, GitHub Issues, e-mail, alert manager, env interpolation. |
| `src/csp/` | CSP parser, analyser, recommendations, linter. |
| `src/security/` | IP policy, network policy, egress proxy, URL validation, SSRF-safe HTTP client, redaction, worker sandbox. |
| `src/storage/` | Storage layout, filesystem store, content store, retention. |
| `src/types/` | Evidence schema (Zod), result, finding and report types. |
| `src/utils/` | Logging (pino, to stderr), errors and exit codes, atomic/stable JSON IO, patterns. |

## Key design decisions

**Evidence vs. results.** The worker produces `ScanEvidence`: raw, untrusted, size-limited JSON including captured bodies. Only trusted code turns it into `ScanResult`, which contains hashes and metadata but never script bodies.

**Network events are authoritative.** External scripts are discovered from browser protocol events (outside the page's JavaScript realm). In-page instrumentation (MutationObserver, DOM API hooks, `URL.createObjectURL` hook) adds context such as "inserted by script" and blob contents, but a hostile page can tamper with it, so it never overrides network facts.

**Identity, URL and content are separate.** A resource is matched across scans by identity (requested URL, canonicalised; or page/frame/DOM position for inline code; or content for blobs). The original URL and raw bytes are preserved; the normalised hash is an additional signal that only classifies a byte change as formatting-only.

**Baselines are explicit.** Scans never write baselines. Approval is a separate command with confirmation and an audit trail.

**Explainable risk.** Every finding's score is the sum of named, weighted signals. Behaviour signals only count when behaviour is *new* relative to the approved version, which keeps routine vendor updates at "review" level and raises genuinely new behaviour.

**Per-connection SSRF enforcement.** The egress proxy resolves DNS once per connection, validates every address and connects to that address, so redirects and DNS rebinding cannot reach internal targets. The same policy backs the server-side HTTP client used by `csp-lint`.

**Fail loudly, never silently.** Partial scans are marked as such, exit code `3` signals incompleteness, removals are not reported for incomplete pages, and alert failures are reported without touching results.

## Extending

- **New rule:** add an entry to `RULES` in `src/analysis/indicator-rules.ts` with visitors (and optionally `finalize`), all documentation fields, and positive and negative tests in `tests/unit/ast-rules.test.ts`. Regenerate `docs/rules.md`.
- **New alert channel:** implement a sender in `src/alerts/`, add its schema to `AlertsSchema`, wire it in `alert-manager.ts`, and test it against a local mock server.
- **New report format:** add a renderer in `src/reporting/` and register it in `src/reporting/index.ts`.
