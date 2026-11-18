# Contributing to ScriptDrift

Thank you for helping. ScriptDrift is security tooling, so correctness, honesty about limitations and safe defaults matter more than feature count.

## Development setup

```bash
npm ci
npx playwright install chromium          # firefox/webkit optional (engine tests skip missing engines)
npm run build                            # the isolated browser worker runs compiled JavaScript
npm run typecheck
npm run lint
npm test                                 # unit + integration (local fixture servers only)
```

Requirements: Node.js 20.11+.

On Windows, run the tests from a shell whose working directory uses an upper-case drive letter (`C:\...`), otherwise Vitest may load itself twice.

Docker verification (Linux or Docker Desktop):

```bash
docker build -t scriptdrift:local . && sh tests/docker/verify.sh
```

## Ground rules

- **No real websites in tests.** Integration tests use the local fixture server (`tests/fixtures/server.ts`), which answers for fake `.test` hostnames that the egress proxy maps to `127.0.0.1` via `resolverOverrides`.
- **No silent failures.** Problems must surface as page issues, `partial`/`failed` status, non-zero exit codes or logged warnings.
- **No automatic approvals.** Nothing except the `baseline` command may write baselines.
- **No secrets in the browser worker.** Anything added to the worker's request or environment must be reviewed with this in mind (`src/security/worker-sandbox.ts`).
- **Untrusted input stays untrusted.** Evidence from the worker, page-reported data, URLs and header values must be validated, size-limited and escaped where they are displayed.
- **Honest wording.** Findings describe changes and behaviour worth reviewing. Do not call anything "malware" or "safe".
- **Small, focused modules** with strict TypeScript; no `any`, no unchecked casts of external data.

## Adding a detection rule

1. Add the rule to `RULES` in `src/analysis/indicator-rules.ts`: id (`SD-...`), name, description, severity, confidence, role, explanation, investigation steps, false-positive notes, visitors.
2. Add positive **and** negative cases to `tests/unit/ast-rules.test.ts`, and check `BENIGN_ANALYTICS` and `MINIFIED_LIBRARY` do not start matching unexpectedly.
3. Regenerate the rules table in `docs/rules.md`.

## Pull requests

- Keep commits focused; describe the motivation and any security implications.
- Include tests for behaviour changes and update the relevant docs (`docs/`).
- `npm run typecheck && npm run lint && npm test` must pass.

## Reporting security issues

Please do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
