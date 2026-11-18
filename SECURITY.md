# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Report vulnerabilities privately through GitHub's "Report a vulnerability" (private vulnerability reporting) on this repository. Include:

- a description of the issue and its impact,
- steps to reproduce (a minimal configuration or fixture page is ideal),
- affected versions.

We aim to acknowledge reports within 5 working days and to provide a fix or mitigation plan within 30 days for confirmed issues.

## Scope

Of particular interest:

- bypasses of the egress network policy (SSRF to private, loopback, link-local or metadata addresses; DNS rebinding),
- ways for a scanned page to read credentials, modify baselines or forge findings,
- resource-exhaustion bugs that escape the configured limits,
- leakage of secrets into logs, reports or alerts.

See [docs/security.md](docs/security.md) for the threat model and known residual risks.
