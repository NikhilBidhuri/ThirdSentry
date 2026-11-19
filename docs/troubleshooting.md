# Troubleshooting

## The browser does not start

**`Executable doesn't exist at ...ms-playwright...`**
The Playwright browser build is not installed. Run `npx playwright install chromium` (and `firefox`/`webkit` if you use those profiles). In the default `process` isolation mode the worker receives a scrubbed environment; ThirdSentry passes `PLAYWRIGHT_BROWSERS_PATH` explicitly, so set that variable if you installed browsers to a custom location.

**Linux: missing shared libraries** (`libnss3.so`, `libatk-1.0.so`, ...)
Run `npx playwright install --with-deps chromium`, or use the Docker image.

**Linux: `No usable sandbox!` / Chromium sandbox errors**
ThirdSentry keeps Chromium's renderer sandbox enabled (`security.isolation.chromiumSandbox: true`). The sandbox needs unprivileged user namespaces or a setuid sandbox helper. Options, in order of preference:

1. Enable unprivileged user namespaces on the host (`sysctl kernel.unprivileged_userns_clone=1` on older Debian kernels; on Ubuntu 23.10+ `sysctl kernel.apparmor_restrict_unprivileged_userns=0` or an AppArmor profile that allows them for the browser).
2. Run the scanner in the provided [Docker setup](docker.md). Its hardened scanner container cannot start Chromium's sandbox, so it runs with `--no-chromium-sandbox` and relies on the container boundary (no capabilities, read-only root filesystem, no network except the egress proxy, no secrets).
3. As a last resort, outside containers, set `security.isolation.chromiumSandbox: false`. Do not do this on a shared host.

**WebKit: `Host system is missing dependencies`**
Playwright's WebKit needs extra system libraries (on Linux: `npx playwright install --with-deps webkit`). On some Windows editions WebKit cannot start at all; use Chromium or Firefox profiles there, or run in Docker.

**Docker Desktop: `docker compose run` hangs at "Creating"**
Bind-mounting files from the host (your `thirdsentry.yml` and baselines) requires Docker Desktop file sharing for that drive or folder. Enable it in Docker Desktop settings (Resources → File sharing) or run from a directory that is already shared.

**`Compiled browser worker not found`**
You are running ThirdSentry from TypeScript sources. Run `npm run build` first.

## A page is reported as `partial` or `failed`

ThirdSentry never reports an incomplete page as complete. Look at the page issues in the scan output:

| Code | Meaning | What to do |
| --- | --- | --- |
| `navigation-timeout` | the page did not finish loading within `scan.timeout` | increase `timeout`, or use `waitUntil: load` |
| `navigation-failed` | DNS failure, connection refused, TLS error, or the connection was blocked | check the URL; see blocked connections in the report |
| `http-error` | the page returned HTTP 4xx/5xx | check the page; results are not trusted for change detection |
| `network-not-idle` (warning) | background requests never stopped | normal for chatty sites; the scan continues |
| `script-limit` / `request-limit` | `limits.maxScriptsPerPage` / `maxRequestsPerPage` exceeded | raise the limit if the page is legitimate |
| `scan-time-limit` | `limits.maxScanDurationMs` exceeded | raise the limit or scan fewer pages per run |

Exit code `3` means at least one page was incomplete.

## Requests are blocked unexpectedly

The egress proxy blocks any destination that resolves to a loopback, private, link-local, CGNAT, multicast, reserved or cloud-metadata address, and any port not in `security.network.allowedPorts`. Blocked connections are listed under `blockedConnections` in the scan JSON and logged as `blocked outbound connection`.

To scan an internal staging site deliberately, add its hostname to `security.network.allowedPrivateHosts`. Cloud metadata addresses remain blocked regardless.

## `Refusing to scan ...: Destination resolves to a private address`

The configured site itself resolves to an internal address. See above.

## Results differ between runs

Third-party scripts often vary by request: A/B tests, geography, consent state, rotating ad creatives and cache-busting query parameters. Options:

- add cache-buster parameter names to the site's `ignoreQueryParams`;
- review whether the vendor serves several legitimate variants and approve them in the baseline (see [baselines.md](baselines.md));
- check the "formatting-only change" classification, which uses normalised hashes.

## Development: Vitest reports "failed to find the runner" on Windows

This happens when the working directory's drive letter is lower case (`c:\...`) and Vitest loads two copies of itself. Run the tests from a shell whose current directory uses an upper-case drive letter (`C:\...`), for example `cd C:\path\to\thirdsentry` in PowerShell.
