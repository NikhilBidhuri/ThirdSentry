# Docker deployment

The Docker deployment runs ThirdSentry as four containers, one per trust boundary. It is the recommended way to run scheduled scans on your own infrastructure, because the browser (which executes untrusted third-party code) gets **no** credentials, **no** access to your baselines and **no** route to the internet or your network except through the policy-enforcing egress proxy.

```
                 internet
                    ▲
          ┌─────────┴─────────┐   egress network
          │   egress-proxy    │◄──────────────────────┐
          │ (network policy)  │                       │
          └─────────▲─────────┘                       │
   scan-internal    │  (internal: no internet route)  │
          ┌─────────┴─────────┐                ┌──────┴──────┐
          │      scanner      │                │   alerter   │  ← .env credentials
          │ browser, no secrets│               │ reads reports│
          └─────────┬─────────┘                └──────▲──────┘
                    │ evidence volume                 │ reports volume (ro)
          ┌─────────▼─────────┐                       │
          │     analyzer      │───────────────────────┘
          │ network_mode: none│  baselines mounted read-only
          └───────────────────┘
```

| Container | Network | Mounts | Secrets |
| --- | --- | --- | --- |
| `egress-proxy` | `scan-internal` + `egress` | config (ro) | none |
| `scanner` | `scan-internal` only (no internet route) | config (ro), evidence volume | none |
| `analyzer` | none | config (ro), **baselines (ro)**, evidence (ro), reports, state, cache | none |
| `alerter` | `egress` | config (ro), reports (ro), state | `.env` |
| `tools` | none | config (ro), baselines (rw), reports, state, cache | none |

All containers run as the unprivileged `pwuser`, with a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, memory/CPU/PID limits and private `/tmp`. No host directories other than your project's `thirdsentry.yml` and baselines are mounted.

The egress proxy enforces the same per-connection policy as in local mode (see [security.md](security.md)). Because the scanner's network is `internal`, Docker itself refuses any connection that does not go through the proxy, so network restrictions are applied at the container network layer, not only by URL checks. Note that the proxy also blocks the private addresses Docker uses for its networks, so the browser cannot reach the other containers.

**Chromium sandbox:** inside the hardened scanner container (no capabilities, `no-new-privileges`), Chromium's own namespace sandbox cannot start, so the scanner runs with `--no-chromium-sandbox` and relies on the container boundary. If you prefer to keep Chromium's sandbox as an additional layer, run the scanner with Playwright's [seccomp profile](https://playwright.dev/docs/docker) and remove `--no-chromium-sandbox`; that requires relaxing the container settings and is not the default.

## Setup

1. Build the image (the tag must stay in sync with the pinned Playwright version):

   ```bash
   docker build -t thirdsentry:local .
   ```

2. Create a project directory with your configuration and baselines (or use `examples/project`):

   ```
   my-monitoring/
     thirdsentry.yml
     .thirdsentry/baselines/      # committed, reviewed baselines
   ```

   and point the compose file at it:

   ```bash
   export THIRDSENTRY_PROJECT_DIR=/srv/my-monitoring
   ```

3. Put alert credentials in `.env` next to `docker-compose.yml` (see `.env.example`). Only the `alerter` container reads it. Never commit `.env`.

4. Run a scan:

   ```bash
   ./scripts/run-scan.sh
   ```

   This starts the proxy (long-running), then runs `scanner` → `analyzer` → `alerter`. The exit code is the analyzer's (`0` ok, `1` findings over threshold, `3` incomplete scan). Alert failures are reported but do not change it.

## First baseline and maintenance

Baselines are approved explicitly, by a person:

```bash
./scripts/run-scan.sh                         # first scan (no baseline yet)
docker compose run --rm tools diff            # review
docker compose run --rm tools baseline        # approve (asks for confirmation; use -it)
docker compose run --rm -it tools baseline
```

`tools` is the only container that can write baselines. The files land in `$THIRDSENTRY_PROJECT_DIR/.thirdsentry/baselines/`; commit them to version control after review.

Reports are kept in the `reports` volume. To copy them out:

```bash
docker compose run --rm --entrypoint sh tools -c 'cat /work/.thirdsentry/reports/report.html' > report.html
```

## Environment variables

| Variable | Where | Purpose |
| --- | --- | --- |
| `THIRDSENTRY_PROJECT_DIR` | host (compose) | Directory with `thirdsentry.yml` and `.thirdsentry/baselines`. Default `./examples/project`. |
| `COMPOSE` | host (`run-scan.sh`) | Override the compose command (default `docker compose`). |
| Alert variables | `.env` (alerter only) | See [alerts.md](alerts.md#environment-variables). |

## Scheduling

See [cron.md](cron.md) for cron and systemd timers.

## Verifying the isolation

`tests/docker/verify.sh` runs the pipeline against a local fixture site and checks that:

- the scan completes and discovers the fixture's scripts,
- the scanner cannot reach the internet directly,
- the proxy refuses cloud-metadata (`169.254.169.254`, `metadata.google.internal`), private (`10.0.0.1`) and disallowed-port destinations, including the other containers,
- the analyzer has no network access,
- no alert credentials are present in the scanner's environment.

```bash
docker build -t thirdsentry:local . && sh tests/docker/verify.sh
```

The verification overlay bakes its fixture configuration into a derived image instead of bind-mounting it, so it also runs where host file sharing is restricted; networks, capabilities, read-only filesystems and volumes are those of the real `docker-compose.yml`.
