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
| `egress-proxy` | `scan-internal` + `egress` | config (ro), **proxy-events (rw)** | none |
| `scanner` | `scan-internal` only (no internet route) | config (ro), evidence volume (not proxy-events) | none |
| `analyzer` | none | config (ro), **baselines (ro)**, evidence (ro), **proxy-events (ro)**, reports, state, cache, **vulndb (ro)** | none |
| `alerter` | `egress` | config (ro), reports (ro), state | `.env` |
| `tools` | none | config (ro), baselines (rw), reports, state, cache, **vulndb (ro)** | none |
| `vulndb-updater` (on demand) | `egress` | config (ro), **vulndb (rw)** and nothing else | none |

All containers run as the unprivileged `pwuser`, with a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, memory/CPU/PID limits and private `/tmp`. No host directories other than your project's `thirdsentry.yml` and baselines are mounted.

The egress proxy enforces the same per-connection policy as in local mode (see [security.md](security.md)). Because the scanner's network is `internal`, Docker itself refuses any connection that does not go through the proxy, so network restrictions are applied at the container network layer, not only by URL checks. Note that the proxy also blocks the private addresses Docker uses for its networks, so the browser cannot reach the other containers.

**Trusted connection evidence.** The scanner runs hostile page code, so what it reports about blocked connections is not trusted. The scanner tags every connection it makes through the proxy with `<run-id>.<site>` (a Basic `Proxy-Authorization` user name; it is attribution only, the proxy never requires it), the proxy appends the connection events to `/proxy-events/<run-id>.ndjson` (a volume the scanner cannot mount; size-capped, at most 5,000 blocked and 5,000 allowed events per site, dropped events are counted and reported), and `analyze --proxy-events <file>` replaces each site's connection events with that record. Without `--proxy-events` the scanner's own events are used and a warning issue is added. Limitation: a fully compromised scanner can mis-tag its connections and so hide them from the record, but it cannot forge or alter events recorded under the correct tag. If the record is missing for a run, the scan gets an error issue (`proxy-events-missing`). A page that fetches a blocked plain-`http://` address receives the proxy's 403 as an ordinary response, which the analyzer's per-request "blocked" marking does not recognise; HTTPS (CONNECT) blocks are marked.

**Configuration changes.** The egress proxy reads `thirdsentry.yml` only when it starts. `scripts/run-scan.sh` passes a hash of the file to the proxy container, so the proxy is recreated automatically when the file changed. If you run `docker compose` by hand, use `docker compose up -d --force-recreate egress-proxy` after editing the configuration.

**Images.** One Dockerfile, two targets: `slim` (`thirdsentry:slim`, Node.js only, about 400 MB) runs the egress proxy, analyzer, alerter and tools; `browser` (`thirdsentry:local`, Playwright image, about 3.7 GB) runs only the scanner. The scanner waits for the proxy's healthcheck before it starts.

**Chromium sandbox:** inside the hardened scanner container (no capabilities, `no-new-privileges`), Chromium's own namespace sandbox cannot start, so the scanner runs with `--no-chromium-sandbox` and relies on the container boundary. If you prefer to keep Chromium's sandbox as an additional layer, run the scanner with Playwright's [seccomp profile](https://playwright.dev/docs/docker) and remove `--no-chromium-sandbox`; that requires relaxing the container settings and is not the default.

## Setup

1. Build the images (the Playwright tag must stay in sync with the pinned Playwright version; the slim image's Node.js major must match the Playwright image's):

   ```bash
   docker compose build        # or: docker build --target slim -t thirdsentry:slim . && docker build --target browser -t thirdsentry:local .
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

   This starts the proxy (long-running, waits until it is healthy), then runs `scanner` → `analyzer` → `alerter`. Every run gets its own run id, evidence file and proxy event record, and runs are serialised with a lock (`flock`, or a lock directory where `flock` is missing; `THIRDSENTRY_LOCK_WAIT` seconds, default 3600). The per-run files are deleted after a successful analysis; after a failure they are kept (newest `THIRDSENTRY_KEEP_FAILED`, default 10). The exit code is the analyzer's (`0` ok, `1` findings over threshold, `3` incomplete scan or a site without an approved baseline). The very first run therefore exits `3` until you approve a baseline; add `--allow-missing-baseline` to the analyzer command if you prefer `0` there. Alert failures are reported but do not change it.

## First baseline and maintenance

Baselines are approved explicitly, by a person:

```bash
./scripts/run-scan.sh                         # first scan (no baseline yet)
docker compose run --rm tools diff            # review
docker compose run --rm tools baseline        # approve (asks for confirmation; use -it)
docker compose run --rm -it tools baseline
```

`tools` is the only container that can write baselines and the PCI script inventory (`.thirdsentry/inventory/`, mounted read-only into the analyzer; see [pci.md](pci.md)). The files land in `$THIRDSENTRY_PROJECT_DIR/.thirdsentry/baselines/`; commit them to version control after review.

Reports are kept in the `reports` volume. To copy them out:

```bash
docker compose run --rm --entrypoint sh tools -c 'cat /work/.thirdsentry/reports/report.html' > report.html
```

## Vulnerability database updates

Library recognition and CVE lookup ([libraries.md](libraries.md)) use a retire.js database that is downloaded by `thirdsentry vulndb update`. Without it the analyzer uses a small bundled seed and every report says so. Because the analyzer and `tools` have no network, the update runs in its own short-lived service:

```bash
docker compose run --rm vulndb-updater       # download, validate, install; then it exits
```

Why a separate service rather than the alerter or `tools`: the alerter holds your alert credentials, and giving `tools` a network would remove the guarantee that nothing that can write baselines can reach the internet. `vulndb-updater` has the narrowest possible footprint: egress network only, no secrets, no baselines, reports or state, a read-only root filesystem, and write access to one volume (`vulndb`) that the analyzer and `tools` mount **read-only**. It uses the SSRF-safe client, caps the download, validates it against a strict schema and writes it atomically, so a failed or hostile download leaves the previous database in place. The analyzer treats the file as untrusted input regardless (strict schema, regex safeguards).

Schedule it daily or weekly (see [cron.md](cron.md)); reports warn when the database is older than `libraries.maxDbAgeDays` (default 30). Check the state with `docker compose run --rm tools vulndb status`.

## Journeys and credentials

Logged-in journeys need credentials in the browser, so the scanner container is the one place that receives them. Keep them out of `.env` (read by the alerter) and in a separate file that only the scanner reads:

```bash
# journeys.env (next to docker-compose.yml; not committed; chmod 600)
THIRDSENTRY_SECRET_SHOP_PASSWORD=<password of a dedicated, least-privilege test account>
```

`docker-compose.yml` attaches it with `env_file` to the `scanner` service only (optional: without the file the scanner has no secrets, and journeys that reference one fail with `journey-secret-missing`). The analyzer, alerter and egress proxy do not get it. Only variables named `THIRDSENTRY_SECRET_*` and referenced by a journey are used. For a `storageState` session file, mount it read-only into the scanner and reference the container path (relative to `thirdsentry.yml`). Use dedicated test accounts, never live payment credentials; see [security.md](security.md#journey-credentials).

## Environment variables

| Variable | Where | Purpose |
| --- | --- | --- |
| `THIRDSENTRY_PROJECT_DIR` | host (compose) | Directory with `thirdsentry.yml` and `.thirdsentry/baselines`. Default `./examples/project`. |
| `THIRDSENTRY_RUN_ID` | host (compose) | Names the run's evidence file and proxy event record. Set by `run-scan.sh`; default `manual`. |
| `COMPOSE` | host (`run-scan.sh`) | Override the compose command (default `docker compose`). |
| `THIRDSENTRY_METRICS_PORT` | host (compose) | Host port of the optional `metrics` service (bound to `127.0.0.1`). Default `9464`. |
| `THIRDSENTRY_HEARTBEAT_URL` | `.env` (alerter only) | Ping URL for `health.heartbeat`. It is a secret; keep it out of `thirdsentry.yml`. |
| Alert variables | `.env` (alerter only) | See [alerts.md](alerts.md#environment-variables). |
| `THIRDSENTRY_SECRET_*` | `journeys.env` (scanner only) | Journey credentials referenced as `${THIRDSENTRY_SECRET_<NAME>}` in `fill` steps. |

## Scheduling

See [cron.md](cron.md) for cron and systemd timers.

## Metrics (optional)

`docker compose --profile metrics up -d metrics` starts a read-only Prometheus exporter (`thirdsentry metrics --serve`) in the slim image. It mounts the configuration, `reports` and `state` read-only, receives no credentials, and is attached only to a dedicated network with outbound masquerading disabled; its single port is published on the host's loopback (`127.0.0.1:9464`). The exporter has no authentication, so do not publish it on another address without a reverse proxy. For batch jobs the textfile collector is the recommended mode: `docker compose run --rm -v /var/lib/node_exporter/textfile:/textfile tools metrics --textfile /textfile/thirdsentry.prom`. The heartbeat ping (dead-man's switch) is sent by the `alerter` container, the only one with network access and credentials. See [monitoring.md](monitoring.md).

## Verifying the isolation

`tests/docker/verify.sh` runs the pipeline against a local fixture site and checks that:

- the scan completes and discovers the fixture's scripts,
- the scanner cannot reach the internet directly,
- the proxy refuses cloud-metadata (`169.254.169.254`, `metadata.google.internal`), private (`10.0.0.1`) and disallowed-port destinations, including the other containers,
- a page that fetches the cloud-metadata address produces a `blocked-destination` signal in the analyzer's report, taken from the proxy's event record (the scanner cannot see that volume),
- the analyzer has no network access,
- no alert credentials are present in the scanner's environment.

```bash
sh tests/docker/verify.sh      # builds both image targets first
```

The verification overlay bakes its fixture configuration into a derived image instead of bind-mounting it, so it also runs where host file sharing is restricted; networks, capabilities, read-only filesystems and volumes are those of the real `docker-compose.yml`.
