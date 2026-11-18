# Installation

## Requirements

- Node.js **20.11 or newer** (22 LTS recommended).
- A Playwright browser build for each engine you want to use. Chromium is enough for most setups.
- Linux, macOS or Windows. Production deployments should run on Linux, ideally using the [Docker setup](docker.md), which adds container-level isolation.

## Install into a project (recommended)

```bash
npm install --save-dev scriptdrift
npx playwright install chromium
# optional engines
npx playwright install firefox webkit
```

On Linux CI machines, also install the system libraries the browsers need:

```bash
npx playwright install --with-deps chromium
```

Then create a configuration:

```bash
npx scriptdrift init --url https://www.example.com --name my-site
```

`init` creates:

| Path | Purpose | Commit to Git? |
| --- | --- | --- |
| `scriptdrift.yml` | configuration | yes |
| `.scriptdrift/baselines/` | approved baselines | yes, after review |
| `.scriptdrift/.gitignore` | keeps `reports/`, `cache/`, `state/`, `evidence/` out of Git | yes |

It also adds `.env` to your root `.gitignore` so that alert credentials are not committed by accident.

## Global install

```bash
npm install -g scriptdrift
npx playwright install chromium
scriptdrift --help
```

## Docker

See [docker.md](docker.md). The image bundles Node.js, ScriptDrift and Playwright's browsers, runs as a non-root user and is designed to run the browser worker in a separate, network-restricted container.

## Building from source

```bash
git clone <repository-url> scriptdrift
cd scriptdrift
npm ci
npx playwright install chromium
npm run build
node dist/cli/bin.js --help
```

## Verifying the installation

```bash
npx scriptdrift --version
npx scriptdrift scan --site my-site
```

If the browser fails to start, see [troubleshooting.md](troubleshooting.md).
