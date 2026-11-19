# Scheduled scans with cron or systemd

Third-party scripts can change at any time, so ThirdSentry is most useful when it runs on a schedule. Choose an interval that matches how quickly you want to know about a change (every 1-6 hours is typical) and how much load you are willing to put on your own site (each run loads every configured page once).

## cron (Docker pipeline)

`examples/cron/crontab`:

```cron
0 */6 * * * cd /opt/thirdsentry && flock -n /tmp/thirdsentry.lock ./scripts/run-scan.sh >> /var/log/thirdsentry/scan.log 2>&1
```

- `flock -n` prevents overlapping runs if a scan takes longer than the interval.
- `run-scan.sh` exits `1` when findings exceed `failOn` and `3` when a scan was incomplete; cron treats every run the same, so rely on alerts (or log monitoring) for notification.
- Run it as a user that may use Docker. The ThirdSentry containers themselves run unprivileged.

## cron without Docker

```cron
0 */6 * * * cd /srv/monitoring && flock -n /tmp/thirdsentry.lock npx thirdsentry scan >> /var/log/thirdsentry/scan.log 2>&1
```

The browser still runs in a separate process with a scrubbed environment and all traffic still goes through the egress proxy, but there is no container network isolation. Prefer the Docker pipeline on shared servers. Alert credentials must be in the cron job's environment (for example in a root-readable env file sourced by a wrapper script), never in `thirdsentry.yml`.

## systemd timer

`examples/systemd/thirdsentry.service` and `thirdsentry.timer`:

```bash
sudo cp examples/systemd/thirdsentry.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now thirdsentry.timer
systemctl list-timers thirdsentry.timer
journalctl -u thirdsentry.service
```

The service treats exit codes `1` and `3` as success (`SuccessExitStatus=1 3`), because they are expected outcomes rather than service failures; findings are delivered by alerts. `RandomizedDelaySec` spreads load, and `Persistent=true` runs a missed scan after downtime.

## Retention

Each run writes a scan result. Old results, screenshots and cached script content are removed according to `retention.maxScanReports` and `retention.maxAgeDays` after every scan. To clean up manually:

```bash
npx thirdsentry cleanup                 # apply retention now
npx thirdsentry cleanup --all-content   # also delete all cached script bodies
docker compose run --rm tools cleanup   # Docker
```
