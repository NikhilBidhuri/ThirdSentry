#!/bin/sh
# Run one ScriptDrift scan with the container pipeline (see docs/docker.md):
#   egress-proxy (long-running) -> scanner -> analyzer -> alerter
#
# Exit code is the analyzer's: 0 ok, 1 findings over threshold, 3 incomplete scan,
# 2 configuration error, 4 internal error. Alert delivery problems are reported
# on stderr but do not change the exit code.
set -eu

cd "$(dirname "$0")/.."
COMPOSE="${COMPOSE:-docker compose}"

$COMPOSE up -d egress-proxy

if ! $COMPOSE run --rm scanner; then
  echo "scriptdrift: browser collection failed" >&2
  exit 4
fi

status=0
$COMPOSE run --rm analyzer || status=$?

case "$status" in
  0|1|3)
    # Reports were written; send alerts for new findings.
    if ! $COMPOSE run --rm alerter; then
      echo "scriptdrift: alert delivery failed (reports are unaffected)" >&2
    fi
    ;;
  *)
    echo "scriptdrift: analysis failed with exit code $status; no alerts sent" >&2
    ;;
esac

exit "$status"
