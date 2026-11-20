#!/bin/sh
# Run one ThirdSentry scan with the container pipeline (see docs/docker.md):
#   egress-proxy (long-running) -> scanner -> analyzer -> alerter
#
# Exit code is the analyzer's: 0 ok, 1 findings over threshold, 3 incomplete scan,
# 2 configuration error, 4 internal error. Alert delivery problems are reported
# on stderr but do not change the exit code.
#
# Runs are serialised (a second invocation waits for the first, up to
# THIRDSENTRY_LOCK_WAIT seconds, default 3600) and every run uses its own
# evidence file and proxy event record, named after a fresh run id. Both are
# deleted after a successful analysis and kept after a failure (the newest
# THIRDSENTRY_KEEP_FAILED, default 10, are retained).
set -eu

cd "$(dirname "$0")/.."
COMPOSE="${COMPOSE:-docker compose}"
LOCK_WAIT="${THIRDSENTRY_LOCK_WAIT:-3600}"
KEEP_FAILED="${THIRDSENTRY_KEEP_FAILED:-10}"
LOCK_FILE="${THIRDSENTRY_LOCK:-${TMPDIR:-/tmp}/thirdsentry-run-scan.lock}"

# --- serialise runs ---------------------------------------------------------
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK_FILE"
  if ! flock -w "$LOCK_WAIT" 9; then
    echo "thirdsentry: another scan still holds $LOCK_FILE after ${LOCK_WAIT}s" >&2
    exit 4
  fi
else
  # No flock (e.g. macOS): fall back to an atomic mkdir lock with a pid file.
  LOCK_DIR="$LOCK_FILE.d"
  waited=0
  until mkdir "$LOCK_DIR" 2>/dev/null; do
    owner="$(cat "$LOCK_DIR/pid" 2>/dev/null || true)"
    if [ -n "$owner" ] && ! kill -0 "$owner" 2>/dev/null; then
      echo "thirdsentry: removing stale lock of pid $owner" >&2
      rm -rf "$LOCK_DIR"
      continue
    fi
    if [ "$waited" -ge "$LOCK_WAIT" ]; then
      echo "thirdsentry: another scan still holds $LOCK_DIR after ${LOCK_WAIT}s" >&2
      exit 4
    fi
    sleep 2
    waited=$((waited + 2))
  done
  echo "$$" >"$LOCK_DIR/pid"
  trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM
fi

# --- per-run identity -------------------------------------------------------
THIRDSENTRY_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
export THIRDSENTRY_RUN_ID

# The egress proxy reads the configuration only when it starts. Hand it a hash
# of the file: when the file changed, `up -d` recreates the proxy.
CONFIG_FILE="${THIRDSENTRY_PROJECT_DIR:-./examples/project}/thirdsentry.yml"
if [ -f "$CONFIG_FILE" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    THIRDSENTRY_PROXY_CONFIG_HASH="$(sha256sum "$CONFIG_FILE" | cut -d' ' -f1)"
  elif command -v shasum >/dev/null 2>&1; then
    THIRDSENTRY_PROXY_CONFIG_HASH="$(shasum -a 256 "$CONFIG_FILE" | cut -d' ' -f1)"
  else
    THIRDSENTRY_PROXY_CONFIG_HASH="$(cksum "$CONFIG_FILE" | cut -d' ' -f1,2 | tr ' ' '-')"
  fi
  export THIRDSENTRY_PROXY_CONFIG_HASH
fi

# Delete this run's files (evidence: scanner volume; proxy events: proxy volume).
cleanup_run() {
  $COMPOSE run --rm -T --no-deps --entrypoint sh scanner -c \
    "rm -f '/evidence/$THIRDSENTRY_RUN_ID.json'" >/dev/null 2>&1 || echo "thirdsentry: could not delete evidence of run $THIRDSENTRY_RUN_ID" >&2
  $COMPOSE exec -T egress-proxy sh -c \
    "rm -f '/proxy-events/$THIRDSENTRY_RUN_ID.ndjson'" >/dev/null 2>&1 || echo "thirdsentry: could not delete proxy events of run $THIRDSENTRY_RUN_ID" >&2
}

# Keep only the newest $KEEP_FAILED leftovers of failed runs.
trim_failed() {
  $COMPOSE exec -T egress-proxy sh -c \
    "ls -1t /proxy-events/*.ndjson 2>/dev/null | tail -n +$((KEEP_FAILED + 1)) | xargs -r rm -f" >/dev/null 2>&1 || true
  $COMPOSE run --rm -T --no-deps --entrypoint sh scanner -c \
    "ls -1t /evidence/*.json 2>/dev/null | tail -n +$((KEEP_FAILED + 1)) | xargs -r rm -f" >/dev/null 2>&1 || true
}

echo "thirdsentry: run $THIRDSENTRY_RUN_ID" >&2
$COMPOSE up -d --wait egress-proxy

if ! $COMPOSE run --rm scanner; then
  echo "thirdsentry: browser collection failed (files of run $THIRDSENTRY_RUN_ID kept for inspection)" >&2
  trim_failed
  exit 4
fi

status=0
$COMPOSE run --rm analyzer || status=$?

case "$status" in
  0|1|3)
    cleanup_run
    # Reports were written; send alerts for new findings.
    if ! $COMPOSE run --rm alerter; then
      echo "thirdsentry: alert delivery failed (reports are unaffected)" >&2
    fi
    ;;
  *)
    echo "thirdsentry: analysis failed with exit code $status; no alerts sent (files of run $THIRDSENTRY_RUN_ID kept)" >&2
    trim_failed
    ;;
esac

exit "$status"
