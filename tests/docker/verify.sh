#!/bin/sh
# Verifies the container deployment end to end:
#   1. the pipeline (proxy -> scanner -> analyzer) produces a complete scan of a local fixture,
#   2. the scanner container has no direct route to the internet,
#   3. the egress proxy refuses cloud-metadata, internal and disallowed-port destinations,
#   4. the analyzer container has no network at all,
#   5. no alert secrets are visible inside the scanner.
#   (+ the analyzer reports a blocked-destination signal from the proxy's trusted record,
#      although the page fetched http://169.254.169.254/ and the scanner is untrusted)
# Builds both image targets (slim and browser) from the working tree.
set -eu
cd "$(dirname "$0")/../.."

export THIRDSENTRY_PROJECT_DIR=./tests/docker/project
export COMPOSE_PROJECT_NAME=thirdsentry-verify
DC="docker compose --profile pipeline --profile tools -f docker-compose.yml -f tests/docker/compose.verify.yml"
fail() { echo "FAIL: $*" >&2; $DC down -v >/dev/null 2>&1 || true; exit 1; }
pass() { echo "PASS: $*"; }

docker build --target slim -t thirdsentry:slim . >/dev/null || fail "slim image build failed"
docker build --target browser -t thirdsentry:local . >/dev/null || fail "browser image build failed"
$DC down -v >/dev/null 2>&1 || true
$DC build fixture scanner
$DC up -d --no-build fixture egress-proxy

# 1. Pipeline
$DC run --rm -T scanner || fail "scanner run failed"
status=0
$DC run --rm -T analyzer >/tmp/thirdsentry-verify-analyze.txt 2>&1 || status=$?
[ "$status" -eq 0 ] || { cat /tmp/thirdsentry-verify-analyze.txt; fail "analyzer exit code $status"; }
grep -q "complete" /tmp/thirdsentry-verify-analyze.txt || fail "scan not complete"
grep -q "vendor.js" /tmp/thirdsentry-verify-analyze.txt || fail "vendor.js not discovered"
pass "pipeline produced a complete scan with the vendor script"

# 1b. Blocked-connection evidence comes from the proxy's record, not from the scanner.
# Approve the clean scan as baseline, make the page fetch the cloud-metadata
# address, scan again: the analyzer must report a blocked-destination signal.
if $DC run --rm -T --entrypoint sh scanner -c 'ls /proxy-events' >/dev/null 2>&1; then fail "scanner can see the proxy-events volume"; fi
$DC run --rm -T tools baseline --yes >/dev/null 2>&1 || fail "could not approve the baseline"
$DC exec -T fixture node -e "fetch('http://127.0.0.1:8080/__evil').then(r=>process.exit(r.status===204?0:1),()=>process.exit(1))" || fail "could not switch the fixture page"
export THIRDSENTRY_RUN_ID=evil
$DC run --rm -T scanner >/dev/null 2>&1 || fail "second scanner run failed"
$DC run --rm -T analyzer >/tmp/thirdsentry-verify-analyze2.txt 2>&1 || true
grep -q "blocked by the network policy" /tmp/thirdsentry-verify-analyze2.txt || fail "analyzer did not report the blocked connection"
$DC run --rm -T --entrypoint sh analyzer -c 'cat /work/.thirdsentry/reports/report.json' >/tmp/thirdsentry-verify-report.json 2>/dev/null || fail "could not read the analyzer report"
grep -q '"blocked-destination"' /tmp/thirdsentry-verify-report.json || fail "analyzer report has no blocked-destination finding"
unset THIRDSENTRY_RUN_ID
pass "blocked metadata fetch is reported from the proxy's trusted event record (scanner cannot reach it)"

NODE_FETCH='fetch(process.argv[1], { signal: AbortSignal.timeout(5000) }).then(() => process.exit(0), () => process.exit(7))'

# 2. No direct internet from the scanner
if $DC run --rm -T --entrypoint node scanner -e "$NODE_FETCH" http://1.1.1.1/ >/dev/null 2>&1; then
  fail "scanner reached the internet directly"
fi
pass "scanner has no direct internet access"

# 3. Proxy policy, tested from inside the scanner container
PROXY_TEST='const net=require("node:net");const [h,p]=process.argv.slice(1);const s=net.connect(3128,"egress-proxy",()=>s.write(`CONNECT ${h}:${p} HTTP/1.1\r\nHost: ${h}:${p}\r\n\r\n`));s.setTimeout(8000,()=>{console.log("timeout");process.exit(9)});s.on("data",d=>{console.log(d.toString().split("\r\n")[0]);process.exit(0)});s.on("error",e=>{console.log("error "+e.message);process.exit(8)})'
for target in "169.254.169.254 80" "metadata.google.internal 80" "egress-proxy 3128" "fixture 22" "10.0.0.1 443"; do
  # shellcheck disable=SC2086
  out=$($DC run --rm -T --entrypoint node scanner -e "$PROXY_TEST" $target 2>/dev/null || true)
  echo "$out" | grep -q "403" || fail "proxy did not refuse $target (got: $out)"
  pass "proxy refused $target"
done

# 4. Analyzer has no network
if $DC run --rm -T --entrypoint node analyzer -e "$NODE_FETCH" http://fixture:8080/ >/dev/null 2>&1; then
  fail "analyzer has network access"
fi
pass "analyzer has no network access"

# 5. No secrets in the scanner environment
if THIRDSENTRY_SLACK_WEBHOOK=should-not-leak $DC run --rm -T --entrypoint node scanner -e 'process.exit(Object.keys(process.env).some(k=>k.startsWith("THIRDSENTRY_")||k==="GITHUB_TOKEN")?7:0)'; then
  pass "scanner environment contains no alert credentials"
else
  fail "scanner environment contains alert credentials"
fi

$DC down -v >/dev/null 2>&1
echo "All container isolation checks passed."
