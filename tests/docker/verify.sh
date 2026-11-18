#!/bin/sh
# Verifies the container deployment end to end:
#   1. the pipeline (proxy -> scanner -> analyzer) produces a complete scan of a local fixture,
#   2. the scanner container has no direct route to the internet,
#   3. the egress proxy refuses cloud-metadata, internal and disallowed-port destinations,
#   4. the analyzer container has no network at all,
#   5. no alert secrets are visible inside the scanner.
# Requires the image: docker build -t scriptdrift:local .
set -eu
cd "$(dirname "$0")/../.."

export SCRIPTDRIFT_PROJECT_DIR=./tests/docker/project
export COMPOSE_PROJECT_NAME=scriptdrift-verify
DC="docker compose -f docker-compose.yml -f tests/docker/compose.verify.yml"
fail() { echo "FAIL: $*" >&2; $DC down -v >/dev/null 2>&1 || true; exit 1; }
pass() { echo "PASS: $*"; }

$DC down -v >/dev/null 2>&1 || true
$DC build fixture
$DC up -d --no-build fixture egress-proxy

# 1. Pipeline
$DC run --rm -T scanner || fail "scanner run failed"
status=0
$DC run --rm -T analyzer >/tmp/scriptdrift-verify-analyze.txt 2>&1 || status=$?
[ "$status" -eq 0 ] || { cat /tmp/scriptdrift-verify-analyze.txt; fail "analyzer exit code $status"; }
grep -q "complete" /tmp/scriptdrift-verify-analyze.txt || fail "scan not complete"
grep -q "vendor.js" /tmp/scriptdrift-verify-analyze.txt || fail "vendor.js not discovered"
pass "pipeline produced a complete scan with the vendor script"

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
if SCRIPTDRIFT_SLACK_WEBHOOK=should-not-leak $DC run --rm -T --entrypoint node scanner -e 'process.exit(Object.keys(process.env).some(k=>k.startsWith("SCRIPTDRIFT_")||k==="GITHUB_TOKEN")?7:0)'; then
  pass "scanner environment contains no alert credentials"
else
  fail "scanner environment contains alert credentials"
fi

$DC down -v >/dev/null 2>&1
echo "All container isolation checks passed."
