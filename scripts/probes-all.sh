#!/usr/bin/env bash
# Run every probe we have, in order: unauth (fast, no setup), image
# (supply-chain), authenticated (issues test keys + revokes them).
#
# Designed for a nightly Container App Job or local sanity check. Exits 0
# only if EVERY probe passes; otherwise non-zero with a summary.
#
# Usage:
#   bash scripts/probes-all.sh
#   HOST=https://staging.cogos.5ceos.com bash scripts/probes-all.sh

set -uo pipefail

HOST="${HOST:-https://cogos.5ceos.com}"
DIR="$(cd "$(dirname "$0")" && pwd)"

OVERALL_FAIL=0

run_probe() {
  local script="$1" label="$2"
  echo ""
  echo "============================================================"
  echo "  $label"
  echo "============================================================"
  if HOST="$HOST" bash "$script"; then
    return 0
  else
    OVERALL_FAIL=$((OVERALL_FAIL + 1))
    return 1
  fi
}

run_probe "$DIR/probes-unauth.sh" "UNAUTH PROBES" || true
run_probe "$DIR/probes-image.sh"  "IMAGE PROBES"  || true
run_probe "$DIR/pentest-authed.sh" "AUTHENTICATED PROBES" || true

echo ""
echo "============================================================"
if [ "$OVERALL_FAIL" -eq 0 ]; then
  echo "  ALL PROBES PASSED"
else
  echo "  $OVERALL_FAIL PROBE SUITE(S) FAILED"
fi
echo "============================================================"
exit "$OVERALL_FAIL"
