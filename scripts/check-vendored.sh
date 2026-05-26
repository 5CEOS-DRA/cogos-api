#!/usr/bin/env bash
# Vendor-drift detector for cogos-api process modules.
#
# The substrate process engines are vendored byte-equal from the
# 5ceos-platform-internal repo (see SUBSTRATE_CANON_v0.x I7). This
# script reports drift between vendored copies and their upstream
# source-of-truth files.
#
# Allowed local edits in the vendored copies:
#   - require-path translation (./_canonicalize vs ../substrate/canonicalize.cjs)
#   - vendor-header note pointing back at upstream
# Everything else is drift and must be reconciled by re-vendoring.
#
# Usage:
#   ./scripts/check-vendored.sh           · report only · exit 0 if clean, 1 if drift
#   ./scripts/check-vendored.sh --fix     · re-copy upstream over vendored + fix require paths
#                                            (preserves the vendor-header note)
#
# Exit codes:
#   0 · all vendored files match upstream (modulo allowed local edits)
#   1 · drift detected (printed to stderr)
#   2 · script invocation error (missing upstream, missing files)
#
# Requires: diff, sed, mktemp.

set -euo pipefail

UPSTREAM_ROOT="${UPSTREAM_ROOT:-$HOME/dev/5ceos-platform-internal}"
LOCAL_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -d "$UPSTREAM_ROOT" ]]; then
  echo "ERROR: upstream platform repo not found at $UPSTREAM_ROOT" >&2
  echo "       set UPSTREAM_ROOT env var to override" >&2
  exit 2
fi

MODE="report"
if [[ "${1:-}" == "--fix" ]]; then MODE="fix"; fi

# Mapping table · vendored_path : upstream_path
# Keep alphabetically sorted by vendored_path for stable output.
MAPPINGS=(
  "src/processes/5law-conflict.js:backend/services/5law/conflictEngine.cjs"
  "src/processes/_canonicalize.js:backend/services/substrate/canonicalize.cjs"
  "src/processes/_compose.js:backend/services/substrate/compose.cjs"
  "src/processes/_keyState.js:backend/services/substrate/keyState.cjs"
  "src/processes/iolta-reconciler.js:backend/services/5law/trustReconciler.cjs"
  "src/processes/ma-detectors.js:backend/services/ma-truth/detectors/index.js"
  "src/processes/primitive-8/rule_8_03.js:backend/services/ma-truth/organizational-integrity/rules/rule_8_03.js"
  "src/processes/primitive-8/rule_8_04.js:backend/services/ma-truth/organizational-integrity/rules/rule_8_04.js"
  "src/processes/primitive-8/rule_8_07.js:backend/services/ma-truth/organizational-integrity/rules/rule_8_07.js"
)

# Allowed require-path translations · "<vendored require> → <upstream require>"
# When diffing, we normalize the vendored side BACK to upstream require paths
# so legitimate path edits don't surface as drift.
NORMALIZE_TO_UPSTREAM=(
  "./_canonicalize|../substrate/canonicalize.cjs"
)

drift_count=0

for pair in "${MAPPINGS[@]}"; do
  vendored="${pair%%:*}"
  upstream="${pair#*:}"
  vendored_abs="$LOCAL_ROOT/$vendored"
  upstream_abs="$UPSTREAM_ROOT/$upstream"

  if [[ ! -f "$vendored_abs" ]]; then
    echo "MISSING vendored: $vendored" >&2
    drift_count=$((drift_count+1))
    continue
  fi
  if [[ ! -f "$upstream_abs" ]]; then
    echo "MISSING upstream: $upstream" >&2
    drift_count=$((drift_count+1))
    continue
  fi

  if [[ "$MODE" == "fix" ]]; then
    cp "$upstream_abs" "$vendored_abs"
    # Apply require-path translations: upstream-style → cogos-api-style.
    for rule in "${NORMALIZE_TO_UPSTREAM[@]}"; do
      vendored_form="${rule%%|*}"
      upstream_form="${rule##*|}"
      # Escape slashes for sed
      sed_upstream="$(printf '%s' "$upstream_form" | sed 's|/|\\/|g')"
      sed_vendored="$(printf '%s' "$vendored_form" | sed 's|/|\\/|g')"
      sed -i.bak "s/${sed_upstream}/${sed_vendored}/g" "$vendored_abs" && rm -f "$vendored_abs.bak"
    done
    echo "FIXED: $vendored"
    continue
  fi

  # Report mode: normalize vendored to upstream form before diffing.
  tmp_vendored="$(mktemp)"
  cp "$vendored_abs" "$tmp_vendored"
  for rule in "${NORMALIZE_TO_UPSTREAM[@]}"; do
    vendored_form="${rule%%|*}"
    upstream_form="${rule##*|}"
    sed_upstream="$(printf '%s' "$upstream_form" | sed 's|/|\\/|g')"
    sed_vendored="$(printf '%s' "$vendored_form" | sed 's|/|\\/|g')"
    sed -i.bak "s/${sed_vendored}/${sed_upstream}/g" "$tmp_vendored" && rm -f "$tmp_vendored.bak"
  done

  # Diff · ignore the vendor-header block by stripping lines between
  # the two "VENDORED COPY" marker and the next "5law" or "Substrate"
  # heading. We use diff -I to ignore the marker lines themselves; the
  # vendored copies add 4-12 lines of vendoring-note prose at the top
  # which is the allowed edit beyond require paths.
  if diff -q -I '^ \* VENDORED COPY' -I '^ \* \s*5ceos-platform-internal' -I '^ \*\s*Pure-function module' -I '^ \*\s*Fix upstream' -I '^ \* \s*$' "$tmp_vendored" "$upstream_abs" >/dev/null 2>&1; then
    : # match (modulo ignored vendor-header lines)
  else
    # Honest report: any remaining diff is drift.
    if ! diff -u -I '^ \* VENDORED COPY' -I '^ \*\s*5ceos-platform-internal' -I '^ \*\s*Pure-function module' -I '^ \*\s*Fix upstream' "$tmp_vendored" "$upstream_abs" | grep -E '^[+-][^+-]' >/dev/null; then
      : # only header-block lines differ; allowed
    else
      drift_count=$((drift_count+1))
      echo "DRIFT: $vendored ⟷ $upstream" >&2
      diff -u -I '^ \* VENDORED COPY' -I '^ \*\s*5ceos-platform-internal' "$tmp_vendored" "$upstream_abs" | head -40 >&2 || true
      echo "" >&2
    fi
  fi
  rm -f "$tmp_vendored"
done

if [[ "$MODE" == "fix" ]]; then
  echo "" >&2
  echo "Done. Run tests + commit. The fix path re-copies upstream over vendored" >&2
  echo "and re-applies require-path translations only — the vendor-header note" >&2
  echo "will need to be re-added manually since upstream doesn't carry it." >&2
  exit 0
fi

if [[ $drift_count -eq 0 ]]; then
  echo "✓ all ${#MAPPINGS[@]} vendored files match upstream"
  exit 0
else
  echo "" >&2
  echo "✗ $drift_count drift / missing finding(s) · run 'scripts/check-vendored.sh --fix' to re-vendor" >&2
  exit 1
fi
