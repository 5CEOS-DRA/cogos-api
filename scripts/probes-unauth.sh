#!/usr/bin/env bash
# Unauthenticated continuous probes against cogos.5ceos.com.
#
# Designed to be run as a scheduled job (Container App Job, cron, GitHub
# Actions) — checks the public-facing security surface without needing
# any keys or admin credentials. Fast (~10 seconds), idempotent, no side
# effects, no test-key issuance, no anomaly-counter pollution.
#
# Exits 0 if all probes pass; non-zero with a summary if any fail.
# Output is line-per-probe so the result feeds easily into /trust or any
# monitoring tool that wants probe status.

set -euo pipefail

HOST="${HOST:-https://cogos.5ceos.com}"
PASS=0
FAIL=0
FAIL_LINES=()

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); FAIL_LINES+=("$1"); }

# ---------------------------------------------------------------------------
# Honeypot canary content on scanner paths
# ---------------------------------------------------------------------------
echo "[unauth] honeypot canary content"
for p in /.env /.aws/credentials /.git/config /wp-admin /backup.sql; do
  BODY=$(curl -sS "$HOST$p")
  if echo "$BODY" | grep -qiE "HONEYPOT|EXAMPLE|fake"; then
    pass "honeypot path $p returns canary content"
  else
    fail "honeypot path $p missing canary markers"
  fi
done
# Case + slash variants — pentest finding 2026-05-14, must stay closed
for p in "/.ENV" "/Wp-Admin" "/Backup.SQL" "/.env/"; do
  C=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST$p")
  if [ "$C" = "200" ]; then
    pass "honeypot variant $p trips trap (200)"
  else
    fail "honeypot variant $p bypasses trap ($C — expected 200)"
  fi
done

# ---------------------------------------------------------------------------
# All /admin/* + /v1/* reject without auth
# ---------------------------------------------------------------------------
echo ""
echo "[unauth] /admin/* and /v1/* require auth"
for p in /admin/keys /admin/usage /admin/packages /v1/models /v1/audit; do
  C=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST$p")
  if [ "$C" = "401" ]; then
    pass "$p → 401 without auth"
  else
    fail "$p → $C without auth (expected 401)"
  fi
done

# ---------------------------------------------------------------------------
# /admin/live was removed — must 404
# ---------------------------------------------------------------------------
echo ""
echo "[unauth] removed routes stay removed"
C=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/admin/live")
if [ "$C" = "404" ]; then
  pass "/admin/live → 404 (removed in v15)"
else
  fail "/admin/live → $C (expected 404 — route resurrection?)"
fi

# ---------------------------------------------------------------------------
# Repo files NOT served
# ---------------------------------------------------------------------------
echo ""
echo "[unauth] no source / config file leakage"
for p in /SECURITY.md /STATE.md /package.json /Dockerfile /src/index.js /tests/api.test.js /.gitignore; do
  C=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST$p")
  if [ "$C" = "404" ]; then
    pass "$p → 404"
  else
    fail "$p → $C (file leak?)"
  fi
done

# ---------------------------------------------------------------------------
# Security headers present on every response shape
# ---------------------------------------------------------------------------
echo ""
echo "[unauth] security headers"
for p in / /health /cosign.pub /attestation.pub /.env; do
  HDRS=$(curl -sIL "$HOST$p")
  if echo "$HDRS" | grep -qi "content-security-policy:" \
     && echo "$HDRS" | grep -qi "strict-transport-security:" \
     && echo "$HDRS" | grep -qi "x-frame-options:" \
     && echo "$HDRS" | grep -qi "x-content-type-options:"; then
    pass "$p carries CSP + HSTS + X-Frame + X-Content-Type"
  else
    fail "$p missing one or more required security headers"
  fi
done

# ---------------------------------------------------------------------------
# Public pubkey endpoints
# ---------------------------------------------------------------------------
echo ""
echo "[unauth] public pubkey endpoints"
COSIGN=$(curl -sS "$HOST/cosign.pub" | head -1)
if echo "$COSIGN" | grep -q "BEGIN PUBLIC KEY"; then
  pass "/cosign.pub serves a PEM"
else
  fail "/cosign.pub does not look like a PEM (got: $COSIGN)"
fi
ATT=$(curl -sS "$HOST/attestation.pub" | head -1)
if echo "$ATT" | grep -q "BEGIN PUBLIC KEY"; then
  pass "/attestation.pub serves a PEM"
else
  fail "/attestation.pub does not look like a PEM (got: $ATT)"
fi

# ---------------------------------------------------------------------------
# Legal + trust pages
# ---------------------------------------------------------------------------
echo ""
echo "[unauth] policy + trust pages reachable"
for p in /terms /privacy /aup /dpa /baa /gdpr /sub-processors /trust /cookbook /whitepaper /demo; do
  C=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST$p")
  if [ "$C" = "200" ]; then
    pass "$p → 200"
  else
    fail "$p → $C (expected 200)"
  fi
done

echo ""
echo "============================================================"
echo "[probes-unauth] $PASS pass, $FAIL fail"
if [ "$FAIL" -gt 0 ]; then
  for line in "${FAIL_LINES[@]}"; do echo "  - $line"; done
  exit 1
fi
echo "[probes-unauth] all unauth probes clean."
echo "============================================================"
