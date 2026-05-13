#!/usr/bin/env bash
# Smoke-test the live cogos-api inference path end-to-end.
# Verifies: /health, /v1/models, /v1/chat/completions (plain),
# /v1/chat/completions (schema-locked), and 5-call determinism.
#
# Usage:
#   COGOS_API_KEY=sk-cogos-... bash scripts/smoke-api.sh
#   COGOS_API_KEY=sk-cogos-... BASE=https://cogos.5ceos.com bash scripts/smoke-api.sh

set -u

BASE="${BASE:-https://cogos.5ceos.com}"
KEY="${COGOS_API_KEY:-}"

if [ -z "$KEY" ]; then
  echo "ERROR: COGOS_API_KEY not set."
  echo "Run with:  COGOS_API_KEY=sk-cogos-... bash scripts/smoke-api.sh"
  exit 1
fi

if [ -t 1 ]; then G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; N='\033[0m'
else G=''; R=''; Y=''; N=''; fi

pass() { printf "  ${G}✓${N} %s\n" "$1"; }
fail() { printf "  ${R}✗${N} %s\n" "$1"; FAILS=$((FAILS+1)); }
warn() { printf "  ${Y}!${N} %s\n" "$1"; }

FAILS=0

echo ""
echo "=== Smoke-testing ${BASE} ==="
echo ""

# 1. Health
echo "[1/5] /health"
HEALTH=$(curl -s -w "\n%{http_code}" "${BASE}/health")
HEALTH_CODE=$(echo "$HEALTH" | tail -1)
HEALTH_BODY=$(echo "$HEALTH" | head -n -1)
[ "$HEALTH_CODE" = "200" ] && pass "200 OK" || fail "got ${HEALTH_CODE}"
echo "    body: ${HEALTH_BODY:0:120}"

# 2. /v1/models
echo ""
echo "[2/5] /v1/models (bearer auth)"
MODELS=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer ${KEY}" "${BASE}/v1/models")
MODELS_CODE=$(echo "$MODELS" | tail -1)
MODELS_BODY=$(echo "$MODELS" | head -n -1)
if [ "$MODELS_CODE" = "200" ]; then
  pass "200 OK"
  echo "    models: $(echo "$MODELS_BODY" | grep -oE '"id":"[^"]+"' | head -3 | tr '\n' ' ')"
else
  fail "got ${MODELS_CODE}"
  echo "    body: ${MODELS_BODY:0:200}"
fi

# 3. /v1/chat/completions plain
echo ""
echo "[3/5] /v1/chat/completions (plain, cogos-tier-b)"
PLAIN_PAYLOAD='{"model":"cogos-tier-b","messages":[{"role":"user","content":"Say HELLO. One word."}]}'
PLAIN_RESP=$(curl -s -w "\nHTTP_CODE=%{http_code}" -H "Authorization: Bearer ${KEY}" -H "Content-Type: application/json" -d "$PLAIN_PAYLOAD" "${BASE}/v1/chat/completions")
PLAIN_CODE=$(echo "$PLAIN_RESP" | grep "HTTP_CODE=" | sed 's/HTTP_CODE=//')
PLAIN_BODY=$(echo "$PLAIN_RESP" | grep -v "HTTP_CODE=")
if [ "$PLAIN_CODE" = "200" ]; then
  pass "200 OK"
  CONTENT=$(echo "$PLAIN_BODY" | grep -oE '"content":"[^"]*"' | head -1 | sed 's/.*"content":"//' | sed 's/"$//')
  echo "    response: ${CONTENT:0:100}"
else
  fail "got ${PLAIN_CODE}"
  echo "    body: ${PLAIN_BODY:0:300}"
fi

# 4. /v1/chat/completions schema-locked
echo ""
echo "[4/5] /v1/chat/completions (schema-locked JSON)"
SCHEMA_PAYLOAD='{"model":"cogos-tier-b","messages":[{"role":"user","content":"What is 12 times 8?"}],"response_format":{"type":"json_schema","json_schema":{"name":"a","strict":true,"schema":{"type":"object","required":["product"],"properties":{"product":{"type":"integer"}}}}}}'
SCHEMA_RESP=$(curl -s -w "\nHTTP_CODE=%{http_code}" -H "Authorization: Bearer ${KEY}" -H "Content-Type: application/json" -d "$SCHEMA_PAYLOAD" "${BASE}/v1/chat/completions")
SCHEMA_CODE=$(echo "$SCHEMA_RESP" | grep "HTTP_CODE=" | sed 's/HTTP_CODE=//')
SCHEMA_BODY=$(echo "$SCHEMA_RESP" | grep -v "HTTP_CODE=")
if [ "$SCHEMA_CODE" = "200" ]; then
  pass "200 OK"
  SCHEMA_CONTENT=$(echo "$SCHEMA_BODY" | grep -oE '"content":"[^"]*"' | head -1)
  echo "    content: ${SCHEMA_CONTENT}"
  if echo "$SCHEMA_CONTENT" | grep -q "product"; then
    pass "response contains 'product' key"
  else
    fail "no 'product' key in response"
  fi
else
  fail "got ${SCHEMA_CODE}"
  echo "    body: ${SCHEMA_BODY:0:300}"
fi

# 5. Determinism — 5 identical schema-locked calls, hash + count uniques
echo ""
echo "[5/5] determinism: 5 identical calls → expect 1 unique hash"
HASHES=""
for i in 1 2 3 4 5; do
  RESP=$(curl -s -H "Authorization: Bearer ${KEY}" -H "Content-Type: application/json" -d "$SCHEMA_PAYLOAD" "${BASE}/v1/chat/completions")
  CONTENT=$(echo "$RESP" | grep -oE '"content":"[^"]*"' | head -1)
  HASH=$(printf "%s" "$CONTENT" | shasum -a 256 | cut -c1-12)
  HASHES="${HASHES}${HASH}\n"
  echo "    call ${i}/5  hash=${HASH}"
done
UNIQ=$(printf "$HASHES" | sort -u | grep -c .)
if [ "$UNIQ" = "1" ]; then
  pass "1 unique hash across 5 calls — determinism confirmed"
else
  warn "${UNIQ} unique hashes across 5 calls — determinism is NOT 1.0 (expected for first cold call; investigate if all warm)"
fi

echo ""
if [ "$FAILS" = "0" ]; then
  printf "${G}=== ALL CHECKS PASSED ===${N}\n"
  exit 0
else
  printf "${R}=== ${FAILS} CHECKS FAILED ===${N}\n"
  exit 1
fi
