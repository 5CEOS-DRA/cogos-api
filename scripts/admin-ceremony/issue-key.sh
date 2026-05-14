#!/usr/bin/env bash
# scripts/admin-ceremony/issue-key.sh
#
# STUB. See scripts/admin-ceremony/README.md for the design intent.
#
# Final form: generate an API key locally, sign the resulting config diff
# with the operator's cosign / HSM / YubiKey, and emit a signed JSON blob
# the deploy pipeline picks up at the next revision roll. No live HTTP
# admin endpoint is involved.

set -euo pipefail

echo "TODO: implement key issuance via cosign-signed config diff. Tracking issue: <TBD>." >&2
exit 1
