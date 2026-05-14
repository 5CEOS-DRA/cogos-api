#!/usr/bin/env bash
# scripts/admin-ceremony/revoke-key.sh
#
# STUB. See scripts/admin-ceremony/README.md for the design intent.
#
# Final form: mark a key as revoked in the local config artifact, sign
# the resulting config diff, and emit it as a signed JSON blob the
# deploy pipeline picks up at the next revision roll. Revocation lands
# on the server when it boots the new revision and verifies the signed
# diff against the operator pubkey.

set -euo pipefail

echo "TODO: implement key revocation via cosign-signed config diff. Tracking issue: <TBD>." >&2
exit 1
