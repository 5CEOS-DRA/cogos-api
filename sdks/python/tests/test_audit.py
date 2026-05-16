"""Tests for ``cogos.unseal_audit_row``.

Mirrors the matrix in ``tests/sealed-audit.test.js`` on the server, plus a
byte-exact round-trip against a fixture sealed by the server.
"""

from __future__ import annotations

import base64
import copy

import pytest

from cogos import unseal_audit_row


# ---------------------------------------------------------------------------
# 1. Round-trip against the server-sealed fixture
# ---------------------------------------------------------------------------

def test_unseal_round_trip_against_server_fixture(fixtures):
    s = fixtures["sealed_audit"]
    plain = unseal_audit_row(s["row"], s["x25519_private_pem"])
    expected = {
        "request_id": "chatcmpl-abc123",
        "prompt_fingerprint": "sha256:deadbeefdeadbeef",
        "schema_name": "invoice_v1",
    }
    assert plain == expected


# ---------------------------------------------------------------------------
# 2. Wrong privkey can't decrypt
# ---------------------------------------------------------------------------

def test_unseal_rejects_wrong_private_key(fixtures):
    s = fixtures["sealed_audit"]
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    other = X25519PrivateKey.generate()
    other_pem = other.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="decryption failed"):
        unseal_audit_row(s["row"], other_pem)


# ---------------------------------------------------------------------------
# 3. Tampered ciphertext / nonce / tag → tag check fails
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["ciphertext_b64", "nonce_b64", "tag_b64"])
def test_unseal_rejects_tampered_envelope_field(fixtures, field):
    s = fixtures["sealed_audit"]
    row = copy.deepcopy(s["row"])
    raw = bytearray(base64.b64decode(row["sealed_content"][field]))
    raw[0] ^= 0x01
    row["sealed_content"][field] = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(ValueError, match="decryption failed"):
        unseal_audit_row(row, s["x25519_private_pem"])


# ---------------------------------------------------------------------------
# 4. AAD binding — tenant_id / app_id / ts mismatch all fail
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "field, new_value",
    [
        ("tenant_id", "bob"),
        ("app_id", "different-app"),
        ("ts", "2099-01-01T00:00:00.000Z"),
    ],
)
def test_unseal_rejects_aad_mismatch(fixtures, field, new_value):
    s = fixtures["sealed_audit"]
    row = copy.deepcopy(s["row"])
    row[field] = new_value
    with pytest.raises(ValueError, match="decryption failed"):
        unseal_audit_row(row, s["x25519_private_pem"])


# ---------------------------------------------------------------------------
# 5. Envelope versioning — unknown v / unknown alg
# ---------------------------------------------------------------------------

def test_unseal_rejects_unknown_envelope_version(fixtures):
    s = fixtures["sealed_audit"]
    row = copy.deepcopy(s["row"])
    row["sealed_content"]["v"] = 999
    with pytest.raises(ValueError, match="envelope version"):
        unseal_audit_row(row, s["x25519_private_pem"])


def test_unseal_rejects_unknown_envelope_alg(fixtures):
    s = fixtures["sealed_audit"]
    row = copy.deepcopy(s["row"])
    row["sealed_content"]["alg"] = "rsa-pretty-please"
    with pytest.raises(ValueError, match="envelope alg"):
        unseal_audit_row(row, s["x25519_private_pem"])


# ---------------------------------------------------------------------------
# 6. Unsealed rows refuse
# ---------------------------------------------------------------------------

def test_unseal_refuses_unsealed_row(fixtures):
    s = fixtures["sealed_audit"]
    row = copy.deepcopy(s["row"])
    row["sealed"] = False
    with pytest.raises(ValueError, match="sealed is false"):
        unseal_audit_row(row, s["x25519_private_pem"])


def test_unseal_refuses_missing_envelope(fixtures):
    s = fixtures["sealed_audit"]
    row = copy.deepcopy(s["row"])
    del row["sealed_content"]
    with pytest.raises(ValueError, match="sealed_content"):
        unseal_audit_row(row, s["x25519_private_pem"])


# ---------------------------------------------------------------------------
# 7. Bad pubkey curves rejected
# ---------------------------------------------------------------------------

def test_unseal_rejects_ed25519_private_key(fixtures):
    s = fixtures["sealed_audit"]
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    ed = Ed25519PrivateKey.generate()
    ed_pem = ed.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="X25519 private key"):
        unseal_audit_row(s["row"], ed_pem)
