"""HMAC verify + Ed25519 request sign + attestation token verify.

Every assertion is against a byte-exact fixture produced by the **server's
own** crypto primitives (see ``generate_fixtures.js``). If these tests
pass, the Python implementation is wire-compatible with the live API.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from cogos.signing import (
    Ed25519Signer,
    AttestationPayload,
    verify_attestation,
    verify_hmac,
)


# ---------------------------------------------------------------------------
# HMAC
# ---------------------------------------------------------------------------

def test_hmac_matches_server_fixture(fixtures):
    h = fixtures["hmac"]
    body = h["body_utf8"].encode("utf-8")
    assert verify_hmac(h["hmac_secret"], body, h["expected_signature_hex"]) is True


def test_hmac_rejects_tampered_body(fixtures):
    h = fixtures["hmac"]
    tampered = h["body_utf8"].encode("utf-8") + b" "
    assert verify_hmac(h["hmac_secret"], tampered, h["expected_signature_hex"]) is False


def test_hmac_rejects_tampered_signature(fixtures):
    h = fixtures["hmac"]
    body = h["body_utf8"].encode("utf-8")
    sig = h["expected_signature_hex"]
    bad = ("0" if sig[0] != "0" else "1") + sig[1:]
    assert verify_hmac(h["hmac_secret"], body, bad) is False


def test_hmac_rejects_wrong_length_signature(fixtures):
    h = fixtures["hmac"]
    body = h["body_utf8"].encode("utf-8")
    assert verify_hmac(h["hmac_secret"], body, "deadbeef") is False


def test_hmac_rejects_empty_inputs():
    assert verify_hmac("", b"body", "abc") is False
    assert verify_hmac("secret", b"body", "") is False


# ---------------------------------------------------------------------------
# Ed25519 request signing
# ---------------------------------------------------------------------------

def test_ed25519_sign_request_matches_server_fixture(fixtures):
    e = fixtures["ed25519_request"]
    signer = Ed25519Signer(e["private_pem"], key_id="kid-test")
    header = signer.sign_request(
        method=e["method"],
        path=e["path"],
        ts=e["ts"],
        body=e["body_utf8"],
    )
    # Header should be the full CogOS-Ed25519 line for "kid-test".
    assert header == f"CogOS-Ed25519 {e['expected_header_suffix']}"


def test_ed25519_sign_without_key_id_returns_suffix(fixtures):
    e = fixtures["ed25519_request"]
    signer = Ed25519Signer(e["private_pem"])  # no key_id
    header = signer.sign_request(e["method"], e["path"], e["ts"], e["body_utf8"])
    # Should be the param-suffix form.
    assert header == f"sig={e['expected_signature_base64']},ts={e['ts']}"
    assert not header.startswith("CogOS-Ed25519")


def test_ed25519_sign_empty_body_uses_empty_sha256(fixtures):
    """Server treats body=None and body=b'' identically — empty-body sha256."""
    e = fixtures["ed25519_request"]
    signer = Ed25519Signer(e["private_pem"], key_id="kid-test")
    a = signer.sign_request("GET", "/v1/models", 1715706000000, None)
    b = signer.sign_request("GET", "/v1/models", 1715706000000, "")
    c = signer.sign_request("GET", "/v1/models", 1715706000000, b"")
    assert a == b == c


def test_ed25519_sign_method_is_uppercased(fixtures):
    e = fixtures["ed25519_request"]
    signer = Ed25519Signer(e["private_pem"], key_id="kid-test")
    lower = signer.sign_request("post", e["path"], e["ts"], e["body_utf8"])
    upper = signer.sign_request("POST", e["path"], e["ts"], e["body_utf8"])
    assert lower == upper


def test_ed25519_signer_rejects_non_ed25519_pem():
    # An RSA private key should not be accepted as an Ed25519 signer.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="Ed25519"):
        Ed25519Signer(pem)


# ---------------------------------------------------------------------------
# Attestation token verification
# ---------------------------------------------------------------------------

def test_verify_attestation_against_server_fixture(fixtures):
    a = fixtures["attestation"]
    body = a["response_body_utf8"].encode("utf-8")
    payload = verify_attestation(a["token"], a["public_pem"], body)
    assert isinstance(payload, AttestationPayload)
    assert payload.v == 1
    assert payload.rev == a["revision"]
    assert payload.chain_head == a["chain_head"]
    assert payload.ts == a["ts"]
    assert payload.signer == "cogos-api"
    # resp_hash must match sha256(body) — that's the bind we enforce.
    assert payload.resp_hash == hashlib.sha256(body).hexdigest()
    # signer_kid is sha256(pubkey_pem)[:16]
    expected_kid = hashlib.sha256(a["public_pem"].encode("utf-8")).hexdigest()[:16]
    assert payload.signer_kid == expected_kid


def test_verify_attestation_rejects_body_tamper(fixtures):
    a = fixtures["attestation"]
    tampered = (a["response_body_utf8"] + " ").encode("utf-8")
    with pytest.raises(ValueError, match="resp_hash"):
        verify_attestation(a["token"], a["public_pem"], tampered)


def test_verify_attestation_rejects_signature_tamper(fixtures):
    a = fixtures["attestation"]
    body = a["response_body_utf8"].encode("utf-8")
    token = a["token"]
    payload_b64, _, sig_b64 = token.partition(".")
    # Flip a byte in the middle of the signature segment.
    mid = len(sig_b64) // 2
    swap = "A" if sig_b64[mid] != "A" else "B"
    tampered = f"{payload_b64}.{sig_b64[:mid]}{swap}{sig_b64[mid + 1:]}"
    with pytest.raises(ValueError):
        verify_attestation(tampered, a["public_pem"], body)


def test_verify_attestation_rejects_payload_tamper(fixtures):
    a = fixtures["attestation"]
    body = a["response_body_utf8"].encode("utf-8")
    token = a["token"]
    payload_b64, _, sig_b64 = token.partition(".")
    # Flip a byte in the payload. The Ed25519 sig will no longer verify.
    pad = (-len(payload_b64)) % 4
    decoded = base64.urlsafe_b64decode(payload_b64 + ("=" * pad))
    flipped = bytes([decoded[0] ^ 0x01]) + decoded[1:]
    new_payload = base64.urlsafe_b64encode(flipped).rstrip(b"=").decode("ascii")
    tampered = f"{new_payload}.{sig_b64}"
    with pytest.raises(ValueError):
        verify_attestation(tampered, a["public_pem"], body)


def test_verify_attestation_rejects_wrong_pubkey(fixtures):
    a = fixtures["attestation"]
    body = a["response_body_utf8"].encode("utf-8")
    # Generate a fresh ed25519 keypair the server never knew about.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    other_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(ValueError):
        verify_attestation(a["token"], other_pem, body)


def test_verify_attestation_rejects_malformed_token(fixtures):
    a = fixtures["attestation"]
    body = a["response_body_utf8"].encode("utf-8")
    with pytest.raises(ValueError, match="payload_b64url"):
        verify_attestation("not_a_token", a["public_pem"], body)
    with pytest.raises(ValueError):
        verify_attestation(".justsig", a["public_pem"], body)
    with pytest.raises(ValueError):
        verify_attestation("justpayload.", a["public_pem"], body)
