"""Customer-side decryption of sealed audit rows.

When a key was issued under ``scheme="ed25519"`` the customer also
received an X25519 private PEM (``x25519_private_pem``). Every audit row
the gateway writes for that customer has its content-sensitive fields
(``request_id``, ``prompt_fingerprint``, ``schema_name``) encrypted under
that key — the gateway holds only the X25519 *public* key, and the
ephemeral private key used per row is dropped immediately. The server
**cannot** decrypt these rows; a full breach yields ciphertext only.

This module mirrors ``src/sealed-audit.js`` on the server::

    alg          = x25519-hkdf-aes-256-gcm
    KDF          = HKDF-SHA256, salt = empty, info = "cogos/seal/v1"
    AEAD         = AES-256-GCM, 12-byte nonce, 16-byte tag
    AAD          = "<tenant_id>|<app_id>|<ts>" (UTF-8)
    plaintext    = canonical JSON of {request_id, prompt_fingerprint, schema_name}
                   (fields present only if non-null at write time)

The customer is the only party who can call :func:`unseal_audit_row`.
**The server must never** — this is part of the threat model.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Mapping

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_HKDF_INFO = b"cogos/seal/v1"
_HKDF_LEN = 32  # AES-256
_ENVELOPE_VERSION = 1
_ENVELOPE_ALG = "x25519-hkdf-aes-256-gcm"


def _build_aad(tenant_id: str, app_id: str, ts: str) -> bytes:
    if not tenant_id:
        raise ValueError("unseal_audit_row: row.tenant_id required")
    if not app_id:
        raise ValueError("unseal_audit_row: row.app_id required")
    if not ts:
        raise ValueError("unseal_audit_row: row.ts required")
    return f"{tenant_id}|{app_id}|{ts}".encode("utf-8")


def _derive_content_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_HKDF_LEN,
        salt=None,           # cryptography treats None as empty salt
        info=_HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def unseal_audit_row(
    row: Mapping[str, Any],
    x25519_private_pem: str | bytes,
) -> dict:
    """Decrypt a sealed audit row's content fields.

    :param row: a row dict as returned by ``GET /v1/audit`` (one element
        of ``response.rows``). Must include ``tenant_id``, ``app_id``,
        ``ts``, and a ``sealed_content`` envelope object.
    :param x25519_private_pem: PEM bytes of the customer's X25519 private
        key, returned **once** by ``POST /admin/keys`` as
        ``x25519_private_pem``.
    :returns: the decoded content payload as a dict, e.g.
        ``{"request_id": "chatcmpl-...", "prompt_fingerprint": "sha256:...", ...}``.
    :raises ValueError: if the row is not sealed, the envelope version /
        algorithm is unknown, or the AEAD tag check fails (tamper or
        wrong key).

    Standalone — does **not** live on :class:`cogos.Client` because
    unsealing is a customer-side-only operation (we deliberately keep
    the private key out of the same code path as the network client).
    """
    if not isinstance(row, Mapping):
        raise ValueError("unseal_audit_row: row must be a mapping")
    if not row.get("sealed"):
        raise ValueError("unseal_audit_row: row.sealed is false (no envelope present)")
    envelope = row.get("sealed_content")
    if not isinstance(envelope, Mapping):
        raise ValueError("unseal_audit_row: row.sealed_content is missing or not an object")

    if envelope.get("v") != _ENVELOPE_VERSION:
        raise ValueError(
            f"unseal_audit_row: unknown envelope version {envelope.get('v')!r}"
        )
    if envelope.get("alg") != _ENVELOPE_ALG:
        raise ValueError(
            f"unseal_audit_row: unknown envelope alg {envelope.get('alg')!r}"
        )

    if isinstance(x25519_private_pem, str):
        x25519_private_pem = x25519_private_pem.encode("utf-8")
    priv = serialization.load_pem_private_key(x25519_private_pem, password=None)
    if not isinstance(priv, X25519PrivateKey):
        raise ValueError(
            f"unseal_audit_row: expected X25519 private key, got {type(priv).__name__}"
        )

    eph_pub_raw = base64.b64decode(envelope["ephemeral_pub_b64"])
    if len(eph_pub_raw) != 32:
        raise ValueError("unseal_audit_row: ephemeral_pub_b64 must decode to 32 bytes")
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_raw)

    shared = priv.exchange(eph_pub)
    aes_key = _derive_content_key(shared)

    nonce = base64.b64decode(envelope["nonce_b64"])
    ct = base64.b64decode(envelope["ciphertext_b64"])
    tag = base64.b64decode(envelope["tag_b64"])

    aad = _build_aad(
        tenant_id=str(row["tenant_id"]),
        app_id=str(row["app_id"]),
        ts=str(row["ts"]),
    )

    # cryptography's AESGCM takes (ciphertext || tag) as one input.
    aesgcm = AESGCM(aes_key)
    try:
        pt = aesgcm.decrypt(nonce, ct + tag, aad)
    except Exception as e:  # InvalidTag is the typical case
        raise ValueError(
            "unseal_audit_row: AEAD decryption failed (wrong key, "
            "tampered envelope, or AAD mismatch)"
        ) from e

    try:
        decoded = json.loads(pt.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"unseal_audit_row: plaintext is not valid JSON: {e}") from e
    if not isinstance(decoded, dict):
        raise ValueError("unseal_audit_row: plaintext is not a JSON object")
    return decoded
