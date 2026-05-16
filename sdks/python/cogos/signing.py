"""Crypto helpers for the cogos client.

Three primitives live here:

  1. :func:`verify_hmac` — verify the ``X-Cogos-Signature`` header against
     the raw response body using a shared ``hmac_secret``. Mirrors
     ``src/crypto-sign.js`` (HMAC-SHA256 over the exact body bytes, lower-hex).

  2. :class:`Ed25519Signer` — produce the ``Authorization: CogOS-Ed25519
     keyId=...,sig=...,ts=...`` header. Signed bytes are
     ``METHOD\\npath\\nts\\nsha256_hex(body)`` per ``src/auth.js``.

  3. :func:`verify_attestation` — verify the ``X-Cogos-Attestation`` token
     against the server's Ed25519 public PEM (fetched from
     ``/attestation.pub``). Mirrors ``src/attestation.js``: token shape
     ``payload_b64url . signature_b64url`` with canonical fixed-field-order
     JSON inside. Also re-derives ``resp_hash = sha256(body_bytes)`` and
     refuses to accept a token whose ``resp_hash`` does not match — that
     bind is what makes the receipt actually witness this response and
     not just "some response from this build."
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Empty-body sha256 hex digest. The server uses this constant when the
# request body is empty so the signed bytes always have the same shape.
_EMPTY_BODY_SHA256 = hashlib.sha256(b"").hexdigest()


def _b64url_decode(s: str) -> bytes:
    """Decode RFC 7515 base64url (no padding)."""
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad))


def _sha256_hex(buf: bytes) -> str:
    return hashlib.sha256(buf).hexdigest()


# ---------------------------------------------------------------------------
# HMAC response signature
# ---------------------------------------------------------------------------

def verify_hmac(hmac_secret: str, body_bytes: bytes, signature_hex: str) -> bool:
    """Constant-time verify ``X-Cogos-Signature`` against the response body.

    :param hmac_secret: shared HMAC secret issued alongside the API key.
    :param body_bytes: the **exact** raw response body bytes the wire delivered.
        Do **not** re-serialize parsed JSON — whitespace and key order changes
        will break the comparison.
    :param signature_hex: contents of the ``X-Cogos-Signature`` header
        (lowercase hex).
    :returns: True iff the recomputed HMAC matches.
    """
    if not hmac_secret or not signature_hex:
        return False
    if isinstance(hmac_secret, str):
        secret_bytes = hmac_secret.encode("utf-8")
    else:
        secret_bytes = hmac_secret
    expected = _hmac.new(secret_bytes, body_bytes, hashlib.sha256).hexdigest()
    if len(expected) != len(signature_hex):
        return False
    return _hmac.compare_digest(expected, signature_hex)


# ---------------------------------------------------------------------------
# Ed25519 request signing (Authorization: CogOS-Ed25519 ...)
# ---------------------------------------------------------------------------

class Ed25519Signer:
    """Sign requests under the ``CogOS-Ed25519`` Authorization scheme.

    Construct one of these from the ``private_pem`` you received once at
    issuance time (``POST /admin/keys`` with ``scheme="ed25519"``) and pass
    it to :class:`cogos.Client` as ``ed25519_signer=`` — every call will be
    signed instead of bearer-authenticated. Keep ``ed25519_key_id`` on the
    Client too so the header carries the right ``keyId=`` field.

    Wire format::

        Authorization: CogOS-Ed25519 keyId=<id>,sig=<base64>,ts=<unix_ms>

    Signed bytes (newline-separated, no trailing newline)::

        <METHOD>\\n<path-including-query>\\n<ts>\\n<sha256_hex(body)>

    Notes:
      * ``METHOD`` is uppercased automatically.
      * ``path`` MUST include the query string (the server reads
        ``req.originalUrl`` which preserves it).
      * Replay window on the server is ±5 minutes around the ``ts`` you sent.
      * The signature is raw Ed25519 (no SHA-pre-hash), standard base64
        (not URL-safe), no padding stripping — matches Node's
        ``crypto.sign(null, ...).toString('base64')``.
    """

    def __init__(self, private_pem: str | bytes, key_id: Optional[str] = None) -> None:
        if isinstance(private_pem, str):
            private_pem = private_pem.encode("utf-8")
        key = serialization.load_pem_private_key(private_pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(
                f"Ed25519Signer: expected Ed25519 private key, got {type(key).__name__}"
            )
        self._key = key
        #: The ``ed25519_key_id`` you received at issuance, e.g. ``kid-abc...``.
        #: If unset, :meth:`sign_request` returns the param-suffix form
        #: ``sig=...,ts=...`` and the caller is responsible for adding
        #: ``CogOS-Ed25519 keyId=<id>,`` themselves.
        self.key_id = key_id

    def sign_request(
        self,
        method: str,
        path: str,
        ts: int,
        body: bytes | str | None = None,
    ) -> str:
        """Return the value to put in the ``Authorization`` header.

        :param method: HTTP method (case-insensitive; uppercased internally).
        :param path: request path INCLUDING any query string, e.g.
            ``/v1/audit?since=0``.
        :param ts: request timestamp in **unix milliseconds**. Must be
            within ±5 minutes of server wall-clock or the server returns 401.
        :param body: raw request body bytes. ``None`` and ``""`` are
            equivalent (empty body sha256 is used).
        :returns: the full header value, e.g.
            ``"CogOS-Ed25519 keyId=kid-abc,sig=...,ts=1715706000000"``.

        If a ``key_id`` was passed to ``__init__`` it is used; otherwise
        callers must wrap the return value into the header themselves.
        """
        if body is None or body == "":
            body_hex = _EMPTY_BODY_SHA256
        else:
            if isinstance(body, str):
                body = body.encode("utf-8")
            body_hex = _sha256_hex(body)
        signed_bytes = f"{method.upper()}\n{path}\n{ts}\n{body_hex}".encode("utf-8")
        sig = self._key.sign(signed_bytes)
        sig_b64 = base64.b64encode(sig).decode("ascii")
        if self.key_id is None:
            # Return only the params suffix — caller supplies keyId itself.
            return f"sig={sig_b64},ts={ts}"
        return f"CogOS-Ed25519 keyId={self.key_id},sig={sig_b64},ts={ts}"


# ---------------------------------------------------------------------------
# Attestation token verification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttestationPayload:
    """Decoded + verified payload of an ``X-Cogos-Attestation`` token.

    Field order matches the server's canonical JSON. ``chain_head`` is a
    64-hex-character row hash; persist it alongside the response if you
    need a court-defensible receipt later.
    """

    v: int
    req_hash: str
    resp_hash: str
    rev: str
    chain_head: str
    signer: str
    signer_kid: str
    ts: int


def verify_attestation(
    token: str,
    pub_pem: str | bytes,
    body_bytes: bytes,
) -> AttestationPayload:
    """Verify an ``X-Cogos-Attestation`` token end-to-end.

    Three checks:
      1. Token is well-formed (``payload_b64url.signature_b64url``).
      2. The Ed25519 signature over the **canonical payload JSON bytes**
         verifies under ``pub_pem``.
      3. The payload's ``resp_hash`` equals ``sha256(body_bytes)``.

    All three must pass. Returns the parsed :class:`AttestationPayload`
    on success.

    :raises ValueError: if any verification step fails. The Client wraps
        this in :class:`cogos.AttestationMismatch` for the caller.
    """
    if not isinstance(token, str) or "." not in token:
        raise ValueError("attestation: token must be 'payload_b64url.signature_b64url'")
    payload_b64, _, sig_b64 = token.partition(".")
    if not payload_b64 or not sig_b64:
        raise ValueError("attestation: empty payload or signature segment")

    try:
        payload_json_bytes = _b64url_decode(payload_b64)
        sig_bytes = _b64url_decode(sig_b64)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"attestation: base64url decode failed: {e}") from e

    try:
        payload: Any = json.loads(payload_json_bytes)
    except json.JSONDecodeError as e:
        raise ValueError(f"attestation: payload JSON parse failed: {e}") from e
    if not isinstance(payload, dict):
        raise ValueError("attestation: payload is not a JSON object")
    for field in ("v", "req_hash", "resp_hash", "rev", "chain_head", "signer", "signer_kid", "ts"):
        if field not in payload:
            raise ValueError(f"attestation: payload missing required field {field!r}")

    if isinstance(pub_pem, str):
        pub_pem_bytes = pub_pem.encode("utf-8")
    else:
        pub_pem_bytes = pub_pem
    pub_key = serialization.load_pem_public_key(pub_pem_bytes)
    if not isinstance(pub_key, Ed25519PublicKey):
        raise ValueError(
            f"attestation: pub_pem is not Ed25519 ({type(pub_key).__name__})"
        )
    try:
        pub_key.verify(sig_bytes, payload_json_bytes)
    except InvalidSignature as e:
        raise ValueError("attestation: Ed25519 signature did not verify") from e

    expected_resp_hash = _sha256_hex(body_bytes)
    if not _hmac.compare_digest(expected_resp_hash, str(payload["resp_hash"])):
        raise ValueError(
            "attestation: resp_hash in token does not match sha256(body) — "
            "the body was modified in transit even though the token signature "
            "verifies (attacker holds a stale receipt)"
        )

    return AttestationPayload(
        v=int(payload["v"]),
        req_hash=str(payload["req_hash"]),
        resp_hash=str(payload["resp_hash"]),
        rev=str(payload["rev"]),
        chain_head=str(payload["chain_head"]),
        signer=str(payload["signer"]),
        signer_kid=str(payload["signer_kid"]),
        ts=int(payload["ts"]),
    )
