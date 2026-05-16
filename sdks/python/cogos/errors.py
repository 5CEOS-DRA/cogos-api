"""Exception types raised by the cogos client.

Every error carries:
  * ``status`` — HTTP status code (or ``None`` for transport-layer issues
    raised before a response landed, e.g. signature/attestation failures
    on responses that *did* arrive but failed crypto verification).
  * ``error`` — the parsed ``error`` object from the server response,
    if the body was JSON-decodable. ``{"message": ..., "type": ...}`` is
    the standard shape; falls back to ``None`` otherwise.
  * ``body`` — the raw response body bytes (preserved so callers can
    forensically inspect or surface the exact bytes the server emitted).

Mirroring the OpenAI SDK split: AuthError (401), RateLimitError (429,
``rate_limit_exceeded``), DailyQuotaError (429, ``daily_quota_exceeded``),
ServerError (5xx). SignatureMismatch and AttestationMismatch are
cogos-specific and indicate the response made it across the wire but
failed cryptographic verification — treat as a transit-tampering signal.
"""

from __future__ import annotations

from typing import Optional


class CogOSError(Exception):
    """Base class for all cogos client errors."""

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        error: Optional[dict] = None,
        body: Optional[bytes] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.error = error
        self.body = body

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status={self.status!r}, message={self.message!r})"


class AuthError(CogOSError):
    """401 — invalid / revoked / expired API key, or signature scheme failed."""


class RateLimitError(CogOSError):
    """429 — generic rate limit (per-IP or per-tenant rps cap)."""


class DailyQuotaError(CogOSError):
    """429 — daily cap exhausted (distinct from monthly package quota)."""


class SignatureMismatch(CogOSError):
    """X-Cogos-Signature did not match the HMAC re-computed from the body.

    Either the body was modified in transit or the customer's ``hmac_secret``
    is wrong. Inspect ``self.body`` to see the bytes that arrived.
    """


class AttestationMismatch(CogOSError):
    """X-Cogos-Attestation failed verification.

    Raised when any of the following holds:
      * The token's Ed25519 signature did not verify under the live
        ``/attestation.pub`` (transit tamper, or stale receipt vs a
        restarted container — re-fetch ``/attestation.pub`` and re-verify
        immediately on receipt to detect drift).
      * The token's ``resp_hash`` did not match ``sha256(body_bytes)``
        the client received (body was modified in transit even though
        the token signature checks out — the attacker held an old
        token but couldn't re-sign).
      * The token was structurally malformed (bad base64url, missing
        signature, etc.).

    Set ``verify_attestation=False`` on the client to disable this check;
    that is a footgun and is documented as such.
    """


class ServerError(CogOSError):
    """5xx — upstream inference engine unreachable or other server-side failure."""
