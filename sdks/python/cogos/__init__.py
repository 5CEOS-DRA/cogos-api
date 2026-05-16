"""cogos — Python client for cogos.5ceos.com.

Quick start::

    import cogos
    client = cogos.Client(
        api_key="sk-cogos-...",
        hmac_secret="hsec_...",            # optional; auto-verifies X-Cogos-Signature
    )
    resp = client.chat.completions.create(
        model="cogos-tier-b",
        messages=[{"role": "user", "content": "hi"}],
    )
    print(resp["choices"][0]["message"]["content"])
    print(resp.attestation.chain_head)     # cryptographic receipt

What this gives you that a curl does not:
  * Bearer auth wrapped (or Ed25519 signed-request flow if you opt in).
  * `X-Cogos-Signature` (HMAC) auto-verified on every response — raises
    ``cogos.SignatureMismatch`` if the body was tampered with in transit.
  * `X-Cogos-Attestation` (Ed25519 receipt) auto-verified against
    ``/attestation.pub`` and exposed as ``resp.attestation`` so you can
    archive court-defensible proof that the response came from a specific
    build at a specific chain position.
  * Standardised exceptions (``AuthError``, ``RateLimitError``,
    ``DailyQuotaError``, ``ServerError``, ...) carrying the HTTP status +
    the parsed error response.
"""

from .errors import (
    CogOSError,
    AuthError,
    RateLimitError,
    DailyQuotaError,
    SignatureMismatch,
    AttestationMismatch,
    ServerError,
)
from .signing import (
    Ed25519Signer,
    verify_hmac,
    verify_attestation,
    AttestationPayload,
)
from .audit import unseal_audit_row
from .client import Client, Response, KeyRotation

__version__ = "0.1.0"

__all__ = [
    "Client",
    "Response",
    "KeyRotation",
    "Ed25519Signer",
    "verify_hmac",
    "verify_attestation",
    "AttestationPayload",
    "unseal_audit_row",
    "CogOSError",
    "AuthError",
    "RateLimitError",
    "DailyQuotaError",
    "SignatureMismatch",
    "AttestationMismatch",
    "ServerError",
    "__version__",
]
