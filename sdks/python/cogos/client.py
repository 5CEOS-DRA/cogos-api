"""HTTP client for cogos.5ceos.com.

Design notes:

* Sync only in v0.1 — async support is a v0.2 TODO. Customers who need
  async can wrap calls in ``asyncio.to_thread``.
* Stdlib ``urllib.request`` only — no ``requests``/``httpx`` dependency.
  The single hard dependency is ``cryptography`` (already required for
  Ed25519 + X25519).
* HMAC + attestation verification both happen inside :meth:`Client._request`,
  before the response is handed back to the caller. The verified
  attestation payload is attached to the returned :class:`Response`
  object as ``.attestation``. On any verification failure the call
  raises :class:`cogos.SignatureMismatch` or
  :class:`cogos.AttestationMismatch` — the customer never has to
  remember to call ``verify_hmac()`` manually.
* The attestation public key is fetched from ``/attestation.pub`` and
  cached in-process by ``signer_kid`` so we both detect rotation (kid
  drift between consecutive responses → re-fetch and re-verify) and
  amortise the cost.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from .errors import (
    AttestationMismatch,
    AuthError,
    CogOSError,
    DailyQuotaError,
    RateLimitError,
    ServerError,
    SignatureMismatch,
)
from .signing import (
    AttestationPayload,
    Ed25519Signer,
    verify_attestation,
    verify_hmac,
)

DEFAULT_BASE_URL = "https://cogos.5ceos.com"
DEFAULT_TIMEOUT = 60.0
USER_AGENT = "cogos-python/0.1.0"


@dataclass
class Response(dict):
    """Decoded JSON body with cryptographic metadata attached.

    Subclasses ``dict`` so callers can keep using
    ``resp["choices"][0]["message"]["content"]`` (OpenAI-SDK-shaped). The
    extra attributes — ``attestation``, ``hmac_verified``, ``status``,
    ``headers``, ``raw_body`` — are added on top.
    """

    def __init__(
        self,
        decoded: dict,
        *,
        status: int,
        headers: Mapping[str, str],
        raw_body: bytes,
        hmac_verified: bool,
        attestation: Optional[AttestationPayload],
    ) -> None:
        super().__init__(decoded)
        self.status = status
        self.headers = dict(headers)
        self.raw_body = raw_body
        self.hmac_verified = hmac_verified
        self.attestation = attestation

    # __repr__ override would lose the OpenAI-shaped dict feel; intentionally
    # leave dict's __repr__ in place.


@dataclass
class KeyRotation:
    """Result of :meth:`Client.keys.rotate` — the new credentials.

    The customer must persist every field. ``api_key`` / ``private_pem`` /
    ``x25519_private_pem`` / ``hmac_secret`` are returned **once** and
    are not retrievable again. The old key remains valid until
    ``rotation_grace_until``; switch over before then.
    """

    key_id: str
    tenant_id: str
    app_id: str
    tier: str
    scheme: str  # "bearer" | "ed25519"
    issued_at: str
    expires_at: Optional[str]
    hmac_secret: Optional[str]
    rotated_from_key_id: str
    rotation_grace_until: Optional[str]
    warning: str

    # Bearer-only:
    api_key: Optional[str] = None

    # Ed25519-only:
    ed25519_key_id: Optional[str] = None
    private_pem: Optional[str] = None
    pubkey_pem: Optional[str] = None
    x25519_private_pem: Optional[str] = None
    x25519_pubkey_pem: Optional[str] = None

    @classmethod
    def from_response(cls, decoded: Mapping[str, Any]) -> "KeyRotation":
        return cls(
            key_id=str(decoded["key_id"]),
            tenant_id=str(decoded["tenant_id"]),
            app_id=str(decoded.get("app_id", "_default")),
            tier=str(decoded.get("tier", "")),
            scheme=str(decoded["scheme"]),
            issued_at=str(decoded.get("issued_at", "")),
            expires_at=decoded.get("expires_at"),
            hmac_secret=decoded.get("hmac_secret"),
            rotated_from_key_id=str(decoded.get("rotated_from_key_id", "")),
            rotation_grace_until=decoded.get("rotation_grace_until"),
            warning=str(decoded.get("warning", "")),
            api_key=decoded.get("api_key"),
            ed25519_key_id=decoded.get("ed25519_key_id"),
            private_pem=decoded.get("private_pem"),
            pubkey_pem=decoded.get("pubkey_pem"),
            x25519_private_pem=decoded.get("x25519_private_pem"),
            x25519_pubkey_pem=decoded.get("x25519_pubkey_pem"),
        )


# ---------------------------------------------------------------------------
# Namespace handles
# ---------------------------------------------------------------------------

class _ChatCompletions:
    def __init__(self, client: "Client") -> None:
        self._client = client

    def create(
        self,
        messages: list[dict],
        model: str = "cogos-tier-b",
        response_format: Optional[dict] = None,
        **kw: Any,
    ) -> Response:
        """Create a chat completion. Mirrors ``openai.chat.completions.create``.

        :param messages: list of ``{"role": "user"|"system"|"assistant",
            "content": "..."}`` dicts.
        :param model: ``"cogos-tier-b"`` (default, 3B) or ``"cogos-tier-a"`` (7B).
        :param response_format: optional ``{"type": "json_schema", ...}``
            for schema-locked output.
        :param kw: forwarded to the request body (``temperature``,
            ``max_tokens``, ``seed``, ...).
        """
        body: dict[str, Any] = {"model": model, "messages": messages}
        if response_format is not None:
            body["response_format"] = response_format
        body.update(kw)
        return self._client._request("POST", "/v1/chat/completions", body=body)


class _Chat:
    def __init__(self, client: "Client") -> None:
        self.completions = _ChatCompletions(client)


class _Models:
    def __init__(self, client: "Client") -> None:
        self._client = client

    def list(self) -> Response:
        """``GET /v1/models`` — returns ``{"object": "list", "data": [...]}``."""
        return self._client._request("GET", "/v1/models")


class _Audit:
    def __init__(self, client: "Client") -> None:
        self._client = client

    def read(
        self,
        since_ms: int = 0,
        limit: int = 100,
        app_id: Optional[str] = None,
    ) -> Response:
        """``GET /v1/audit`` — paged tenant audit slice.

        Returned :class:`Response` carries the audit-level ``chain_ok``
        and ``chain_ok_by_app`` flags inside the dict body (server-side
        verification). For independent assurance, customers can re-run
        chain verification locally — that helper is on the v0.2 roadmap.
        """
        qs = {"since": int(since_ms), "limit": int(limit)}
        if app_id is not None:
            qs["app_id"] = app_id
        path = "/v1/audit?" + urllib.parse.urlencode(qs)
        return self._client._request("GET", path)


class _Keys:
    def __init__(self, client: "Client") -> None:
        self._client = client

    def rotate(self) -> KeyRotation:
        """``POST /v1/keys/rotate`` — rotate the current key in place.

        Returns the new credentials as a :class:`KeyRotation` object the
        customer should persist immediately. The old key remains valid
        until ``rotation_grace_until``.
        """
        resp = self._client._request("POST", "/v1/keys/rotate", body={})
        return KeyRotation.from_response(resp)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class Client:
    """Synchronous client for cogos.5ceos.com.

    :param api_key: bearer API key (``sk-cogos-...``). Mutually exclusive
        with ``ed25519_signer``.
    :param hmac_secret: HMAC secret shown alongside the API key at
        issuance. When present, **every response is auto-verified** and
        :class:`cogos.SignatureMismatch` is raised on mismatch. Pass
        ``None`` (the default) to opt out — the responsibility is on you.
    :param base_url: defaults to ``https://cogos.5ceos.com``.
    :param ed25519_signer: pre-built :class:`cogos.Ed25519Signer` with its
        ``key_id`` set. When provided, every request is signed under the
        ``CogOS-Ed25519`` scheme instead of bearer-authenticated.
    :param verify_attestation: when True (default) every response's
        ``X-Cogos-Attestation`` token is verified against
        ``{base_url}/attestation.pub`` and exposed as
        ``response.attestation``. Set False to skip (e.g. for offline
        replay analysis); :class:`AttestationMismatch` is silenced and
        ``response.attestation`` will be ``None``.
    :param timeout: request timeout in seconds (default 60).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        hmac_secret: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        *,
        ed25519_signer: Optional[Ed25519Signer] = None,
        verify_attestation: bool = True,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if api_key is None and ed25519_signer is None:
            raise ValueError(
                "Client: pass api_key (bearer) or ed25519_signer (signed-request scheme)"
            )
        if api_key is not None and ed25519_signer is not None:
            raise ValueError(
                "Client: api_key and ed25519_signer are mutually exclusive — "
                "pick one auth scheme"
            )
        if ed25519_signer is not None and ed25519_signer.key_id is None:
            raise ValueError(
                "Client: ed25519_signer must have a key_id set "
                "(pass key_id=... to Ed25519Signer)"
            )
        self.api_key = api_key
        self.hmac_secret = hmac_secret
        self.base_url = base_url.rstrip("/")
        self.ed25519_signer = ed25519_signer
        self.verify_attestation = verify_attestation
        self.timeout = float(timeout)

        # Namespace handles (OpenAI-SDK-shaped):
        self.chat = _Chat(self)
        self.models = _Models(self)
        self.audit = _Audit(self)
        self.keys = _Keys(self)

        # Attestation-pubkey cache, keyed by signer_kid. Lets us detect
        # key rotation across consecutive responses (kid drift → re-fetch).
        self._attestation_pubkey_cache: dict[str, bytes] = {}
        # Last-resort: if we don't yet know the kid (cold start) we fetch
        # unconditionally and store under whatever kid the first response
        # advertises.

    # -----------------------------------------------------------------------
    # Internal HTTP plumbing
    # -----------------------------------------------------------------------

    def _build_auth_header(self, method: str, path: str, body: bytes) -> str:
        if self.ed25519_signer is not None:
            ts = int(time.time() * 1000)
            return self.ed25519_signer.sign_request(method, path, ts, body)
        assert self.api_key is not None
        return f"Bearer {self.api_key}"

    def _fetch_attestation_pubkey(self) -> bytes:
        """Fetch ``/attestation.pub``. No auth required (it's public)."""
        url = f"{self.base_url}/attestation.pub"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read()
        except urllib.error.URLError as e:
            raise CogOSError(
                f"failed to fetch attestation pubkey from {url}: {e}"
            ) from e

    def _resolve_attestation_pubkey(self, kid: Optional[str]) -> bytes:
        """Return the public PEM bytes for a given kid, fetching + caching."""
        if kid is not None and kid in self._attestation_pubkey_cache:
            return self._attestation_pubkey_cache[kid]
        pem = self._fetch_attestation_pubkey()
        # We don't know the kid until we verify; cache opportunistically
        # under any kid we're told about. If we just fetched and the
        # token's kid IS present in the cache (race against another
        # caller), we still verify against the freshly-fetched pem.
        if kid is not None:
            self._attestation_pubkey_cache[kid] = pem
        return pem

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
    ) -> Response:
        """Issue one HTTP request, verify response signatures, return :class:`Response`."""
        if body is None:
            body_bytes = b""
        else:
            body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")

        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": self._build_auth_header(method, path, body_bytes),
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        }
        if body_bytes:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            url,
            method=method.upper(),
            data=body_bytes if body_bytes else None,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw_body = resp.read()
                status = resp.status
                resp_headers = dict(resp.headers.items())
        except urllib.error.HTTPError as e:
            try:
                raw_body = e.read() or b""
                status = e.code
                resp_headers = dict(e.headers.items()) if e.headers else {}
            finally:
                # Avoid PytestUnraisableExceptionWarning from the fp the
                # HTTPError holds — close it explicitly now that we're done.
                try:
                    e.close()
                except Exception:  # noqa: BLE001
                    pass
            self._raise_for_error_response(status, raw_body, resp_headers)
            # _raise_for_error_response always raises on non-2xx; sanity:
            raise  # pragma: no cover

        # HMAC verify (if customer supplied a secret). Verification BEFORE
        # JSON parse so we're checking the exact bytes the wire delivered.
        hmac_verified = False
        if self.hmac_secret is not None:
            sig_hex = _header_get(resp_headers, "X-Cogos-Signature")
            if not sig_hex:
                raise SignatureMismatch(
                    "hmac_secret was provided but response has no X-Cogos-Signature header",
                    status=status,
                    body=raw_body,
                )
            if not verify_hmac(self.hmac_secret, raw_body, sig_hex):
                raise SignatureMismatch(
                    "X-Cogos-Signature did not match HMAC-SHA256(hmac_secret, body)",
                    status=status,
                    body=raw_body,
                )
            hmac_verified = True

        # Attestation verify (always on unless verify_attestation=False).
        attestation_payload: Optional[AttestationPayload] = None
        if self.verify_attestation:
            token = _header_get(resp_headers, "X-Cogos-Attestation")
            if token:
                # First attempt with cached pubkey for the kid the token
                # advertises (we peek without verifying). On any failure
                # — bad sig, kid drift — re-fetch /attestation.pub once
                # and retry. Two-stage so a cached pubkey rotation hit
                # doesn't hard-fail when the customer's process has been
                # alive longer than the server's.
                try:
                    payload_kid = _peek_kid(token)
                except Exception:
                    payload_kid = None
                pub_pem = self._resolve_attestation_pubkey(payload_kid)
                try:
                    attestation_payload = verify_attestation(token, pub_pem, raw_body)
                except ValueError:
                    # Force a re-fetch and try once more — handles container
                    # restart / key rotation since we last cached.
                    pem = self._fetch_attestation_pubkey()
                    try:
                        attestation_payload = verify_attestation(token, pem, raw_body)
                        if payload_kid is not None:
                            self._attestation_pubkey_cache[payload_kid] = pem
                    except ValueError as e:
                        raise AttestationMismatch(
                            f"X-Cogos-Attestation verification failed: {e}",
                            status=status,
                            body=raw_body,
                        ) from e

        # Parse the body. We do this AFTER signature checks so a malformed
        # body that happened to pass crypto checks still raises a clean
        # ServerError below.
        try:
            decoded = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ServerError(
                f"response body was not valid JSON: {e}",
                status=status,
                body=raw_body,
            ) from e
        if not isinstance(decoded, dict):
            raise ServerError(
                f"response body was JSON but not an object: {type(decoded).__name__}",
                status=status,
                body=raw_body,
            )

        return Response(
            decoded,
            status=status,
            headers=resp_headers,
            raw_body=raw_body,
            hmac_verified=hmac_verified,
            attestation=attestation_payload,
        )

    def _raise_for_error_response(
        self,
        status: int,
        raw_body: bytes,
        headers: Mapping[str, str],
    ) -> None:
        """Map an HTTP error response onto a typed exception."""
        try:
            decoded = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:  # noqa: BLE001
            decoded = {}
        err = decoded.get("error") if isinstance(decoded, dict) else None
        err_dict = err if isinstance(err, dict) else None
        err_type = err_dict.get("type") if err_dict else None
        msg = (
            err_dict.get("message") if err_dict else None
        ) or f"HTTP {status}"
        if status == 401:
            raise AuthError(msg, status=status, error=err_dict, body=raw_body)
        if status == 429:
            if err_type == "daily_quota_exceeded":
                raise DailyQuotaError(msg, status=status, error=err_dict, body=raw_body)
            raise RateLimitError(msg, status=status, error=err_dict, body=raw_body)
        if 500 <= status < 600:
            raise ServerError(msg, status=status, error=err_dict, body=raw_body)
        # 400 / 402 / 403 / 404 / ... — generic CogOSError with the parsed body.
        raise CogOSError(msg, status=status, error=err_dict, body=raw_body)


# ---------------------------------------------------------------------------
# Header / token helpers (private; tested via Client behaviour)
# ---------------------------------------------------------------------------

def _header_get(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup. HTTP headers are case-insensitive but
    urllib gives us a plain dict, so iterate."""
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None


def _peek_kid(token: str) -> Optional[str]:
    """Decode the payload of an attestation token WITHOUT verifying, to read
    the ``signer_kid`` for cache lookup. Verification still happens after."""
    if "." not in token:
        return None
    payload_b64 = token.split(".", 1)[0]
    pad = (-len(payload_b64)) % 4
    import base64

    try:
        raw = base64.urlsafe_b64decode(payload_b64 + ("=" * pad))
        decoded = json.loads(raw)
        if isinstance(decoded, dict) and isinstance(decoded.get("signer_kid"), str):
            return decoded["signer_kid"]
    except Exception:  # noqa: BLE001
        return None
    return None
