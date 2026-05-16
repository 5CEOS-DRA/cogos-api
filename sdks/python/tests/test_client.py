"""Mocked-HTTP integration tests for :class:`cogos.Client`.

Approach: monkeypatch ``urllib.request.urlopen`` inside ``cogos.client`` to
return synthesised responses. We construct the responses on the fly using
the same crypto primitives the server uses — HMAC-SHA256 over the exact
body bytes, and a server-side-signed Ed25519 attestation token whose
public PEM is what the patched ``/attestation.pub`` fetch returns.

Coverage:
  * ``chat.completions.create`` — happy path; HMAC + attestation both verify.
  * ``models.list`` — same.
  * ``audit.read`` — chain_ok surfaces on the response dict.
  * ``keys.rotate`` — KeyRotation object populated for both bearer +
    ed25519 schemes.
  * Error mapping: 401 → AuthError, 429+rate_limit_exceeded →
    RateLimitError, 429+daily_quota_exceeded → DailyQuotaError, 5xx →
    ServerError.
  * Crypto failure: tampered body → SignatureMismatch; tampered
    attestation token → AttestationMismatch.
  * ``verify_attestation=False`` opt-out silences attestation checks.
  * Ed25519-signer client signs requests (no bearer header issued).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import urllib.error
from contextlib import contextmanager
from typing import Any, Mapping, Optional
from unittest.mock import patch

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import cogos
from cogos import client as client_module


# ---------------------------------------------------------------------------
# Fake-server scaffolding
# ---------------------------------------------------------------------------

class _HeaderBag:
    """Quacks like the headers object that urllib gives back."""

    def __init__(self, h: Mapping[str, str]) -> None:
        self._h = list(h.items())

    def items(self):
        return list(self._h)

    def __iter__(self):
        return iter(self._h)


class _FakeResp:
    """Minimal duck-type for what urlopen() returns."""

    def __init__(self, status: int, body: bytes, headers: Mapping[str, str]) -> None:
        self.status = status
        self._body = body
        self.headers = _HeaderBag(headers)

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class _FakeHTTPError(urllib.error.HTTPError):
    """HTTPError carrying a real body + headers, the way urlopen raises 4xx/5xx."""

    def __init__(self, url: str, code: int, msg: str, body: bytes, headers: Mapping[str, str]) -> None:
        # We must call HTTPError init with hdrs that quacks like email.Message.
        class _Hdrs:
            def __init__(self, h):
                self._h = list(h.items())

            def items(self):
                return self._h

            def __iter__(self):
                return iter(self._h)

        super().__init__(url, code, msg, _Hdrs(headers), fp=io.BytesIO(body))


@pytest.fixture
def server_keys():
    """Ed25519 attestation keypair for the fake server."""
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    priv_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = hashlib.sha256(pub_pem).hexdigest()[:16]
    return {"sk": sk, "pub_pem": pub_pem, "kid": kid}


def _sign_attestation(
    sk: Ed25519PrivateKey,
    kid: str,
    method: str,
    path: str,
    ts: int,
    req_body: bytes,
    resp_body: bytes,
    chain_head: str = "0" * 64,
    rev: str = "test-rev",
) -> str:
    body_hash = hashlib.sha256(req_body).hexdigest()
    canonical = f"{method}\n{path}\n{ts}\n{body_hash}".encode("utf-8")
    req_hash = hashlib.sha256(canonical).hexdigest()
    resp_hash = hashlib.sha256(resp_body).hexdigest()
    # MUST match the server's fixed-key-order JSON layout exactly.
    payload_obj = {
        "v": 1,
        "req_hash": req_hash,
        "resp_hash": resp_hash,
        "rev": rev,
        "chain_head": chain_head,
        "signer": "cogos-api",
        "signer_kid": kid,
        "ts": ts,
    }
    payload_json = json.dumps(payload_obj, separators=(",", ":"))
    sig = sk.sign(payload_json.encode("utf-8"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).rstrip(b"=").decode("ascii")
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    return f"{payload_b64}.{sig_b64}"


def _hmac_hex(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


@contextmanager
def _patched_urlopen(
    response_factory,
    pubkey_pem: bytes,
    record_requests: Optional[list] = None,
):
    """Patch urlopen inside cogos.client to dispatch on URL.

    response_factory(method, path, body_bytes) -> (status, resp_body, headers)
    """

    def _urlopen(req, *args, **kwargs):
        method = req.get_method()
        url = req.full_url
        # Strip base
        path = url.split("//", 1)[1].split("/", 1)[1]
        path = "/" + path
        data = req.data or b""
        if record_requests is not None:
            record_requests.append({
                "method": method,
                "url": url,
                "headers": dict(req.headers),
                "body": data,
            })
        if path == "/attestation.pub":
            return _FakeResp(200, pubkey_pem, {"Content-Type": "application/x-pem-file"})
        status, body, headers = response_factory(method, path, data)
        if status >= 400:
            raise _FakeHTTPError(url, status, "error", body, headers)
        return _FakeResp(status, body, headers)

    with patch.object(client_module.urllib.request, "urlopen", _urlopen):
        yield


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------

def test_client_requires_an_auth_scheme():
    with pytest.raises(ValueError, match="api_key.*ed25519"):
        cogos.Client()


def test_client_rejects_mutually_exclusive_auth():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    signer = cogos.Ed25519Signer(priv, key_id="kid-x")
    with pytest.raises(ValueError, match="mutually exclusive"):
        cogos.Client(api_key="sk-cogos-abc", ed25519_signer=signer)


def test_client_rejects_signer_without_key_id():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    signer = cogos.Ed25519Signer(priv)  # no key_id
    with pytest.raises(ValueError, match="key_id"):
        cogos.Client(ed25519_signer=signer)


# ---------------------------------------------------------------------------
# Happy paths — chat.completions / models / audit / keys.rotate
# ---------------------------------------------------------------------------

def test_chat_completions_happy_path_verifies_hmac_and_attestation(server_keys):
    hmac_secret = "hsec_test"
    resp_body = json.dumps({
        "id": "chatcmpl-xyz",
        "object": "chat.completion",
        "created": 1,
        "model": "cogos-tier-b",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }).encode("utf-8")

    def factory(method, path, body):
        assert method == "POST"
        assert path == "/v1/chat/completions"
        ts = 1715706000000
        token = _sign_attestation(
            server_keys["sk"], server_keys["kid"], method, path, ts,
            body, resp_body, chain_head="a" * 64, rev="rev-7",
        )
        headers = {
            "Content-Type": "application/json",
            "X-Cogos-Signature": _hmac_hex(hmac_secret, resp_body),
            "X-Cogos-Signature-Algo": "hmac-sha256",
            "X-Cogos-Attestation": token,
            "X-Cogos-Attestation-Algo": "ed25519",
        }
        # Override ts on the token by signing with the client's actual ts.
        # The client adds Date.now() ts when SENDING; the server uses its
        # own server-wall-clock for attestation. So we must use the same ts
        # in the canonical req_hash. To keep this simple, our fake doesn't
        # bind to req ts — the client only verifies resp_hash + signature.
        return (200, resp_body, headers)

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(
            api_key="sk-cogos-abc",
            hmac_secret=hmac_secret,
            base_url="https://api.example",
        )
        resp = c.chat.completions.create(
            model="cogos-tier-b",
            messages=[{"role": "user", "content": "hi"}],
        )
    assert resp["choices"][0]["message"]["content"] == "hello"
    assert resp.hmac_verified is True
    assert resp.attestation is not None
    assert resp.attestation.chain_head == "a" * 64
    assert resp.attestation.rev == "rev-7"
    assert resp.attestation.signer_kid == server_keys["kid"]
    assert resp.status == 200


def test_models_list_happy_path(server_keys):
    resp_body = json.dumps({"object": "list", "data": [{"id": "cogos-tier-b"}]}).encode("utf-8")

    def factory(method, path, body):
        assert method == "GET"
        assert path == "/v1/models"
        ts = 1
        token = _sign_attestation(
            server_keys["sk"], server_keys["kid"], method, path, ts, body, resp_body,
        )
        return (200, resp_body, {"X-Cogos-Attestation": token})

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(api_key="sk-cogos-abc", base_url="https://api.example")
        resp = c.models.list()
    assert resp["data"][0]["id"] == "cogos-tier-b"
    assert resp.attestation is not None


def test_audit_read_exposes_chain_ok(server_keys):
    resp_body = json.dumps({
        "rows": [],
        "next_cursor": None,
        "chain_ok": True,
        "chain_break": None,
        "chain_ok_by_app": {},
        "app_id": None,
        "server_time_ms": 123,
    }).encode("utf-8")

    def factory(method, path, body):
        assert path.startswith("/v1/audit?")
        assert "since=0" in path
        assert "limit=50" in path
        token = _sign_attestation(
            server_keys["sk"], server_keys["kid"], method, path, 1, body, resp_body,
        )
        return (200, resp_body, {"X-Cogos-Attestation": token})

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(api_key="sk-cogos-abc", base_url="https://api.example")
        resp = c.audit.read(since_ms=0, limit=50)
    assert resp["chain_ok"] is True
    assert resp["rows"] == []


def test_keys_rotate_bearer_returns_KeyRotation(server_keys):
    resp_body = json.dumps({
        "key_id": "key-new",
        "tenant_id": "alice",
        "app_id": "_default",
        "tier": "starter",
        "scheme": "bearer",
        "issued_at": "2026-05-14T00:00:00Z",
        "expires_at": "2027-05-14T00:00:00Z",
        "rotated_from_key_id": "key-old",
        "rotation_grace_until": "2026-05-15T00:00:00Z",
        "hmac_secret": "hsec_new",
        "api_key": "sk-cogos-NEW",
        "warning": "save it now",
    }).encode("utf-8")

    def factory(method, path, body):
        assert method == "POST"
        assert path == "/v1/keys/rotate"
        token = _sign_attestation(
            server_keys["sk"], server_keys["kid"], method, path, 1, body, resp_body,
        )
        return (201, resp_body, {"X-Cogos-Attestation": token})

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(api_key="sk-cogos-OLD", base_url="https://api.example")
        rot = c.keys.rotate()
    assert isinstance(rot, cogos.KeyRotation)
    assert rot.scheme == "bearer"
    assert rot.api_key == "sk-cogos-NEW"
    assert rot.hmac_secret == "hsec_new"
    assert rot.rotation_grace_until is not None


def test_keys_rotate_ed25519_returns_KeyRotation(server_keys):
    resp_body = json.dumps({
        "key_id": "key-new-ed",
        "tenant_id": "alice",
        "app_id": "_default",
        "tier": "starter",
        "scheme": "ed25519",
        "issued_at": "2026-05-14T00:00:00Z",
        "expires_at": None,
        "rotated_from_key_id": "key-old-ed",
        "rotation_grace_until": None,
        "hmac_secret": "hsec_new",
        "ed25519_key_id": "kid-new-ed",
        "private_pem": "-----BEGIN PRIVATE KEY-----\nA\n-----END PRIVATE KEY-----\n",
        "pubkey_pem": "-----BEGIN PUBLIC KEY-----\nB\n-----END PUBLIC KEY-----\n",
        "x25519_private_pem": "-----BEGIN PRIVATE KEY-----\nC\n-----END PRIVATE KEY-----\n",
        "x25519_pubkey_pem": "-----BEGIN PUBLIC KEY-----\nD\n-----END PUBLIC KEY-----\n",
        "warning": "save it now",
    }).encode("utf-8")

    def factory(method, path, body):
        token = _sign_attestation(
            server_keys["sk"], server_keys["kid"], method, path, 1, body, resp_body,
        )
        return (201, resp_body, {"X-Cogos-Attestation": token})

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(api_key="sk-cogos-OLD", base_url="https://api.example")
        rot = c.keys.rotate()
    assert rot.scheme == "ed25519"
    assert rot.api_key is None
    assert rot.ed25519_key_id == "kid-new-ed"
    assert rot.private_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert rot.x25519_private_pem.startswith("-----BEGIN PRIVATE KEY-----")


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "status, err, expected",
    [
        (401, {"message": "Invalid", "type": "invalid_api_key"}, cogos.AuthError),
        (429, {"message": "Rate", "type": "rate_limit_exceeded"}, cogos.RateLimitError),
        (429, {"message": "Daily", "type": "daily_quota_exceeded"}, cogos.DailyQuotaError),
        (500, {"message": "boom", "type": "server_error"}, cogos.ServerError),
        (502, {"message": "upstream", "type": "upstream_error"}, cogos.ServerError),
    ],
)
def test_error_status_maps_to_exception(server_keys, status, err, expected):
    resp_body = json.dumps({"error": err}).encode("utf-8")

    def factory(method, path, body):
        return (status, resp_body, {})

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(api_key="sk-cogos-abc", base_url="https://api.example")
        with pytest.raises(expected) as excinfo:
            c.models.list()
    assert excinfo.value.status == status
    assert excinfo.value.error == err
    assert excinfo.value.body == resp_body


# ---------------------------------------------------------------------------
# Crypto failure → typed exceptions
# ---------------------------------------------------------------------------

def test_hmac_mismatch_raises_SignatureMismatch(server_keys):
    hmac_secret = "hsec_right"
    resp_body = b'{"ok": true}'

    def factory(method, path, body):
        token = _sign_attestation(
            server_keys["sk"], server_keys["kid"], method, path, 1, body, resp_body,
        )
        return (200, resp_body, {
            # Sign with the WRONG secret on purpose.
            "X-Cogos-Signature": _hmac_hex("hsec_WRONG", resp_body),
            "X-Cogos-Attestation": token,
        })

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(
            api_key="sk-cogos-abc",
            hmac_secret=hmac_secret,
            base_url="https://api.example",
        )
        with pytest.raises(cogos.SignatureMismatch):
            c.models.list()


def test_missing_hmac_header_raises_SignatureMismatch_when_secret_provided(server_keys):
    resp_body = b'{"ok": true}'

    def factory(method, path, body):
        token = _sign_attestation(
            server_keys["sk"], server_keys["kid"], method, path, 1, body, resp_body,
        )
        return (200, resp_body, {"X-Cogos-Attestation": token})  # no X-Cogos-Signature

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(
            api_key="sk-cogos-abc",
            hmac_secret="hsec_x",
            base_url="https://api.example",
        )
        with pytest.raises(cogos.SignatureMismatch, match="no X-Cogos-Signature"):
            c.models.list()


def test_attestation_tamper_raises_AttestationMismatch(server_keys):
    resp_body = b'{"ok": true}'

    def factory(method, path, body):
        token = _sign_attestation(
            server_keys["sk"], server_keys["kid"], method, path, 1, body, resp_body,
        )
        # Corrupt the signature half.
        payload, _, sig = token.partition(".")
        sig = "A" + sig[1:] if sig[0] != "A" else "B" + sig[1:]
        return (200, resp_body, {"X-Cogos-Attestation": f"{payload}.{sig}"})

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(api_key="sk-cogos-abc", base_url="https://api.example")
        with pytest.raises(cogos.AttestationMismatch):
            c.models.list()


def test_verify_attestation_false_silences_check(server_keys):
    """Opt-out: ``verify_attestation=False`` skips check entirely."""
    resp_body = b'{"ok": true}'

    def factory(method, path, body):
        # Send a garbage token — would normally raise.
        return (200, resp_body, {"X-Cogos-Attestation": "garbage.garbage"})

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(
            api_key="sk-cogos-abc",
            base_url="https://api.example",
            verify_attestation=False,
        )
        resp = c.models.list()
    assert resp["ok"] is True
    assert resp.attestation is None


def test_no_attestation_header_is_ok_when_verify_disabled(server_keys):
    resp_body = b'{"ok": true}'

    def factory(method, path, body):
        return (200, resp_body, {})

    with _patched_urlopen(factory, server_keys["pub_pem"]):
        c = cogos.Client(
            api_key="sk-cogos-abc",
            base_url="https://api.example",
            verify_attestation=False,
        )
        resp = c.models.list()
    assert resp["ok"] is True
    assert resp.attestation is None


# ---------------------------------------------------------------------------
# Bearer vs Ed25519 auth headers — wire format check
# ---------------------------------------------------------------------------

def test_bearer_auth_header_is_set(server_keys):
    captured = []
    resp_body = b'{"object":"list","data":[]}'

    def factory(method, path, body):
        token = _sign_attestation(
            server_keys["sk"], server_keys["kid"], method, path, 1, body, resp_body,
        )
        return (200, resp_body, {"X-Cogos-Attestation": token})

    with _patched_urlopen(factory, server_keys["pub_pem"], record_requests=captured):
        c = cogos.Client(api_key="sk-cogos-MYKEY", base_url="https://api.example")
        c.models.list()
    # Find the /v1/models request — the pubkey fetch is also captured.
    api_req = next(r for r in captured if "/v1/models" in r["url"])
    assert api_req["headers"].get("Authorization") == "Bearer sk-cogos-MYKEY"


def test_ed25519_signer_issues_signed_request_header(server_keys):
    captured = []
    resp_body = b'{"object":"list","data":[]}'

    sk = Ed25519PrivateKey.generate()
    priv_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    signer = cogos.Ed25519Signer(priv_pem, key_id="kid-abc123")

    def factory(method, path, body):
        token = _sign_attestation(
            server_keys["sk"], server_keys["kid"], method, path, 1, body, resp_body,
        )
        return (200, resp_body, {"X-Cogos-Attestation": token})

    with _patched_urlopen(factory, server_keys["pub_pem"], record_requests=captured):
        c = cogos.Client(ed25519_signer=signer, base_url="https://api.example")
        c.models.list()
    api_req = next(r for r in captured if "/v1/models" in r["url"])
    auth = api_req["headers"].get("Authorization")
    assert auth is not None
    assert auth.startswith("CogOS-Ed25519 keyId=kid-abc123,sig=")
    assert ",ts=" in auth
