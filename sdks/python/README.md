# cogos — Python client for cogos.5ceos.com

Schema-locked LLM inference with cryptographic response signing.

This package wraps the bearer auth (or Ed25519 signed-request flow),
**auto-verifies** the `X-Cogos-Signature` HMAC and `X-Cogos-Attestation`
Ed25519 receipt on every response, and exposes the result through an
OpenAI-SDK-shaped API. One dependency: `cryptography`.

## What this gives you over a `curl`

Every response from `cogos.5ceos.com/v1/*` carries two signatures: an HMAC
of the body bytes (transit integrity) and an Ed25519 attestation token
binding `(req_hash, resp_hash, source_rev, chain_head, ts)`. With curl
you'd have to verify both by hand on every call. **This SDK does it for
you — silently, on by default, and raises a typed exception if anything
doesn't add up.** No silent acceptance of tampered responses.

## Install

```bash
pip install cogos
```

## Quick start (5 lines)

```python
import cogos

client = cogos.Client(api_key="sk-cogos-...", hmac_secret="hsec_...")
resp = client.chat.completions.create(
    model="cogos-tier-b",
    messages=[{"role": "user", "content": "summarise: cogos is..."}],
)
print(resp["choices"][0]["message"]["content"])
print(resp.attestation.chain_head)   # court-defensible receipt — persist this
```

If the HMAC doesn't match the body, `cogos.SignatureMismatch` is raised.
If the attestation token is forged or the body was rewritten in transit,
`cogos.AttestationMismatch` is raised. You **cannot** accept a tampered
response by accident.

## API surface

### `cogos.Client(api_key=None, hmac_secret=None, base_url="https://cogos.5ceos.com", *, ed25519_signer=None, verify_attestation=True, timeout=60)`

The client. Pass `api_key` for bearer auth (the common path) or
`ed25519_signer` for the signed-request scheme. Mutually exclusive.

| Argument             | Type                  | Default                       | Notes                                                                                              |
| -------------------- | --------------------- | ----------------------------- | -------------------------------------------------------------------------------------------------- |
| `api_key`            | `str \| None`         | —                             | Your bearer token (`sk-cogos-...`).                                                                |
| `hmac_secret`        | `str \| None`         | `None`                        | If set, every response's `X-Cogos-Signature` is auto-verified. **Recommended.**                    |
| `base_url`           | `str`                 | `https://cogos.5ceos.com`     | Override for staging / self-hosted.                                                                |
| `ed25519_signer`     | `Ed25519Signer`       | `None`                        | Use the signed-request scheme instead of bearer.                                                   |
| `verify_attestation` | `bool`                | `True`                        | When True, every response's `X-Cogos-Attestation` token is verified against `/attestation.pub`.    |
| `timeout`            | `float`               | `60.0`                        | Request timeout (seconds).                                                                         |

### `client.chat.completions.create(messages, model="cogos-tier-b", response_format=None, **kw)`

OpenAI-shaped chat completion. `model` is a CogOS tier alias
(`cogos-tier-b` = 3B, `cogos-tier-a` = 7B). `response_format` accepts the
standard `{"type": "json_schema", "json_schema": {...}}` for schema-locked
output. Extra keyword args (`temperature`, `max_tokens`, `seed`, …) are
forwarded to the request body unchanged.

Returns a `Response` (a `dict` subclass with `.attestation`,
`.hmac_verified`, `.status`, `.headers`, `.raw_body` attached).

### `client.models.list()`

`GET /v1/models` — list the available tier aliases and what each resolves to.

### `client.audit.read(since_ms=0, limit=100, app_id=None)`

`GET /v1/audit` — your tenant's hash-chained audit slice. Server-verified
`chain_ok` is available as `resp["chain_ok"]`; per-app verification is in
`resp["chain_ok_by_app"]`. Page forward with `since_ms=resp["next_cursor"]`.

### `client.keys.rotate()`

`POST /v1/keys/rotate` — rotates the current key in place. Returns a
`KeyRotation` object containing every credential the customer must
persist (`api_key`, `hmac_secret`, `private_pem`, `pubkey_pem`,
`x25519_private_pem`, `x25519_pubkey_pem` — whichever apply to the
scheme). The old key remains valid until `rotation_grace_until`. **All
secret material is shown once. Save it before the call returns.**

### `cogos.Ed25519Signer(private_pem, key_id=None)`

For customers using the signed-request scheme (`POST /admin/keys` with
`scheme="ed25519"`). Wrap your `private_pem` and the `ed25519_key_id`
you received at issuance, then hand it to the client:

```python
signer = cogos.Ed25519Signer(private_pem, key_id="kid-...")
client = cogos.Client(ed25519_signer=signer, hmac_secret="...")
```

Every request the client makes is now signed with `CogOS-Ed25519`
instead of bearer-authenticated.

### `cogos.unseal_audit_row(row, x25519_private_pem)`

Decrypts a single sealed audit row's content fields. Mirrors the
server's `x25519-hkdf-aes-256-gcm` envelope. Takes one row from
`client.audit.read().rows` and returns the cleartext content as a dict:

```python
audit = client.audit.read(limit=50)
for row in audit["rows"]:
    if row["sealed"]:
        content = cogos.unseal_audit_row(row, x25519_private_pem)
        print(content["request_id"], content.get("prompt_fingerprint"))
```

The cogos server **cannot** decrypt sealed content — the X25519 private
key never crossed the wire after issuance. A full server breach yields
ciphertext only.

### Exception hierarchy

```
cogos.CogOSError                  (base)
├── cogos.AuthError               (401)
├── cogos.RateLimitError          (429, rate_limit_exceeded)
├── cogos.DailyQuotaError         (429, daily_quota_exceeded — distinct from monthly)
├── cogos.SignatureMismatch       (X-Cogos-Signature failed; transit tamper)
├── cogos.AttestationMismatch     (X-Cogos-Attestation failed; transit or build tamper)
└── cogos.ServerError             (5xx)
```

Every exception carries `.status` (HTTP code), `.error` (parsed
`{"message": ..., "type": ...}` from the body), and `.body` (raw bytes).

## Security notes

### HMAC response signature

`X-Cogos-Signature` is `HMAC-SHA256(hmac_secret, raw_response_body)` in
lowercase hex. The client recomputes it over the **exact** bytes the
wire delivered — re-serialising the parsed JSON would change whitespace
and key order and the HMAC would not match. If you ever need to verify
manually:

```python
import hmac, hashlib
ok = hmac.compare_digest(
    hmac.new(hmac_secret.encode(), raw_body, hashlib.sha256).hexdigest(),
    response.headers["X-Cogos-Signature"],
)
```

Or call `cogos.verify_hmac(hmac_secret, raw_body, sig_hex)`.

### Attestation token

`X-Cogos-Attestation` is an Ed25519-signed receipt over a fixed-field-order
JSON payload:

```
v, req_hash, resp_hash, rev, chain_head, signer, signer_kid, ts
```

The client fetches the verification key from `/attestation.pub` (no
auth required) and verifies (a) the Ed25519 signature, (b) that
`resp_hash` equals `sha256(body)`. Both checks must pass. The verified
payload is exposed as `response.attestation`:

```python
print(resp.attestation.chain_head)    # 64-hex chain position
print(resp.attestation.rev)            # build revision SHA
print(resp.attestation.ts)             # unix-ms issuance time
```

Persist `resp.attestation.chain_head` alongside the response if you need a
court-defensible receipt later — it cryptographically binds the response
you received to a specific position in our audit chain, signed by a key
bound to a specific build of cogos-api.

### Sealed audit (ed25519 + x25519 scheme)

When you issue a key under `scheme="ed25519"`, the server also gives
you an X25519 keypair (`x25519_private_pem`, `x25519_pubkey_pem`).
Every audit row written for your tenant has its
content-sensitive fields encrypted under your X25519 pubkey using
`x25519-hkdf-aes-256-gcm`. The server keeps only the public half — a
full server breach yields ciphertext only.

To decrypt rows you fetched from `/v1/audit`, call
`cogos.unseal_audit_row(row, x25519_private_pem)`. Keep the X25519
private PEM somewhere safe (the same place you keep your API key).

### Replay window

Ed25519 signed requests carry a `ts` field (unix-ms). The server
accepts a `±5 minute` window around its wall clock. Keep your client
clock in sync (NTP / chrony).

### Container-restart receipts

The attestation signing key is persisted across restarts (sealed under
the server's data-encryption key), so receipts you collected days ago
still verify against the live `/attestation.pub`. If verification ever
fails after a deploy, the SDK transparently re-fetches the public key
and retries once.

## Verify against production

A quick prod smoke-test that hits `/v1/models` and verifies both signatures:

```python
import cogos

client = cogos.Client(
    api_key="sk-cogos-...",
    hmac_secret="hsec_...",
)
resp = client.models.list()
assert resp.hmac_verified, "HMAC failed — body tampered?"
assert resp.attestation is not None, "no attestation token"
print(f"verified ok; chain_head={resp.attestation.chain_head}, rev={resp.attestation.rev}")
```

If you see `cogos.SignatureMismatch` or `cogos.AttestationMismatch`,
something downstream of the gateway rewrote the response — investigate
immediately.

## Roadmap (v0.2+)

- Async client (`AsyncClient`) using `asyncio` + `aiohttp` (would add a
  dep, so will probably stay opt-in).
- Streaming chat completions (`stream=True`).
- Helper that re-runs `verify_chain()` locally over a `/v1/audit` slice
  (mirrors the server's `chain_ok` for independent assurance).
- Retry-with-backoff on 5xx / connection errors.
- Structured-output type generation from JSON Schema → Python `TypedDict`
  bindings the way `instructor` does for OpenAI.

## License

MIT — see the top-level repository.
