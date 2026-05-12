# cogos-api

The public API surface of **CogOS** — a cognition substrate that turns commodity open-weight language models into production-grade infrastructure.

## What it actually is

`cogos-api` is the gateway. Customers POST chat-completions-shape requests to it; under the hood, calls route through Ollama (or any compatible inference engine) with:

- **Grammar-constrained decoding** — when a JSON Schema is supplied, the decoder physically can't emit non-conforming output
- **Pinned deterministic settings** — same input, same bytes out, run after run, verifiable
- **Tier-routed model selection** — task-shape determines model size (GreenOps doctrine)
- **Provenance-grade usage logging** — every call emits a hash-chain-able event

The model is interchangeable (Qwen 2.5 today; Llama 3.3 / Mistral as discrete versioned upgrades later). The runtime guarantees are the product.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | — | Liveness probe |
| `GET` | `/` | — | Public landing page |
| `POST` | `/signup` | — | Creates a Stripe Checkout session, 303 redirect |
| `GET` | `/success` | — | Post-payment landing; shows the issued API key once |
| `GET` | `/cancel` | — | Stripe redirect on cancellation |
| `POST` | `/stripe/webhook` | Stripe signature | Receives `checkout.session.completed`, subscription updates |
| `GET` | `/v1/models` | Bearer | Compatible model list |
| `POST` | `/v1/chat/completions` | Bearer | The product. Chat-completions shape in/out, with CogOS extensions |
| `POST` | `/admin/keys` | Admin | Issue a new `sk-cogos-…` API key for a tenant |
| `GET` | `/admin/keys` | Admin | List issued keys (hashes never returned) |
| `POST` | `/admin/keys/:id/revoke` | Admin | Soft-delete an API key |
| `GET` | `/admin/usage` | Admin | Read the append-only usage log |
| `GET` | `/admin/live` | — (key gate in browser) | Live traffic dashboard |

## Auth

- **Customer**: `Authorization: Bearer sk-cogos-<32-hex>`. Issued via `/admin/keys` or Stripe Checkout. Stored as sha256 hash; plaintext shown to the customer at issue time only.
- **Admin**: `X-Admin-Key: <ADMIN_KEY-env>`. Single shared key for issuance/revocation. Rotate by changing the env var.
- **Stripe**: webhooks gated on `Stripe-Signature` header, verified against `STRIPE_WEBHOOK_SECRET`.

## CogOS-specific request fields

The `/v1/chat/completions` endpoint accepts the standard chat-completions request shape plus:

- `model: "cogos-tier-b"` resolves to `qwen2.5:3b-instruct` (classification-shaped workloads, per GreenOps doctrine)
- `model: "cogos-tier-a"` resolves to `qwen2.5:7b-instruct` (narrative)
- Any raw Ollama model tag also works (e.g. `model: "qwen2.5:7b-instruct"`)

## Schema-enforced decoding

When you pass `response_format: { type: "json_schema", json_schema: { schema: ... } }`, CogOS forwards the schema to the inference engine's grammar-constrained decoder. The model is **physically prevented** from emitting non-conforming output at the token level. Works on every supported model — no opt-in tier needed.

## Response headers (CogOS extensions)

Every successful `/v1/chat/completions` response includes:

| Header | Meaning |
|---|---|
| `X-Cogos-Model` | The actual model that served the request (after tier alias resolution) |
| `X-Cogos-Latency-Ms` | End-to-end inference time |
| `X-Cogos-Schema-Enforced` | `1` if grammar-constrained decoding was used, `0` otherwise |
| `X-Cogos-Request-Id` | Echo of `id` in the response body, for log correlation |

The response body also includes a `cogos: { ... }` extension field (ignored by standard clients).

## Quick start

```bash
git clone https://github.com/5CEOS-DRA/cogos-api.git
cd cogos-api
npm install
cp .env.example .env       # set ADMIN_KEY, STRIPE_* if doing self-serve
npm test                    # 24 tests, mocked inference engine and Stripe
npm start                   # listens on PORT (default 4444)
```

## Run a real call

```bash
# 1. Issue a customer API key
curl -X POST http://localhost:4444/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"denny","tier":"starter"}' | jq

# Save the api_key — it's shown ONCE.

# 2. Make a chat-completions call
curl -X POST http://localhost:4444/v1/chat/completions \
  -H "Authorization: Bearer sk-cogos-XXXXXXXX..." \
  -H "Content-Type: application/json" \
  -d '{
    "model": "cogos-tier-b",
    "messages": [{"role":"user","content":"What is 2+2?"}],
    "response_format": {
      "type": "json_schema",
      "json_schema": {
        "name": "math",
        "strict": true,
        "schema": {
          "type": "object",
          "required": ["answer"],
          "properties": {"answer": {"type": "integer"}}
        }
      }
    }
  }' | jq .
```

## Storage (v1)

- **API keys**: `data/keys.json` (mode 0600, sha256-hashed, gitignored)
- **Usage log**: `data/usage.jsonl` (append-only, one line per call)
- **Stripe events**: `data/stripe-events.json` (idempotency log)

All three swap for Postgres + Stripe metering when customer count justifies it.

## Deploy

See [`deploy/`](deploy/) for the Azure provisioning automation. Single `bash deploy/provision.sh` from your Mac produces a live URL ~10 minutes after GPU quota is approved.

## License

Internal — private repo. Source not redistributed.
