# cogos-api

OpenAI-compatible API gateway for **CogOS** — deterministic, schema-locked, tier-routed inference on open-weight LLMs.

## What it is

`cogos-api` is the public surface of CogOS. Customers call `POST /v1/chat/completions` with the same request shape they'd use against OpenAI; under the hood, the request routes through Ollama (or any OpenAI-compatible inference engine) with **grammar-constrained decoding**, **pinned deterministic settings**, and **provenance-grade usage logging**.

The model is interchangeable. The runtime guarantees are the product.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | — | Liveness probe |
| `GET` | `/v1/models` | Bearer | OpenAI-compatible model list (from Ollama tags) |
| `POST` | `/v1/chat/completions` | Bearer | The product. OpenAI-shape in, OpenAI-shape out, with CogOS extensions |
| `POST` | `/admin/keys` | Admin | Issue a new `sk-cogos-…` API key for a tenant |
| `GET` | `/admin/keys` | Admin | List issued keys (hashes never returned) |
| `POST` | `/admin/keys/:id/revoke` | Admin | Soft-delete an API key |
| `GET` | `/admin/usage` | Admin | Read the append-only usage log |

## Auth

- **Customer**: `Authorization: Bearer sk-cogos-<32-hex>`. Keys are issued once and stored as sha256 hashes; the plaintext is shown to the customer at issuance only.
- **Admin**: `X-Admin-Key: <ADMIN_KEY-env>`. Single shared key for issuance/revocation. Rotate by changing the env var.

## CogOS-specific request fields

The `/v1/chat/completions` endpoint accepts the OpenAI request shape plus:

- `model: "cogos-tier-b"` resolves to `qwen2.5:3b-instruct` (classification-shaped workloads, per GreenOps doctrine)
- `model: "cogos-tier-a"` resolves to `qwen2.5:7b-instruct` (narrative)
- Any raw Ollama model tag also works (e.g. `model: "qwen2.5:7b-instruct"`)

## Schema-enforced decoding

When you pass `response_format: { type: "json_schema", json_schema: { schema: ... } }`, CogOS forwards the schema to the inference engine's grammar-constrained decoder. The model is **physically prevented** from emitting non-conforming output at the token level. Same surface as OpenAI's strict JSON mode — works on any open-weight model.

## Response headers (CogOS extensions)

Every successful `/v1/chat/completions` response includes:

| Header | Meaning |
|---|---|
| `X-Cogos-Model` | The actual model that served the request (after tier alias resolution) |
| `X-Cogos-Latency-Ms` | End-to-end inference time |
| `X-Cogos-Schema-Enforced` | `1` if grammar-constrained decoding was used, `0` otherwise |
| `X-Cogos-Request-Id` | Echo of `id` in the response body, for log correlation |

The response body also includes a `cogos: { ... }` extension field (ignored by OpenAI clients).

## Quick start

```bash
git clone https://github.com/5CEOS-DRA/cogos-api.git
cd cogos-api
npm install
cp .env.example .env       # set ADMIN_KEY
npm test                    # 10+ tests, mocked Ollama
npm start                   # listens on PORT (default 4444)
```

## Run a real call

```bash
# 1. Issue a customer API key
curl -X POST http://localhost:4444/admin/keys \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"denny","tier":"starter"}' | jq .

# Save the api_key — it's shown ONCE.

# 2. Call it like OpenAI
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

Both swap for Postgres + Stripe metering when customer count justifies it.

## License

Internal — private repo. Source not redistributed.
