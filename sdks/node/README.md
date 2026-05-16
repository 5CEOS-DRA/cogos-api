# cogos-client

Node client for [cogos.5ceos.com](https://cogos.5ceos.com) — schema-locked LLM
inference with cryptographic response signing.

Zero runtime dependencies. Pure Node stdlib (`https`, `crypto`, `url`).
TypeScript types shipped. Requires Node 20+.

```
npm install cogos-client
```

## Quick start

```ts
import { Cogos } from 'cogos-client';

const client = new Cogos({
  apiKey: process.env.COGOS_API_KEY!,
  hmacSecret: process.env.COGOS_HMAC_SECRET, // optional but recommended
});

const r = await client.chat.completions.create({
  model: 'cogos-tier-b',
  messages: [{ role: 'user', content: 'Hello from CogOS' }],
});

console.log(r.choices[0].message.content);
```

That call mirrors the OpenAI Node SDK shape AND verifies, by default:

1. The HMAC-SHA256 signature in `X-Cogos-Signature` (when `hmacSecret` is set) —
   catches transit tampering.
2. The Ed25519 attestation token in `X-Cogos-Attestation` — binds the response
   bytes you received to a specific gateway build and audit-chain position.

If either check fails, the SDK throws `SignatureMismatchError` /
`AttestationMismatchError`. No silent passthrough.

## API reference

### `new Cogos(options)`

| option              | type             | default                         | notes                                                                |
| ------------------- | ---------------- | ------------------------------- | -------------------------------------------------------------------- |
| `apiKey`            | `string`         | —                               | Bearer key. Required unless `ed25519Signer` is set.                  |
| `hmacSecret`        | `string?`        | —                               | When set, HMAC verification is ON by default for every call.         |
| `ed25519Signer`     | `Ed25519Signer?` | —                               | When set, swaps bearer for `Authorization: CogOS-Ed25519 …`.         |
| `baseUrl`           | `string`         | `https://cogos.5ceos.com`       |                                                                      |
| `verifyAttestation` | `boolean`        | `true`                          | Set `false` to skip attestation entirely.                            |
| `timeoutMs`         | `number`         | `60000`                         | Per-request timeout.                                                 |
| `attestationPubPem` | `string?`        | (fetched lazily from gateway)   | Pin the gateway's attestation pubkey. Useful for tests / air-gapped. |

### `client.chat.completions.create(params, opts?)`

OpenAI-shaped chat completions. Pass `response_format: { type: 'json_schema', json_schema: { name, schema } }` to enforce a JSON Schema on the model output (schema-locked, deterministic re-serialization).

```ts
const r = await client.chat.completions.create({
  model: 'cogos-tier-b',
  messages: [{ role: 'user', content: 'Score sentiment of: "I love this."' }],
  response_format: {
    type: 'json_schema',
    json_schema: {
      name: 'sentiment',
      schema: {
        type: 'object',
        properties: {
          score: { type: 'number', minimum: -1, maximum: 1 },
          label: { type: 'string', enum: ['negative', 'neutral', 'positive'] },
        },
        required: ['score', 'label'],
      },
    },
  },
});
```

### `client.models.list()`

Returns the available CogOS tier aliases (`cogos-tier-a`, `cogos-tier-b`).

### `client.audit.read({ sinceMs?, limit?, appId? })`

Returns your audit slice. `chain_ok` is `true` when the hash chain over the
returned rows is intact. `chain_ok_by_app` breaks this down per app for the
cross-app view (no `appId` filter).

```ts
const slice = await client.audit.read({ limit: 100 });
if (!slice.chain_ok) {
  // chain_break tells you exactly where it failed
  console.error('audit chain break', slice.chain_break);
}
```

### `client.keys.rotate()`

Mints a new key of the same scheme, returns the new credentials. Saves
nothing — the new `api_key` (or `private_pem` for ed25519 keys) is shown
exactly once. The old key remains valid for a 24-hour grace window.

### `new Ed25519Signer(privatePem, keyId)`

For customers who issued ed25519-scheme keys. Sign each request with your
persistent ed25519 private key so the gateway never sees a reusable
auth secret.

```ts
import { Cogos, Ed25519Signer } from 'cogos-client';

const signer = new Ed25519Signer(fs.readFileSync('cogos.priv', 'utf8'), 'kid-abc123');
const client = new Cogos({ ed25519Signer: signer, hmacSecret: '…' });
```

### `unsealAuditRow(row, x25519PrivatePem)`

Decrypt a customer-sealed audit row. Returns the cleartext content object
(`{ request_id?, prompt_fingerprint?, schema_name? }`). The server cannot
do this — your X25519 private key is the only key that opens the envelope.

```ts
import { unsealAuditRow } from 'cogos-client';
const x25519Priv = fs.readFileSync('cogos.x25519.priv', 'utf8');
const slice = await client.audit.read({ limit: 100 });
for (const row of slice.rows) {
  if (row.sealed) {
    const content = unsealAuditRow(row, x25519Priv);
    console.log(row.ts, content.request_id, content.schema_name);
  }
}
```

## Errors

| class                       | thrown when                                                              |
| --------------------------- | ------------------------------------------------------------------------ |
| `AuthError`                 | 401 (invalid / expired / quarantined key)                                |
| `RateLimitError`            | 429 with non-quota `type` (per-tenant rate circuit)                      |
| `DailyQuotaError`           | 429 with `type` of `daily_quota_exceeded` or `quota_exceeded`            |
| `SignatureMismatchError`    | HMAC verification failed                                                 |
| `AttestationMismatchError`  | Attestation signature failed OR `resp_hash` didn't bind your bytes       |
| `ServerError`               | Any 5xx                                                                  |
| `CogosError`                | Base class — catch this for blanket SDK error handling                   |

Every error carries `.status`, `.errorType`, `.body`, and `.requestId`.
`RateLimitError` and `DailyQuotaError` also carry `.retryAfterSeconds`.

## Security notes

- **HMAC secret**: shown exactly once at API-key issuance. Store it with the
  same care as the API key itself.
- **Attestation pubkey**: the gateway's attestation key persists on disk
  across container restarts when possible, but the operator may rotate it.
  The SDK lazily fetches `/attestation.pub` once and caches it. If you pin
  a stale pubkey via `attestationPubPem`, verification will fail on the
  first response after rotation — clear the cache and re-fetch.
- **Ed25519 signed-request flow**: the gateway enforces a 5-minute replay
  window on `ts`. The SDK uses `Date.now()` per request; don't reuse a
  signed Authorization header.

## TODO (post-v0.1.0)

- Streaming responses (server-sent events for `chat.completions.create`)
- Async iterator over paged audit slices (`for await (const row of client.audit.scan({...}))`)
- Retry-with-backoff on `RateLimitError`
- Auto-refresh attestation pubkey on `signer_kid` mismatch
- JSON Schema → Zod type generation for `response_format` payloads

## License

MIT. © 5CEOS Inc.
