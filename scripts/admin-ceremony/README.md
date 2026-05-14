# Offline Admin Ceremony

> **Status:** scaffold only. The scripts in this directory are stubs. The
> live `/admin/*` HTTP routes in `src/index.js` remain in place today. This
> README describes the design intent and migration path; see
> [`SECURITY.md`](../../SECURITY.md) for the broader security posture this
> ceremony is part of.

## Why offline?

`cogos-api` is the public gateway of CogOS. Anything reachable over HTTP is
in the threat model of every scanner that hits the public IP. A live admin
endpoint — even one gated behind a strong secret — is **a place an attacker
can probe**: a 401 on `/admin/keys` tells the attacker the endpoint exists,
the auth model is "header-based shared secret," and a credential-stuffing
campaign or upstream secret leak (CI logs, Cloudflare tunnel mis-config, a
forgotten reverse proxy that strips the auth header) can turn into "issue
yourself a customer API key" or "exfiltrate the usage log of every paying
tenant."

The cleanest answer is **no live admin endpoint at all**. Admin operations
become **artifacts**, not requests:

- An operator runs a local CLI on their own machine.
- The CLI generates the operational change (new key, revocation, package
  update) as a **config diff** — a structured JSON document.
- The operator **signs** the diff with a hardware-backed operator key
  (cosign with a YubiKey-attested key, or an HSM-resident key).
- The signed diff is **shipped** to the deployment substrate — committed
  to a config repo, uploaded to an artifact bucket, or attached as input
  to the next `az containerapp update --revision-suffix ...` roll.
- The **running server** verifies the operator signature on boot, applies
  the diff to its in-memory key set, and emits an audit row. If verification
  fails, the new revision refuses to start and traffic stays on the old
  revision.

There is no admin HTTP route in the running container. There is nothing for
a scanner to probe. The control plane is **out-of-band by construction**.

## The threat model this closes

The live `/admin/*` route surface, taken together, lets a caller who holds
the admin shared secret do the following without any out-of-band approval:

- Mint a new customer API key for any tenant they name
- Revoke any existing key
- Read the append-only usage log for every tenant
- Mutate the package / tier catalog

A compromise of any one of the following is sufficient to gain all of the
above:

1. The `ADMIN_KEY` env var leaking from the runtime (a misconfigured logging
   line, an OS-level memory dump, a sidecar container with read access).
2. A reverse proxy in front of the gateway that strips and re-injects the
   admin header for a "trusted" internal IP that turns out not to be
   internal.
3. A future CSRF-shaped bug at the HTTP layer that lets a logged-in admin
   browser session be coerced into issuing requests on the attacker's behalf.
4. A vulnerability in any of the gateway's transitive HTTP dependencies that
   lets a request bypass the `adminAuth` middleware.

All four of these compromise the **HTTP layer**. The offline ceremony moves
admin authority **out of the HTTP layer** entirely. A compromise of the HTTP
layer can no longer mint keys, revoke keys, or read the usage log; the most
it can do is observe in-flight traffic on the data plane, which is bounded
by the existing per-key auth and per-tenant isolation.

The operator key (cosign / HSM / YubiKey) becomes the single secret that
matters. It does not live in any deployed container. It does not pass
through any HTTP request path. It is touched only on the operator's
workstation, ideally with hardware presence required (YubiKey touch, HSM
PIN) on every signing operation.

## The intended flow

The ceremony has three phases: **generate**, **sign**, **apply**.

### Phase 1 — Generate (local)

The operator invokes the relevant CLI on their workstation. For key
issuance:

```bash
./scripts/admin-ceremony/issue-key.sh tenant_id=acme tier=starter
```

The CLI runs **entirely locally**. It:

1. Generates a fresh `sk-cogos-<32-hex>` plaintext.
2. Computes the sha256 hash of the plaintext.
3. Builds a config-diff document of shape:
   ```json
   {
     "kind": "issue_key",
     "payload": {
       "tenant_id": "acme",
       "tier": "starter",
       "key_hash": "sha256:abcd…",
       "issued_at": "2026-05-14T12:34:56Z",
       "issuer": "denny@5ceos.com"
     }
   }
   ```
4. Prints the plaintext key to stdout **once** with explicit copy-and-store
   instructions. The plaintext is not written to any file.

For revocation and listing, the structure is analogous; revocation produces
a `{"kind": "revoke_key", "payload": {"key_hash": "...", "revoked_at": ...}}`
diff, and listing is a read-only operation against the current signed
artifact (no diff is produced).

### Phase 2 — Sign (local, hardware-backed)

The CLI shells out to `cosign sign-blob` (or the configured signer) against
the operator's hardware key. The signing prompt requires a physical
interaction — YubiKey touch, HSM PIN, etc. The operator cannot be
silently impersonated by malware running unattended on the workstation.

The signed output is a JSON blob of shape:

```json
{
  "kind": "issue_key",
  "payload": { ... },
  "sig": "MEUCIQD…base64…",
  "cert": "-----BEGIN CERTIFICATE-----\nMII…\n-----END CERTIFICATE-----\n"
}
```

The certificate chains to a published operator-key fingerprint (see
`SECURITY.md §3.2` for the cosign claim).

### Phase 3 — Apply (CI or one-shot)

The signed diff is shipped to production. Two paths are supported in v1:

**Path A — pipeline.** The operator commits the signed diff to a config
repo. The deploy pipeline picks it up at the next revision roll, bakes the
verified artifact into the new container image (or mounts it as a read-only
volume), and rolls the revision. This is the auditable, gitops-shaped flow.

**Path B — one-shot.** For incident response (revocation should land in
seconds, not at the next deploy cadence), the operator can run a one-shot
command of the form:

```bash
az containerapp update \
  --name cogos-api \
  --resource-group cogos-rg \
  --revision-suffix revoke-$(date +%s) \
  --set-env-vars "COGOS_SIGNED_CONFIG_DIFF=$(cat signed-revoke.json | base64)"
```

The new revision boots, the server reads `COGOS_SIGNED_CONFIG_DIFF`, verifies
the operator signature, applies the diff to its in-memory key set,
persists the diff to the append-only config log, and traffic shifts onto
the new revision. The old revision drains and dies. Net effect: a
revocation that lands within one revision-roll window (~30s on Azure
Container Apps), with the same signature guarantee as Path A.

Path B is **TBD in v1**. The exact env-var name, the verification entrypoint
inside `src/index.js`, and the persisted append-only log file are all open
design questions. This README will be amended (and a `SECURITY-NOTICE.md`
entry added) when the v1 implementation lands.

### Server-side verification

On boot, the server:

1. Reads the current signed config artifact from a known path (env var or
   mounted volume).
2. Validates the cosign signature against the operator public key
   fingerprint baked into the image at build time.
3. Walks the diff log in order, applying each verified entry to its
   in-memory key set.
4. Refuses to serve traffic if **any** entry fails verification — the
   revision crashes on boot and the previous revision keeps serving.

There is **no admin HTTP route** in this flow. The data plane (`/v1/*`,
`/health`, `/`) stays exactly as it is today.

## What's stubbed today vs. full v1

| Surface | Today | v1 target |
|---|---|---|
| Live-traffic HTML dashboard (formerly the unauthenticated route on the admin surface) | **Removed** (this card) | — |
| `/admin/keys` (POST + GET + revoke) | Live, gated on `X-Admin-Key` | Removed; replaced by `issue-key.sh` + signed diff |
| `/admin/usage` | Live, gated on `X-Admin-Key` | Replaced by an out-of-band read path (signed log export, or a read-only operator dashboard fed by the append-only log) — design TBD |
| `/admin/packages` (CRUD) | Live, gated on `X-Admin-Key` | Replaced by a `mint-package-diff.sh` ceremony following the same shape |
| `issue-key.sh` | **Stub** — prints TODO and exits 1 | Generates plaintext + diff, signs with operator key, prints signed JSON blob |
| `revoke-key.sh` | **Stub** | Builds revoke diff against an existing key hash, signs, emits |
| `list-keys.sh` | **Stub** | Reads the current signed artifact, prints hash/tenant/tier/revoked-at table |
| Server-side verify-on-boot | **Not implemented** | Wired into `src/index.js` `createApp()` boot path; revision refuses to start on signature failure |
| Operator pubkey distribution | **Not published** | Same path as the cosign image-signing pubkey: `https://cogos.5ceos.com/cosign.pub` (or a sibling URL for the admin pubkey if we choose to separate the roles) |

## Why this is week-1's "no live admin endpoint" claim

Week-1's posture in `SECURITY.md` reads "rolling out" for image signing
and "shipped" for response signature. The live admin route surface is the
one area where the claim "no remote admin attack surface" cannot yet be
made — because the routes are live. This directory is the **migration
target**: when the ceremony ships, the `/admin/*` routes are removed in
the same change, and the SECURITY.md text for §3.6 (Admin auth flow)
changes from "Admin operations require `X-Admin-Key`" to "Admin operations
are signed config diffs verified at boot; there is no admin HTTP route."

That sentence is the actual security improvement. The scaffolding in this
directory is the receipt that the team knows the improvement is coming and
has reserved the path for it, rather than backfilling under pressure when
the first scanner finds the live route.

## References

- `SECURITY.md` — overall security policy, §3 verifiable claims, §4 honest
  list of what is not defended against.
- `scripts/deploy-update.sh` — current image build and signing pipeline;
  the ceremony will hook into this path for Path A (gitops-shaped) apply.
- `src/auth.js` (do not modify here) — the `adminAuth` middleware that
  guards the current `/admin/*` routes. To be removed when the ceremony
  retires those routes.
- `src/keys.js` (do not modify here) — the in-memory key registry that the
  signed-diff verifier will populate on boot.

## Open questions for the v1 implementer

- **Operator pubkey storage.** Bake into image vs. mount via init container
  vs. fetch from a pinned URL at boot. Image-bake is simplest but rotation
  requires a rebuild; mount-via-init lets us rotate without a rebuild.
- **Diff log format.** Single append-only JSONL file vs. one signed file
  per diff. JSONL is operator-friendly but harder to verify a la carte;
  one-file-per-diff is cleaner for cosign tooling but noisier on disk.
- **Path B env-var size.** Container env vars have size limits (~32KB on
  most substrates). For bulk operations (e.g. mass revocation after a
  detected breach), Path B may need to fall back to a mounted secret or
  blob URL with a signed reference rather than inlining the diff.
- **Replay defense.** Each diff needs a monotonically increasing sequence
  number and the server needs to reject diffs with a sequence at or below
  the last-applied. Otherwise an attacker with read access to old signed
  diffs (which are not themselves secret) could replay a long-revoked key.
