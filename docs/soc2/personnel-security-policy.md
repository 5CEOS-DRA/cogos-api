# Personnel Security Policy

Last reviewed: 2026-05-14

This policy covers **TSC CC1.1** (commitment to integrity and ethical values), **CC1.2** (independence and oversight responsibilities of the board), **CC1.3** (organizational structure and authority), and **CC1.4** (commitment to competence). For a solo-operator entity at the current stage, several of these controls are honestly disclosed as gaps with compensating controls in their place.

The audience is a SOC 2 auditor who needs an honest read of personnel-related risk at solo-operator scale. We will not invent a board, a CISO, or an HR function we do not have.

---

## 1. Scope and current organizational state

`cogos-api` is operated by a single individual at the time of this policy. There is one operator (the founder, Denny Adams). There is no board. There is no separate compliance officer, CISO, or HR function. There is no employee population.

This is the current state. Many controls in this policy describe what will change when the operator population grows. The auditor should evaluate the policy against the current state, not the aspirational state.

---

## 2. Integrity and ethical values (CC1.1)

### 2.1 Operator code of conduct

The operator agrees in writing (recorded in operator-local files outside this repo) to:

- Never share customer secrets in any context
- Never modify customer data, audit logs, or hash chains outside of operationally-required mechanisms (the prescribed code paths)
- Never bypass the deploy script (`scripts/deploy-update.sh`) for production changes
- Disclose security incidents per `incident-response-plan.md` without delay
- Follow the customer-notification SLA in `incident-response-plan.md` §6.4 even when it's commercially inconvenient

This is a personal commitment, not a contractual one with a separate employer (there is no separate employer). The compensating control is operator-as-founder alignment with the business's reputation: a breach of these commitments is reputationally fatal.

### 2.2 Founder fitness

The operator's professional history is documented in publicly-available sources (LinkedIn, the `5CEOS` ecosystem documentation). The operator self-attests to:

- No criminal history that would disqualify under standard background-check practice
- No pending legal action that affects fiduciary duty or technical operating capacity
- No undisclosed conflict of interest with vendors listed in `vendor-management-policy.md`

At current scale this is self-attestation. When operator count exceeds one, formal background checks (Checkr or similar) will gate the new operator before any production access is granted.

---

## 3. Organization, oversight, and authority (CC1.2, CC1.3)

### 3.1 Solo-operator caveat

Several SOC 2 controls (e.g. CC1.2 board independence, separation of duties on key actions) presume a multi-person organization. For solo-operator scale, the auditor should record this as a known structural limitation. The mitigation is:

- **Auditable git history**: every code change is in the public-or-private repo's commit log. The operator cannot retroactively edit it without a force-push, which is itself an auditable event in any mirroring system.
- **`Co-Authored-By:` trailers**: every commit involving LLM-assisted authorship is tagged. The auditor can see, from the commit log, what was authored with AI assistance and what was authored without.
- **Signed commits**: when configured, commits are GPG-signed (verifiable via `git log --show-signature`).
- **Manual TTY gate on deploy**: `scripts/deploy-update.sh` requires the operator to manually type a confirmation token. This is the closest equivalent to a two-person rule at solo scale.
- **24-hour display window for credentials**: customer keys are visible on the `/success` page for 24 hours, then return a stale-session message. This bounds the credential-exfiltration window to the duration of a single customer transaction.

### 3.2 Future organizational growth

When the operator population grows beyond one, this policy gets:

- A formal authority/role matrix
- Documented two-person rules on Critical actions (key issuance for enterprise customers, deploy script invocation, cosign signing)
- A separate compliance/security role distinct from engineering
- Documented onboarding and off-boarding procedures including HR-style records

Until then, the auditable git history + Stripe receipts (financial trail) are the org-structure substrate.

---

## 4. Competence and training (CC1.4)

### 4.1 Operator security training

The operator commits to annual security-awareness training covering:

- Phishing recognition (especially around the cosign signing-key and Azure tenancy)
- Secure-coding standards relevant to the gateway's threat model
- Social-engineering awareness (customer impersonation, vendor impersonation)
- Incident-response procedure walk-through (this document and `incident-response-plan.md`)

**Status:** TBD, scheduled at SOC 2 engagement kickoff. The operator has industry-standard awareness from professional history but has not yet completed a structured annual training program with a third-party provider. This is honestly disclosed — see the README's pre-audit punch list.

### 4.2 Cryptography competence

The operator has read and verified the implementations in:

- `src/auth.js` (constant-time admin compare, ed25519 verify, replay window)
- `src/keys.js` (hash-on-issue, scheme dispatch, HMAC secret generation)
- `src/usage.js` (canonical-JSON hash chain, per-tenant chain head, verifyChain)
- `src/anomaly.js` (sliding-window observers)

The operator understands the determinism claims, the schema-enforcement claims, and the verifiable-security claims at the level required to defend them under audit. The operator does **not** claim to be a cryptographer — the primitives used are standard (`crypto.timingSafeEqual`, `crypto.verify` ed25519, `crypto.createHash('sha256')`, HMAC-SHA256 via Node's `crypto`) and the construction is reviewed against published references.

### 4.3 Auditor questions

For competence verification under audit, the auditor can ask the operator to walk through:

- Why is the audit-chain canonical-JSON in fixed-key order rather than sorted? (Answer in `src/usage.js` comment block)
- Why does ed25519 auth not fall back to bearer? (Answer: downgrade-oracle defense; see `src/auth.js`)
- Why is the `ADMIN_KEY` constant-time compared and not bcrypt-style? (Answer: it's a 256-bit random shared secret, not a password)
- Why is the anomaly detector mounted before honeypot rather than after? (Answer: honeypot terminates without calling next(); we still want anomaly observation)

These are the operational-knowledge checks. Failing any of them indicates a competence gap the operator should remediate before continuing in role.

---

## 5. Access rotation cadence

| Item | Rotation cadence | Trigger |
|---|---|---|
| `ADMIN_KEY` | At minimum annual | Operator off-boarding, suspected compromise, audit finding |
| Cosign signing key | At minimum annual | Suspected compromise, operator off-boarding |
| `STRIPE_SECRET_KEY` (when wired) | At minimum annual | Stripe-dashboard rotation |
| `STRIPE_WEBHOOK_SECRET` | At minimum annual | Stripe-dashboard rotation |
| GitHub tokens (PATs, deploy keys) | At minimum annual | Token expiry from GitHub, operator off-boarding |
| Operator's Azure AD password | Per Azure tenant policy (typically 90 days when forced; we currently rely on Azure AD enforcement) | Azure AD policy |

Rotations are recorded in the operator's local incident note. A future iteration will surface rotation events into the `/admin/soc2/evidence-bundle` endpoint.

---

## 6. Separation of duties (CC1.3)

### 6.1 Current state — honest disclosure

At solo-operator scale there is no separation of duties in the traditional sense. The operator authors code, reviews code, deploys code, holds the signing key, and acts as compliance officer. This is a known structural gap.

### 6.2 Compensating controls

- **Git history** — every action that affects the production system has a commit, a revision, or a log line. The operator cannot perform a privileged action without leaving a trail.
- **Signed-CLI ceremony** — `scripts/deploy-update.sh` requires manual confirmation; cannot be silently invoked
- **24-hour display window** — credentials shown on `/success` self-expire; the operator cannot re-display them silently
- **Auditable cosign signatures** — every deployed image is signed; the signature binds the image to the signing key, and the signing key is held in Azure Key Vault with HSM-backed audit trail
- **External determinism bench** — `llm-determinism-bench` runs on a public cadence; the operator cannot silently swap the inference model without the bench surfacing it

### 6.3 Future state

When operator count exceeds one, separation of duties applies to:

- Code review (different author and reviewer for any change to `src/`)
- Deploy authorization (different operator authorizes vs executes)
- Cosign signing-key holders (single-person hold becomes split into multiple parties for higher-trust signatures)
- Customer-key issuance for enterprise tier (two-person rule)

---

## 7. Off-boarding

When the operator population is greater than one and an operator off-boards:

1. Revoke Azure RBAC role assignments on the resource group and Key Vault
2. Remove from GitHub `cogos-api` collaborator list
3. Rotate `ADMIN_KEY` regardless of whether the off-boarded operator held it
4. Rotate cosign signing key if held
5. Rotate Stripe API key if held
6. Remove from all sub-processor admin consoles where the operator had access
7. Record the off-boarding event in this document's CHANGELOG section

At current scale (one operator) this is hypothetical. The procedure is documented now so it's not invented under pressure later.

---

## 8. Review

This policy is reviewed at least annually. The next review date is 2027-05-14. The most likely trigger for an immediate review is an operator-population change.

Reviewed annually or when control surface changes materially.
