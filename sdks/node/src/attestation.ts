// X-Cogos-Attestation token verification — customer side.
//
// Mirrors src/attestation.js on the gateway. Token format:
//   <payload_b64url>.<signature_b64url>
//
// payload is canonical JSON with FIXED KEY ORDER:
//   v, req_hash, resp_hash, rev, chain_head, signer, signer_kid, ts
//
// resp_hash binds the exact response body bytes the customer received,
// so verifying resp_hash here is the part that catches transit tampering.
// req_hash binds (method, path, ts, body) — the customer can recompute it
// when they want a full receipt, but our default verify just checks
// signature validity + resp_hash match. The full req-hash bind is
// available for callers who care to compute it themselves.

import { createHash, createPublicKey, verify } from 'node:crypto';

export interface AttestationPayload {
  v: number;
  req_hash: string;
  resp_hash: string;
  rev: string;
  chain_head: string;
  signer: string;
  signer_kid: string;
  ts: number;
}

function b64urlDecode(str: string): Buffer {
  const pad = str.length % 4 === 0 ? 0 : 4 - (str.length % 4);
  return Buffer.from(
    str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad),
    'base64',
  );
}

export function sha256Hex(buf: Buffer | string): string {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf), 'utf8');
  return createHash('sha256').update(b).digest('hex');
}

// Decode the payload portion of an attestation token WITHOUT verifying
// the signature. Useful for callers who want to inspect the chain_head
// or signer_kid before deciding whether to fetch /attestation.pub.
export function decodeAttestation(token: string): AttestationPayload | null {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [payloadB64, sigB64] = token.split('.', 2);
  if (!payloadB64 || !sigB64) return null;
  try {
    const json = b64urlDecode(payloadB64).toString('utf8');
    const parsed = JSON.parse(json) as AttestationPayload;
    if (typeof parsed.v !== 'number') return null;
    return parsed;
  } catch {
    return null;
  }
}

// Verify the token's signature against `pubPem` and confirm resp_hash
// matches the bytes we actually received. Returns the decoded payload on
// success, throws on any verification failure.
//
// `pubPem` must be the SPKI PEM the customer fetched from
// /attestation.pub of the SAME deployment that issued the token.
// Attestation keys persist across container restarts on the gateway
// (data/attestation-key.pem), but rotate when the operator regenerates
// the file. Re-fetch on `signer_kid` mismatch.
export function verifyAttestation(
  token: string,
  pubPem: string,
  responseBodyBytes: Buffer | string,
): AttestationPayload {
  const decoded = decodeAttestation(token);
  if (!decoded) {
    throw new Error('attestation token malformed');
  }
  const dotIdx = token.indexOf('.');
  const payloadB64 = token.slice(0, dotIdx);
  const sigB64 = token.slice(dotIdx + 1);
  // Reconstruct the EXACT bytes that were signed. The gateway signs the
  // canonical JSON string before base64url; we recompute that JSON from
  // the decoded payload using the same load-bearing key order.
  const canonical = JSON.stringify({
    v: decoded.v,
    req_hash: decoded.req_hash,
    resp_hash: decoded.resp_hash,
    rev: decoded.rev,
    chain_head: decoded.chain_head,
    signer: decoded.signer,
    signer_kid: decoded.signer_kid,
    ts: decoded.ts,
  });
  // Sanity: payload_b64 should base64url-encode the same canonical bytes.
  // If it doesn't, the token was manufactured with a different field order
  // and we refuse to verify (the signature might be valid over the WRONG
  // bytes — never let that pass).
  const reEncoded = Buffer.from(canonical, 'utf8')
    .toString('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  if (reEncoded !== payloadB64) {
    throw new Error('attestation payload field order mismatch');
  }

  const pubKey = createPublicKey(pubPem);
  const sigBuf = b64urlDecode(sigB64);
  let ok = false;
  try {
    ok = verify(null, Buffer.from(canonical, 'utf8'), pubKey, sigBuf);
  } catch {
    ok = false;
  }
  if (!ok) throw new Error('attestation signature invalid');

  // resp_hash bind. This is the critical check — if a MITM altered the
  // response body, resp_hash will not match.
  const respHashHere = sha256Hex(responseBodyBytes);
  if (respHashHere !== decoded.resp_hash) {
    throw new Error('attestation resp_hash does not bind response body');
  }
  return decoded;
}
