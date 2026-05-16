// Ed25519 signed-request flow for cogos-api.
//
// Mirrors the gateway's src/auth.js ed25519Auth() expectations:
//
//   Authorization: CogOS-Ed25519 keyId=<id>,sig=<base64>,ts=<unix_ms>
//
// Signed bytes:
//   <METHOD>\n<path-including-query>\n<ts>\n<body_sha256_hex>
//
// where:
//   - METHOD is uppercase HTTP method
//   - path is the request path WITH query string
//   - ts is the same unix-ms integer string included in the header
//   - body_sha256_hex is hex sha256 of raw request body bytes; empty body
//     uses the empty-string sha256.
//
// Signature is Ed25519 over those bytes, base64-encoded (STANDARD base64,
// not URL-safe — matches what the gateway expects).
//
// Replay window on the gateway side is currently 5 minutes either side
// of server clock. Don't reuse ts; mint a fresh Date.now() per request.

import { createHash, createPrivateKey, KeyObject, sign as ed25519Sign } from 'node:crypto';

const EMPTY_BODY_SHA256 = createHash('sha256').update('').digest('hex');

export interface SignRequestParams {
  method: string;
  path: string;
  ts: number;
  body?: Buffer | string | null;
  keyId: string;
}

// Holds the parsed ed25519 private key + the keyId the gateway uses to
// look up the matching public key on its side. Construct once and reuse.
export class Ed25519Signer {
  private readonly privateKey: KeyObject;
  public readonly keyId: string;

  constructor(privatePem: string, keyId: string) {
    if (typeof privatePem !== 'string' || !/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(privatePem)) {
      throw new Error('Ed25519Signer: privatePem must be a PEM string');
    }
    if (typeof keyId !== 'string' || keyId.length === 0) {
      throw new Error('Ed25519Signer: keyId required');
    }
    const k = createPrivateKey(privatePem);
    if (k.asymmetricKeyType !== 'ed25519') {
      throw new Error(`Ed25519Signer: expected ed25519 key, got ${k.asymmetricKeyType}`);
    }
    this.privateKey = k;
    this.keyId = keyId;
  }

  // Compute the Authorization header VALUE (without the scheme name —
  // the client prepends `CogOS-Ed25519 ` itself). Caller supplies a
  // fresh `ts` per request; ts is what the gateway uses for replay
  // window enforcement.
  signRequest(params: Omit<SignRequestParams, 'keyId'>): string {
    const method = String(params.method || 'GET').toUpperCase();
    const path = String(params.path || '/');
    const ts = String(params.ts);
    const bodyHex = params.body
      ? createHash('sha256').update(
          Buffer.isBuffer(params.body) ? params.body : Buffer.from(params.body, 'utf8'),
        ).digest('hex')
      : EMPTY_BODY_SHA256;
    const signedBytes = `${method}\n${path}\n${ts}\n${bodyHex}`;
    const sig = ed25519Sign(null, Buffer.from(signedBytes, 'utf8'), this.privateKey);
    const sigB64 = sig.toString('base64');
    return `keyId=${this.keyId},sig=${sigB64},ts=${ts}`;
  }

  // Convenience wrapper that returns the full Authorization header
  // value including scheme. Most callers should use the SDK client
  // directly — this is exposed for low-level testing / hand-rolled
  // HTTP clients.
  authorizationHeader(params: Omit<SignRequestParams, 'keyId'>): string {
    return `CogOS-Ed25519 ${this.signRequest(params)}`;
  }
}
