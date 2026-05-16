// Error classes for the cogos SDK.
//
// Every non-2xx response from the gateway gets mapped to one of these.
// Each carries:
//   - .status     — the HTTP status code (or 0 for client-side checks)
//   - .errorType  — the `error.type` field the gateway returns
//                   (e.g. 'invalid_api_key', 'quota_exceeded',
//                   'model_tier_denied'); empty string for SDK-side errors
//   - .body       — the parsed JSON body if present; raw text otherwise
//
// CogosError is the base. Catch it to handle any SDK error generically;
// catch a subclass to handle a specific failure mode (rate-limit retry,
// signature-mismatch alarm, etc.).

export class CogosError extends Error {
  public readonly status: number;
  public readonly errorType: string;
  public readonly body: unknown;
  public readonly requestId: string | null;

  constructor(
    message: string,
    opts: { status?: number; errorType?: string; body?: unknown; requestId?: string | null } = {},
  ) {
    super(message);
    this.name = 'CogosError';
    this.status = opts.status ?? 0;
    this.errorType = opts.errorType ?? '';
    this.body = opts.body ?? null;
    this.requestId = opts.requestId ?? null;
    // Keep prototype chain right under transpilation targets.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// 401 invalid_api_key / expired_api_key / key_quarantined_for_review.
// Wrap the gateway's exact errorType so callers can branch.
export class AuthError extends CogosError {
  constructor(message: string, opts: { status?: number; errorType?: string; body?: unknown; requestId?: string | null } = {}) {
    super(message, opts);
    this.name = 'AuthError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// 429 with `type='rate_limit'` (per-tenant request-rate circuit).
// Distinct from DailyQuotaError so retry policies can differ — rate-limit
// is "wait a few seconds," quota is "wait until midnight UTC."
export class RateLimitError extends CogosError {
  public readonly retryAfterSeconds: number | null;

  constructor(message: string, opts: { status?: number; errorType?: string; body?: unknown; retryAfterSeconds?: number | null; requestId?: string | null } = {}) {
    super(message, opts);
    this.name = 'RateLimitError';
    this.retryAfterSeconds = opts.retryAfterSeconds ?? null;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// 429 with `type='daily_quota_exceeded'` OR `type='quota_exceeded'`.
// Both flavors land here; inspect .errorType to distinguish.
export class DailyQuotaError extends CogosError {
  public readonly retryAfterSeconds: number | null;

  constructor(message: string, opts: { status?: number; errorType?: string; body?: unknown; retryAfterSeconds?: number | null; requestId?: string | null } = {}) {
    super(message, opts);
    this.name = 'DailyQuotaError';
    this.retryAfterSeconds = opts.retryAfterSeconds ?? null;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// HMAC verification failed. Thrown ONLY by the verifying client path
// (when {hmacSecret} was passed at construction). The server response is
// already in hand at this point; this signals transit tampering or a
// mismatched secret. Callers should treat the response as untrusted.
export class SignatureMismatchError extends CogosError {
  constructor(message: string, opts: { body?: unknown; requestId?: string | null } = {}) {
    super(message, { status: 200, errorType: 'signature_mismatch', body: opts.body, requestId: opts.requestId });
    this.name = 'SignatureMismatchError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// Attestation token verification failed (Ed25519 over the gateway's
// receipt). Either the signature is bad, the resp_hash doesn't bind
// the bytes we received, or the token is malformed. Strictly distinct
// from SignatureMismatchError so a caller can opt out of one without
// disabling the other.
export class AttestationMismatchError extends CogosError {
  constructor(message: string, opts: { body?: unknown; requestId?: string | null } = {}) {
    super(message, { status: 200, errorType: 'attestation_mismatch', body: opts.body, requestId: opts.requestId });
    this.name = 'AttestationMismatchError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// Any 5xx from the gateway.
export class ServerError extends CogosError {
  constructor(message: string, opts: { status?: number; errorType?: string; body?: unknown; requestId?: string | null } = {}) {
    super(message, opts);
    this.name = 'ServerError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
