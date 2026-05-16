// Top-level Cogos client.
//
// new Cogos({apiKey, hmacSecret?, baseUrl?})
//
// On every /v1/* response:
//   - If `hmacSecret` was provided, verify X-Cogos-Signature; throw
//     SignatureMismatchError on failure.
//   - If `verifyAttestation` is true (default), fetch /attestation.pub
//     (cached) and verify X-Cogos-Attestation against the exact
//     response bytes; throw AttestationMismatchError on failure.
//
// Auth dispatch: bearer (`Authorization: Bearer <apiKey>`).
// Ed25519 signed-request flow is added in a follow-up commit.

import { rawRequest } from './http';
import { verifyHmac } from './hmac';
import { verifyAttestation } from './attestation';
import {
  AuthError,
  AttestationMismatchError,
  CogosError,
  DailyQuotaError,
  RateLimitError,
  ServerError,
  SignatureMismatchError,
} from './errors';
import type {
  AuditReadParams,
  AuditReadResponse,
  ChatCompletion,
  ChatCompletionCreateParams,
  ModelsList,
  RequestOptions,
  RotateResponse,
} from './types';

export interface CogosClientOptions {
  apiKey?: string;
  hmacSecret?: string;
  baseUrl?: string;
  verifyAttestation?: boolean;
  timeoutMs?: number;
  // Test hook: pin the attestation pubkey PEM so tests don't need to
  // hit /attestation.pub. Customers should never set this in production —
  // the gateway rotates its key on container restart (best effort
  // persisted on disk via data/attestation-key.pem; in containers without
  // a writable volume it regenerates).
  attestationPubPem?: string;
}

const DEFAULT_BASE_URL = 'https://cogos.5ceos.com';
const DEFAULT_TIMEOUT_MS = 60_000;

function errorTypeOf(body: unknown): string {
  if (body && typeof body === 'object') {
    const err = (body as { error?: { type?: unknown } }).error;
    if (err && typeof err === 'object' && typeof err.type === 'string') {
      return err.type;
    }
  }
  return '';
}

function errorMessageOf(body: unknown, fallback: string): string {
  if (body && typeof body === 'object') {
    const err = (body as { error?: { message?: unknown } }).error;
    if (err && typeof err === 'object' && typeof err.message === 'string') {
      return err.message;
    }
  }
  return fallback;
}

function mapErrorFromResponse(
  status: number,
  body: unknown,
  requestId: string | null,
  retryAfter: number | null,
): CogosError {
  const eType = errorTypeOf(body);
  const msg = errorMessageOf(body, `HTTP ${status}`);
  if (status === 401) {
    return new AuthError(msg, { status, errorType: eType, body, requestId });
  }
  if (status === 429) {
    if (eType === 'quota_exceeded' || eType === 'daily_quota_exceeded') {
      return new DailyQuotaError(msg, { status, errorType: eType, body, retryAfterSeconds: retryAfter, requestId });
    }
    return new RateLimitError(msg, { status, errorType: eType, body, retryAfterSeconds: retryAfter, requestId });
  }
  if (status >= 500) {
    return new ServerError(msg, { status, errorType: eType, body, requestId });
  }
  return new CogosError(msg, { status, errorType: eType, body, requestId });
}

export class Cogos {
  public readonly baseUrl: string;
  protected readonly apiKey: string | null;
  protected readonly hmacSecret: string | null;
  protected readonly verifyAttestationDefault: boolean;
  protected readonly defaultTimeoutMs: number;
  protected cachedAttestationPubPem: string | null;

  public readonly chat: { completions: { create: (params: ChatCompletionCreateParams, opts?: RequestOptions) => Promise<ChatCompletion> } };
  public readonly models: { list: (opts?: RequestOptions) => Promise<ModelsList> };
  public readonly audit: { read: (params?: AuditReadParams, opts?: RequestOptions) => Promise<AuditReadResponse> };
  public readonly keys: { rotate: (opts?: RequestOptions) => Promise<RotateResponse> };

  constructor(opts: CogosClientOptions = {}) {
    this.apiKey = opts.apiKey ?? null;
    this.hmacSecret = opts.hmacSecret ?? null;
    this.baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '');
    this.verifyAttestationDefault = opts.verifyAttestation !== false;
    this.defaultTimeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.cachedAttestationPubPem = opts.attestationPubPem ?? null;

    if (!this.apiKey) {
      throw new Error('Cogos: apiKey required');
    }

    // Bind public methods as namespaced objects, mirroring the OpenAI
    // SDK shape: client.chat.completions.create(), client.models.list(),
    // etc.
    this.chat = {
      completions: {
        create: this.createChatCompletion.bind(this),
      },
    };
    this.models = { list: this.listModels.bind(this) };
    this.audit = { read: this.readAudit.bind(this) };
    this.keys = { rotate: this.rotateKey.bind(this) };
  }

  protected async createChatCompletion(
    params: ChatCompletionCreateParams,
    opts: RequestOptions = {},
  ): Promise<ChatCompletion> {
    return this.request<ChatCompletion>({
      method: 'POST',
      path: '/v1/chat/completions',
      body: params,
      opts,
    });
  }

  protected async listModels(opts: RequestOptions = {}): Promise<ModelsList> {
    return this.request<ModelsList>({
      method: 'GET',
      path: '/v1/models',
      opts,
    });
  }

  protected async readAudit(
    params: AuditReadParams = {},
    opts: RequestOptions = {},
  ): Promise<AuditReadResponse> {
    const q: string[] = [];
    if (typeof params.sinceMs === 'number') q.push(`since=${encodeURIComponent(String(params.sinceMs))}`);
    if (typeof params.limit === 'number') q.push(`limit=${encodeURIComponent(String(params.limit))}`);
    if (typeof params.appId === 'string') q.push(`app_id=${encodeURIComponent(params.appId)}`);
    const path = '/v1/audit' + (q.length > 0 ? `?${q.join('&')}` : '');
    return this.request<AuditReadResponse>({
      method: 'GET',
      path,
      opts,
    });
  }

  protected async rotateKey(opts: RequestOptions = {}): Promise<RotateResponse> {
    return this.request<RotateResponse>({
      method: 'POST',
      path: '/v1/keys/rotate',
      // Server doesn't read a body but accepts the route, so we send
      // an empty object for content-length sanity.
      body: {},
      opts,
    });
  }

  // Build the Authorization header for a single request. Overridable in
  // subclasses (the ed25519 follow-up swaps to a signed scheme).
  protected authorizationHeader(_method: string, _path: string, _bodyBytes: Buffer | null): string {
    return `Bearer ${this.apiKey}`;
  }

  protected async request<T>(args: {
    method: string;
    path: string;
    body?: unknown;
    opts: RequestOptions;
  }): Promise<T> {
    const url = this.baseUrl + args.path;
    const bodyBytes: Buffer | null = args.body !== undefined
      ? Buffer.from(JSON.stringify(args.body), 'utf8')
      : null;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'cogos-node/0.1.0',
      ...(args.opts.headers ?? {}),
    };
    headers['Authorization'] = this.authorizationHeader(args.method, args.path, bodyBytes);
    if (bodyBytes) headers['Content-Length'] = String(bodyBytes.length);

    const resp = await rawRequest({
      method: args.method,
      url,
      headers,
      body: bodyBytes,
      timeoutMs: args.opts.timeoutMs ?? this.defaultTimeoutMs,
    });
    const requestId = resp.headers['x-cogos-request-id'] || null;
    const retryAfterRaw = resp.headers['retry-after'];
    const retryAfter = retryAfterRaw ? Number(retryAfterRaw) : null;

    // Parse JSON eagerly; on parse failure the body remains a string for
    // the error to surface.
    let parsed: unknown = null;
    let parseFailed = false;
    if (resp.body.length > 0) {
      try {
        parsed = JSON.parse(resp.body.toString('utf8'));
      } catch {
        parseFailed = true;
        parsed = resp.body.toString('utf8');
      }
    }

    if (resp.status < 200 || resp.status >= 300) {
      throw mapErrorFromResponse(resp.status, parsed, requestId, retryAfter);
    }
    if (parseFailed) {
      throw new ServerError('non-JSON response body', {
        status: resp.status,
        body: parsed,
        requestId,
      });
    }

    // HMAC verification — only when the caller supplied a secret and
    // didn't opt out for this call.
    const wantHmac = (args.opts.verifyHmac ?? true) && this.hmacSecret !== null;
    if (wantHmac) {
      const sig = resp.headers['x-cogos-signature'];
      if (!sig) {
        throw new SignatureMismatchError('X-Cogos-Signature header missing', {
          body: parsed,
          requestId,
        });
      }
      if (!verifyHmac(this.hmacSecret as string, resp.body, sig)) {
        throw new SignatureMismatchError('HMAC signature did not verify', {
          body: parsed,
          requestId,
        });
      }
    }

    // Attestation verification — on by default.
    const wantAttest = args.opts.verifyAttestation ?? this.verifyAttestationDefault;
    if (wantAttest) {
      const token = resp.headers['x-cogos-attestation'];
      if (!token) {
        throw new AttestationMismatchError('X-Cogos-Attestation header missing', {
          body: parsed,
          requestId,
        });
      }
      const pub = await this.getAttestationPubkey(args.opts.timeoutMs ?? this.defaultTimeoutMs);
      try {
        verifyAttestation(token, pub, resp.body);
      } catch (e) {
        throw new AttestationMismatchError(
          `attestation verification failed: ${(e as Error).message}`,
          { body: parsed, requestId },
        );
      }
    }

    return parsed as T;
  }

  // Fetch /attestation.pub. Cached after first fetch; clear via reinit.
  protected async getAttestationPubkey(timeoutMs: number): Promise<string> {
    if (this.cachedAttestationPubPem) return this.cachedAttestationPubPem;
    const resp = await rawRequest({
      method: 'GET',
      url: this.baseUrl + '/attestation.pub',
      headers: { 'Accept': 'application/x-pem-file' },
      timeoutMs,
    });
    if (resp.status < 200 || resp.status >= 300) {
      throw new AttestationMismatchError(
        `could not fetch /attestation.pub (status ${resp.status})`,
        { body: resp.body.toString('utf8') },
      );
    }
    const pem = resp.body.toString('utf8');
    if (!/BEGIN PUBLIC KEY/.test(pem)) {
      throw new AttestationMismatchError(
        '/attestation.pub did not return a PEM',
        { body: pem },
      );
    }
    this.cachedAttestationPubPem = pem;
    return pem;
  }
}
