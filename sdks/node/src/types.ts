// Wire-shape types for cogos-api responses.
//
// These mirror what the gateway returns on /v1/chat/completions,
// /v1/models, /v1/audit, and /v1/keys/rotate. Treat them as the public
// contract; the gateway's response shape moves forward additively.

export type ChatRole = 'system' | 'user' | 'assistant';

export interface ChatMessage {
  role: ChatRole;
  content: string;
}

// json_schema response_format. Matches OpenAI's `response_format` shape
// so customers can paste a schema they already have.
export interface JsonSchemaResponseFormat {
  type: 'json_schema';
  json_schema: {
    name: string;
    strict?: boolean;
    schema: Record<string, unknown>;
  };
}

export type ResponseFormat = JsonSchemaResponseFormat;

export interface ChatCompletionCreateParams {
  messages: ChatMessage[];
  model?: string;
  temperature?: number;
  max_tokens?: number;
  seed?: number;
  response_format?: ResponseFormat;
}

export interface ChatCompletionChoice {
  index: number;
  message: ChatMessage;
  finish_reason: string;
}

export interface ChatCompletionUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatCompletion {
  id: string;
  object: 'chat.completion';
  created: number;
  model: string;
  choices: ChatCompletionChoice[];
  usage: ChatCompletionUsage;
  cogos?: {
    schema_enforced?: boolean;
    latency_ms?: number;
    request_id?: string;
  };
}

export interface ModelDescriptor {
  id: string;
  object: 'model';
  created: number;
  owned_by: string;
  cogos_resolves_to?: string;
}

export interface ModelsList {
  object: 'list';
  data: ModelDescriptor[];
}

// /v1/audit row. Most fields the gateway emits cleartext; sealed_content
// rides alongside when the customer's key was issued ed25519 + holds an
// x25519 sealing pubkey on the gateway side. Unsealable via
// unsealAuditRow().
export interface SealedEnvelope {
  v: 1;
  alg: 'x25519-hkdf-aes-256-gcm';
  ciphertext_b64: string;
  nonce_b64: string;
  ephemeral_pub_b64: string;
  tag_b64: string;
}

export interface AuditRow {
  ts: string;
  tenant_id: string;
  app_id: string;
  key_id?: string;
  model?: string;
  status?: string;
  prompt_tokens?: number;
  completion_tokens?: number;
  latency_ms?: number;
  schema_enforced?: boolean;
  prev_hash?: string;
  row_hash?: string;
  // Cleartext when sealed !== true.
  request_id?: string;
  prompt_fingerprint?: string;
  schema_name?: string;
  // Set to true when sealed_content carries the content fields.
  sealed?: boolean;
  sealed_content?: SealedEnvelope;
  [extra: string]: unknown;
}

export interface AuditReadParams {
  sinceMs?: number;
  limit?: number;
  appId?: string;
}

export interface AuditReadResponse {
  rows: AuditRow[];
  next_cursor: number | null;
  chain_ok: boolean;
  chain_break: null | {
    app_id?: string;
    broke_at_index: number;
    reason: string;
  };
  chain_ok_by_app: Record<string, boolean>;
  app_id: string | null;
  server_time_ms: number;
}

// Rotate response. Two variants — bearer or ed25519 — collapsed under one
// type so the caller can branch on `scheme`.
export interface RotateResponseBase {
  key_id: string;
  tenant_id: string;
  app_id: string;
  tier: string;
  issued_at: string;
  expires_at: string | null;
  rotated_from_key_id: string;
  rotation_grace_until: string;
  hmac_secret: string;
  warning: string;
}

export interface RotateResponseBearer extends RotateResponseBase {
  scheme: 'bearer';
  api_key: string;
}

export interface RotateResponseEd25519 extends RotateResponseBase {
  scheme: 'ed25519';
  ed25519_key_id: string;
  private_pem: string;
  pubkey_pem: string;
  x25519_private_pem: string;
  x25519_pubkey_pem: string;
}

export type RotateResponse = RotateResponseBearer | RotateResponseEd25519;

// Per-call options that override the client-level defaults.
export interface RequestOptions {
  verifyHmac?: boolean;
  verifyAttestation?: boolean;
  timeoutMs?: number;
  headers?: Record<string, string>;
}
