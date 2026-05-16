// Public entry-point for the cogos Node SDK.
//
// Quick start:
//   import { Cogos } from 'cogos';
//   const client = new Cogos({ apiKey: process.env.COGOS_API_KEY!, hmacSecret: process.env.COGOS_HMAC_SECRET });
//   const r = await client.chat.completions.create({
//     messages: [{ role: 'user', content: 'hello' }],
//     model: 'cogos-tier-b',
//   });
//   console.log(r.choices[0].message.content);

export { Cogos } from './client';
export type { CogosClientOptions } from './client';

export { Ed25519Signer } from './ed25519';
export type { SignRequestParams } from './ed25519';

export { unsealAuditRow } from './unseal';
export type { UnsealedContent } from './unseal';

export { verifyHmac, computeHmac } from './hmac';
export { verifyAttestation, decodeAttestation, sha256Hex } from './attestation';
export type { AttestationPayload } from './attestation';

export {
  CogosError,
  AuthError,
  RateLimitError,
  DailyQuotaError,
  SignatureMismatchError,
  AttestationMismatchError,
  ServerError,
} from './errors';

export type {
  ChatRole,
  ChatMessage,
  JsonSchemaResponseFormat,
  ResponseFormat,
  ChatCompletionCreateParams,
  ChatCompletionChoice,
  ChatCompletionUsage,
  ChatCompletion,
  ModelDescriptor,
  ModelsList,
  SealedEnvelope,
  AuditRow,
  AuditReadParams,
  AuditReadResponse,
  RotateResponseBase,
  RotateResponseBearer,
  RotateResponseEd25519,
  RotateResponse,
  RequestOptions,
} from './types';
