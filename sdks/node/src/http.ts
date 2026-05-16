// Minimal HTTPS/HTTP transport built on Node stdlib only.
//
// Why not fetch? Two reasons:
//   1. We need the EXACT response body bytes (Buffer) to feed into HMAC
//      verification and resp_hash recomputation. fetch's Response.text()
//      decodes UTF-8 for us and we cannot ask it to hand back the raw
//      bytes pre-decoding without resorting to .arrayBuffer() + manual
//      handling — which is fine in modern Node, but stdlib http already
//      gives us Buffers natively, so we stay there.
//   2. Smaller surface, no Node 22 / undici quirks in fetch.

import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { URL } from 'node:url';

export interface RawResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

export interface RawRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Buffer | null;
  timeoutMs: number;
}

// Issue an HTTP(S) request, returning the raw response body bytes
// alongside the status + headers. Bytes-in-bytes-out — no JSON parse,
// no UTF-8 decode. The caller decides what to do with the body.
export function rawRequest(req: RawRequest): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try {
      u = new URL(req.url);
    } catch (e) {
      reject(new Error(`invalid URL: ${req.url}`));
      return;
    }
    const isHttps = u.protocol === 'https:';
    const reqFn = isHttps ? httpsRequest : httpRequest;
    const opts = {
      method: req.method,
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      headers: req.headers,
      timeout: req.timeoutMs,
    };
    const r = reqFn(opts, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (Array.isArray(v)) headers[k.toLowerCase()] = v.join(', ');
          else if (typeof v === 'string') headers[k.toLowerCase()] = v;
        }
        resolve({
          status: res.statusCode ?? 0,
          headers,
          body: Buffer.concat(chunks),
        });
      });
      res.on('error', (e) => reject(e));
    });
    r.on('error', (e) => reject(e));
    r.on('timeout', () => {
      r.destroy(new Error(`request timeout after ${req.timeoutMs}ms`));
    });
    if (req.body) r.write(req.body);
    r.end();
  });
}
