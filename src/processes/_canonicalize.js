'use strict';

/**
 * Substrate canonicalization · the bitwise-stable serialization primitive.
 *
 * This module exists to honor Canon I1 v0.2 (Substrate Canon v0.2,
 * commit 44e44ee07): for a fixed engine version, the same canonical
 * input must produce the same canonical output AND the same output
 * hash. v0.1 of the Process Library hashed input only (because output
 * key-iteration order was unstable). v0.2 closes that gap by routing
 * every engine output through this canonicalizer before it ships in
 * the response body, and through sha256() before it ships in the
 * receipt's `output_hash` field.
 *
 * What this module does:
 *   1. canonicalize(value) — returns a structurally identical value
 *      with object keys sorted at every level. Arrays preserve order
 *      (semantically meaningful). Undefined fields dropped. Numeric
 *      values normalized to remove float-format ambiguity (-0 → 0,
 *      JSON-incompatible NaN/Infinity rejected with TypeError).
 *
 *   2. canonicalBytes(value) — returns the canonical JSON byte string
 *      that an engine output reduces to. JSON.stringify on the
 *      canonicalized value with no spacing or extra whitespace. This
 *      is the input to the output hash.
 *
 *   3. canonicalHash(value) — sha256 of the canonical bytes, formatted
 *      as 'sha256:<64-char hex>'. This is what ships in the receipt.
 *
 *   4. sortRowsBy(rows, keyList) — engine-output helper for arrays of
 *      "row" objects where the engine's natural iteration order is
 *      not deterministic (e.g. Object.values iteration, set
 *      operations). Engines call this BEFORE returning to guarantee
 *      output stability across calls. keyList is the sort precedence;
 *      each key is compared as JSON-canonical strings.
 *
 * What this module does NOT do:
 *   - Schema validation. The engine is responsible for emitting only
 *     valid data shapes. canonicalize() will accept any JSON-shaped
 *     value and stabilize it.
 *   - LLM-anything. This is the deterministic substrate; no model in
 *     the path.
 *
 * Determinism contract (verified by tests/substrate-canonicalize.test.js):
 *   For all JSON-shaped values v:
 *     canonicalBytes(canonicalize(v)) === canonicalBytes(v)
 *     canonicalHash(v1) === canonicalHash(v2)
 *       whenever canonicalBytes(v1) === canonicalBytes(v2)
 *   Idempotence:
 *     canonicalize(canonicalize(v)) deepEquals canonicalize(v)
 */

const crypto = require('node:crypto');

function canonicalize(value) {
  if (value === null) return null;
  if (value === undefined) return undefined;  // caller filters at object level
  const t = typeof value;
  if (t === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`canonicalize: non-finite number (${value}) cannot be canonicalized`);
    }
    // Normalize -0 to 0 so the hash doesn't depend on sign of zero.
    return value === 0 ? 0 : value;
  }
  if (t === 'string' || t === 'boolean') return value;
  if (t === 'bigint') {
    throw new TypeError('canonicalize: bigint cannot be canonicalized (engines emit numbers, not bigints)');
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    const out = {};
    for (const k of keys) {
      const c = canonicalize(value[k]);
      if (c === undefined) continue;
      out[k] = c;
    }
    return out;
  }
  throw new TypeError(`canonicalize: unsupported value type (${t})`);
}

function canonicalBytes(value) {
  return JSON.stringify(canonicalize(value));
}

function canonicalHash(value) {
  const bytes = canonicalBytes(value);
  return 'sha256:' + crypto.createHash('sha256').update(bytes).digest('hex');
}

/**
 * Compare two values as canonical JSON strings · lexicographic on the
 * canonical-bytes serialization. Returns -1/0/1 like Array.sort.
 */
function compareCanonical(a, b) {
  const sa = canonicalBytes(a);
  const sb = canonicalBytes(b);
  if (sa < sb) return -1;
  if (sa > sb) return 1;
  return 0;
}

/**
 * Sort an array of row objects by the supplied list of keys, in
 * precedence order. Each key is compared as canonical-bytes. Engines
 * call this BEFORE returning when their natural iteration order is
 * not deterministic (Object.values, Set iteration, multiple-source
 * concat, etc.).
 *
 * Example: detectConflicts emits rows from 5 detector functions
 * concatenated. The order across detectors is fixed by code, but the
 * order WITHIN each detector depends on input party order. Calling
 * sortRowsBy(rows, ['rule_id', 'conflicting_matter_id', 'parties_involved'])
 * guarantees a stable canonical row order regardless of input
 * ordering.
 */
function sortRowsBy(rows, keyList) {
  if (!Array.isArray(rows)) {
    throw new TypeError('sortRowsBy: rows must be an array');
  }
  if (!Array.isArray(keyList) || keyList.length === 0) {
    throw new TypeError('sortRowsBy: keyList must be a non-empty array');
  }
  const copy = rows.slice();
  copy.sort((a, b) => {
    for (const k of keyList) {
      const c = compareCanonical(a == null ? null : a[k], b == null ? null : b[k]);
      if (c !== 0) return c;
    }
    return 0;
  });
  return copy;
}

module.exports = {
  canonicalize,
  canonicalBytes,
  canonicalHash,
  compareCanonical,
  sortRowsBy,
};
