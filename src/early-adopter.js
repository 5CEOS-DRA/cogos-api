'use strict';

// Early-adopter signal — fires a one-shot operator notification when a
// tenant makes its FIRST authenticated /v1/chat/completions call.
//
// Why: distribution channels (HN post, cookbook link, devblog) all funnel
// to /signup/free → key issued. The signup itself is a weak signal — a
// dev might paste their key into a notes app and never call. The first
// real chat completion is when the dev actually integrated. Operator
// hears about it immediately so they can manually reach out (no-sales
// doctrine: this is relationship, not pitch).
//
// Mechanism:
//   - Per-process in-memory Set of key_ids we've already notified about
//     this session — prevents duplicate fires on every subsequent call.
//   - On first observed call for a key, atomically stamp first_call_at
//     on the key record (keys.markFirstCallAt). If the stamp was already
//     set on disk (e.g. another replica beat us, or a prior process
//     stamped before restart), we record the cache hydration without
//     firing a notification.
//   - SES email send is fire-and-forget — chat-completion latency is
//     never blocked on the notification.
//
// Multi-replica caveat: in-memory dedup is per-process. If two replicas
// observe the first call from the same key in the same millisecond, both
// will attempt to stamp first_call_at — keys.markFirstCallAt's
// read-then-write returns the prior value so only ONE will see "this is
// new" semantics. The losing replica gets the already-set timestamp
// back and suppresses the notification. Race-safe modulo last-write-
// wins on the keys.json file (acceptable at current scale; revisit when
// keys.json moves off the filesystem).

const logger = require('./logger');
const keys = require('./keys');
const notifySignup = require('./notify-signup');

// In-memory dedup — reset on process restart, hydrated lazily.
const _notifiedKeyIds = new Set();

function _resetForTest() {
  _notifiedKeyIds.clear();
}

// Compose the operator email body. Kept narrow — operator needs to know
// which tenant + when + what tier + what model. Anything more is in the
// dashboard / /v1/audit slice.
function _renderBody({ keyRecord, model, ts }) {
  return [
    `New tenant just made their FIRST /v1/chat/completions call.`,
    ``,
    `tenant_id:   ${keyRecord.tenant_id}`,
    `key_id:      ${keyRecord.id}`,
    `tier:        ${keyRecord.tier || 'unknown'}`,
    `package_id:  ${keyRecord.package_id || 'unknown'}`,
    `label:       ${keyRecord.label || '(none)'}`,
    `model:       ${model || '(unspecified)'}`,
    `issued_at:   ${keyRecord.issued_at || '(unknown)'}`,
    `first_call:  ${ts}`,
    ``,
    `Dashboard:   https://cogos.5ceos.com/dashboard`,
    `Audit slice: GET /admin/usage?since=${Date.parse(ts) - 60000}`,
  ].join('\n');
}

// Single entry point. Called from chat-api.js handleChatCompletions
// AFTER usage.record() returns successfully (i.e. the call actually
// landed in the audit chain — we don't notify on failed-validation
// attempts that never write a usage row).
//
// keyRecord must carry id + tenant_id at minimum. model is optional.
// Returns true if this call fired a notification (test-observable).
function noteCall(keyRecord, model) {
  if (!keyRecord || !keyRecord.id) return false;
  if (_notifiedKeyIds.has(keyRecord.id)) return false;

  const isoTs = new Date().toISOString();
  const prevStamp = keys.markFirstCallAt(keyRecord.id, isoTs);
  _notifiedKeyIds.add(keyRecord.id);

  // prevStamp truthy → first_call_at was ALREADY set on disk. Either
  // another replica beat us, or this process restarted after stamping
  // a prior call. Either way, the notification already fired once;
  // suppress.
  if (prevStamp) {
    logger.info('early_adopter_already_stamped', {
      key_id: keyRecord.id,
      tenant_id: keyRecord.tenant_id,
      prior_first_call_at: prevStamp,
    });
    return false;
  }

  // Fire-and-forget. Latency budget on the chat-completion hot path is
  // tight; we'd rather lose a notification than slow a paying customer.
  const subject = `[cogos] first-call: ${keyRecord.tenant_id}`;
  const body = _renderBody({ keyRecord, model, ts: isoTs });
  notifySignup.sendOperatorEmail({ subject, body }).then((r) => {
    if (r.sent) {
      logger.info('early_adopter_notify_sent', {
        tenant_id: keyRecord.tenant_id,
        key_id: keyRecord.id,
        transport: r.transport,
      });
    } else {
      logger.warn('early_adopter_notify_skipped', {
        tenant_id: keyRecord.tenant_id,
        key_id: keyRecord.id,
        reason: r.reason,
      });
    }
  }).catch((e) => {
    logger.warn('early_adopter_notify_error', {
      tenant_id: keyRecord.tenant_id,
      key_id: keyRecord.id,
      error: e.message,
    });
  });

  return true;
}

module.exports = {
  noteCall,
  _resetForTest,
};
