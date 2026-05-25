'use strict';

/**
 * IOLTA Reconciler — vendored from 5ceos-platform-internal.
 *
 * VENDORED COPY · source of truth lives at:
 *   5ceos-platform-internal/backend/services/5law/trustReconciler.cjs
 *
 * Pure-function module, no platform-side dependencies. Vendored (not
 * cross-network proxied) so the cogos-api Process Library v0.1 endpoint
 * runs with one auth boundary (sk-cogos-* on Azure) and zero RPC latency.
 * If upstream changes, re-vendor; never edit in place — fix upstream
 * and re-copy.
 *
 * 5law IOLTA Reconciler v0.1
 *
 * Implements L4 of docs/5LAW_DOCTRINE_v0.1.md (locked 90a632d6b).
 *
 * Pure-function deterministic three-way reconciler over a single trust
 * account. No I/O, no LLM. Caller supplies the bank balance, trust
 * ledger rows, and client sub-ledger rows; engine returns the
 * reconciliation state machine.
 *
 * THREE-WAY INVARIANT (doctrine L4 HARD REQUIREMENT):
 *   bank_balance_cents
 *     == trust_ledger_total_cents
 *     == sum(per_client_sub_ledger_balances)
 *   to the cent, at every period close. Any divergence blocks further
 *   trust transactions.
 *
 * COMMINGLING GUARD (doctrine L4 substrate-level):
 *   Per-client sub-ledger balance MUST NEVER go negative. A negative
 *   balance is the canonical "commingling of firm funds with client
 *   funds" failure mode (per-se ABA Rule 1.15 violation; license-revoke
 *   territory in most states). canPostTransaction() pre-write check
 *   returns block_reason for any proposed transaction that would push a
 *   sub-ledger negative.
 *
 * SCHEMA BINDING (per 20260514_5law_v0_1_schemas.sql):
 *   - law_trust_ledger_row.side          ∈ {debit, credit}
 *   - law_client_sub_ledger_row.side     ∈ {debit, credit}
 *   - both ledger row tables: amount_cents > 0 (CHECK)
 *   - law_client_sub_ledger_row.balance_after_cents >= 0 (CHECK at substrate)
 *   - law_three_way_reconciliation_record: balanced via CHECK at substrate;
 *     signature_role MUST = 'trust_officer' per CHECK.
 *
 * ACCOUNTING CONVENTION:
 *   In trust accounting, the trust account itself is a liability of the
 *   firm to its clients. Conventions vary by software; we adopt the
 *   simplest reading for substrate purposes:
 *     - 'credit' (to the trust account) = funds INTO the account (retainer
 *        received, etc.); increases bank balance.
 *     - 'debit'  (from the trust account) = funds OUT of the account
 *        (disbursement, fee transfer out); decreases bank balance.
 *   Net trust ledger balance = sum(credits) - sum(debits).
 *   Same sign convention applies to the per-client sub-ledger.
 *
 * No LLM in any path. Doctrine §L4.
 */

const RECONCILER_VERSION = 1;

const DIVERGENCE_KIND = Object.freeze({
  BANK_VS_TRUST_LEDGER:        'bank_vs_trust_ledger',
  TRUST_LEDGER_VS_SUB_LEDGER:  'trust_ledger_vs_sub_ledger',
  BANK_VS_SUB_LEDGER:          'bank_vs_sub_ledger',
  COMMINGLING_NEGATIVE_CLIENT: 'commingling_negative_client'
});

const BLOCK_REASON = Object.freeze({
  RECONCILIATION_FAILED:       'reconciliation_failed',
  COMMINGLING:                 'commingling_block',
  ACCOUNT_RECONCILIATION_LOCK: 'account_reconciliation_blocked'
});

const SIDE = Object.freeze({ DEBIT: 'debit', CREDIT: 'credit' });

// ────────────────────────────────────────────────────────────────────
// Pure summation helpers
// ────────────────────────────────────────────────────────────────────

function sumLedgerNet(rows) {
  let credits = 0;
  let debits = 0;
  for (const r of rows || []) {
    const amt = Number(r.amount_cents);
    if (!Number.isInteger(amt) || amt < 0) {
      throw new TypeError(`amount_cents must be a non-negative integer, got ${r.amount_cents}`);
    }
    if (r.side === SIDE.CREDIT)      credits += amt;
    else if (r.side === SIDE.DEBIT)  debits  += amt;
    else throw new TypeError(`row.side must be 'debit' or 'credit', got ${JSON.stringify(r.side)}`);
  }
  return { credits, debits, net: credits - debits };
}

function computePerClientBalances(subLedgerRows) {
  const balances = Object.create(null);
  for (const r of subLedgerRows || []) {
    const client = r.client_contact_id;
    if (client == null) throw new TypeError('client_contact_id required on each sub-ledger row');
    if (!(client in balances)) balances[client] = 0;
    const amt = Number(r.amount_cents);
    if (!Number.isInteger(amt) || amt < 0) {
      throw new TypeError(`amount_cents must be a non-negative integer, got ${r.amount_cents}`);
    }
    if (r.side === SIDE.CREDIT)      balances[client] += amt;
    else if (r.side === SIDE.DEBIT)  balances[client] -= amt;
    else throw new TypeError(`row.side must be 'debit' or 'credit', got ${JSON.stringify(r.side)}`);
  }
  return balances;
}

function sumBalances(balanceMap) {
  let total = 0;
  for (const v of Object.values(balanceMap)) total += v;
  return total;
}

function commingledClients(balanceMap) {
  const out = [];
  for (const [client, balance] of Object.entries(balanceMap)) {
    if (balance < 0) out.push({ client_contact_id: client, balance_cents: balance });
  }
  return out;
}

// ────────────────────────────────────────────────────────────────────
// Main: reconcileThreeWay(input) → ReconciliationResult
// ────────────────────────────────────────────────────────────────────

/**
 * @param {object} input
 * @param {number} input.bank_balance_cents          authoritative bank-statement balance (integer cents)
 * @param {Array}  input.trust_ledger_rows           law_trust_ledger_row shape
 * @param {Array}  input.client_sub_ledger_rows      law_client_sub_ledger_row shape
 * @param {string} [input.as_of_date]                ISO date for the reconciliation snapshot
 * @returns {object} ReconciliationResult
 */
function reconcileThreeWay(input) {
  if (!input || typeof input !== 'object') {
    throw new TypeError('reconcileThreeWay: input object is required');
  }
  if (!Number.isInteger(input.bank_balance_cents)) {
    throw new TypeError('bank_balance_cents must be an integer (cents)');
  }

  const bank = input.bank_balance_cents;
  const trustLedger = sumLedgerNet(input.trust_ledger_rows || []);
  const trust_ledger_total_cents = trustLedger.net;

  const per_client_balances = computePerClientBalances(input.client_sub_ledger_rows || []);
  const sub_ledger_total_cents = sumBalances(per_client_balances);

  const divergences = [];
  if (bank !== trust_ledger_total_cents) {
    divergences.push({
      kind: DIVERGENCE_KIND.BANK_VS_TRUST_LEDGER,
      expected_cents: bank,
      actual_cents: trust_ledger_total_cents,
      delta_cents: trust_ledger_total_cents - bank
    });
  }
  if (trust_ledger_total_cents !== sub_ledger_total_cents) {
    divergences.push({
      kind: DIVERGENCE_KIND.TRUST_LEDGER_VS_SUB_LEDGER,
      expected_cents: trust_ledger_total_cents,
      actual_cents: sub_ledger_total_cents,
      delta_cents: sub_ledger_total_cents - trust_ledger_total_cents
    });
  }
  if (bank !== sub_ledger_total_cents) {
    divergences.push({
      kind: DIVERGENCE_KIND.BANK_VS_SUB_LEDGER,
      expected_cents: bank,
      actual_cents: sub_ledger_total_cents,
      delta_cents: sub_ledger_total_cents - bank
    });
  }

  const commingling = commingledClients(per_client_balances);
  for (const c of commingling) {
    divergences.push({
      kind: DIVERGENCE_KIND.COMMINGLING_NEGATIVE_CLIENT,
      client_contact_id: c.client_contact_id,
      balance_cents: c.balance_cents
    });
  }

  const three_way_match = (
    bank === trust_ledger_total_cents
    && trust_ledger_total_cents === sub_ledger_total_cents
  );

  // can_close_period: three-way matches AND no commingled clients.
  // (The matter has no claim to negative balance even when the three
  //  aggregates agree — the per-client invariant is independent.)
  const can_close_period = three_way_match && commingling.length === 0;

  let block_reason = null;
  if (commingling.length > 0) block_reason = BLOCK_REASON.COMMINGLING;
  else if (!three_way_match)  block_reason = BLOCK_REASON.RECONCILIATION_FAILED;

  return {
    reconciler_version:           RECONCILER_VERSION,
    as_of_date:                   input.as_of_date || null,
    bank_balance_cents:           bank,
    trust_ledger_total_cents,
    sub_ledger_total_cents,
    per_client_balances,
    three_way_match,
    divergences,
    commingling_violations:       commingling,
    can_close_period,
    block_reason
  };
}

// ────────────────────────────────────────────────────────────────────
// canPostTransaction — pre-write substrate guard
// Called by the trust-posting service before any law_trust_transaction
// insert. If it returns block_reason ≠ null, the service must reject.
// ────────────────────────────────────────────────────────────────────

/**
 * @param {object} input
 * @param {object} input.trust_account                       law_trust_account row
 * @param {object} input.per_client_balances_before          { [client_id]: balance_cents }
 * @param {object} input.proposed_transaction                { client_contact_id, side, amount_cents, transaction_type }
 * @returns {object} { can_post: boolean, block_reason: string|null, projected_balance_cents: number|null }
 */
function canPostTransaction(input) {
  if (!input || !input.trust_account || !input.proposed_transaction) {
    throw new TypeError('canPostTransaction: trust_account + proposed_transaction required');
  }
  const acct = input.trust_account;
  const tx = input.proposed_transaction;
  const balances = input.per_client_balances_before || {};

  if (acct.reconciliation_blocked === true) {
    return {
      can_post: false,
      block_reason: BLOCK_REASON.ACCOUNT_RECONCILIATION_LOCK,
      projected_balance_cents: null
    };
  }

  if (!tx.client_contact_id) {
    throw new TypeError('proposed_transaction.client_contact_id required');
  }
  if (!Number.isInteger(tx.amount_cents) || tx.amount_cents <= 0) {
    throw new TypeError('proposed_transaction.amount_cents must be a positive integer');
  }
  if (tx.side !== SIDE.DEBIT && tx.side !== SIDE.CREDIT) {
    throw new TypeError(`proposed_transaction.side must be 'debit' or 'credit'`);
  }

  const current = balances[tx.client_contact_id] || 0;
  const projected = tx.side === SIDE.CREDIT
    ? current + tx.amount_cents
    : current - tx.amount_cents;

  if (projected < 0) {
    return {
      can_post: false,
      block_reason: BLOCK_REASON.COMMINGLING,
      projected_balance_cents: projected
    };
  }

  return {
    can_post: true,
    block_reason: null,
    projected_balance_cents: projected
  };
}

// ────────────────────────────────────────────────────────────────────
// canSignPeriodClose — period close eligibility check
// Combines reconcileThreeWay result with the signer's role requirement.
// Doctrine L4 + schema CHECK: signature_role MUST = 'trust_officer'.
// ────────────────────────────────────────────────────────────────────

/**
 * @param {object} input
 * @param {object} input.reconciliation_result  output of reconcileThreeWay
 * @param {string} input.signer_role            law_user_role_kind value
 * @returns {object} { can_sign: boolean, block_reason: string|null }
 */
function canSignPeriodClose(input) {
  if (!input || !input.reconciliation_result) {
    throw new TypeError('canSignPeriodClose: reconciliation_result required');
  }
  const rec = input.reconciliation_result;
  if (input.signer_role !== 'trust_officer') {
    return {
      can_sign: false,
      block_reason: 'signer_role_must_be_trust_officer'
    };
  }
  if (!rec.can_close_period) {
    return {
      can_sign: false,
      block_reason: rec.block_reason || BLOCK_REASON.RECONCILIATION_FAILED
    };
  }
  return { can_sign: true, block_reason: null };
}

module.exports = {
  // main
  reconcileThreeWay,
  canPostTransaction,
  canSignPeriodClose,

  // pure helpers (exported for tests + targeted use)
  sumLedgerNet,
  computePerClientBalances,
  sumBalances,
  commingledClients,

  // constants
  RECONCILER_VERSION,
  DIVERGENCE_KIND,
  BLOCK_REASON,
  SIDE
};
