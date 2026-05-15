'use strict';

// Package (subscription tier) registry.
//
// A "package" is a customer-facing plan: a name, a monthly USD price, a
// monthly request quota, and the set of model tiers it grants access to.
// Stripe Products + Prices are synced 1:1 when a Stripe secret key is
// configured; without one, packages are local-only (dev/stub mode).
//
// Storage: data/packages.json — same write-on-mutation pattern as keys.json.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const logger = require('./logger');

const PACKAGES_FILE = process.env.PACKAGES_FILE
  || path.join(__dirname, '..', 'data', 'packages.json');

// The two locked model tiers the gateway resolves today.
// Keep in sync with chat-api.js TIER_TO_MODEL keys.
const KNOWN_TIERS = ['cogos-tier-a', 'cogos-tier-b'];

// Default package seeded on first run — gives the gateway something
// sensible to enforce against before the operator creates anything.
const DEFAULT_PACKAGE = {
  id: 'starter',
  display_name: 'Operator Starter',
  description: '100,000 schema-locked requests per month on Tier-B (classification-shaped workloads).',
  monthly_usd: 25,
  monthly_request_quota: 100000,
  allowed_model_tiers: ['cogos-tier-b'],
  active: true,
  is_default: true,
};

// Free-tier package — seeded alongside DEFAULT_PACKAGE on first run.
// `public_signup: true` is the gate that POST /signup/free reads to decide
// whether to mint a no-Stripe key for an unauthenticated visitor. Removing
// public_signup (or flipping it to false) kills the free signup route
// without touching code — operator policy, not code policy.
//
// Quota numbers (3000/mo, plus the daily_* caps the companion daily-caps
// agent enforces) match the Free tier on the landing page. Tier-B only —
// frontier-narrative workloads stay on paid tiers.
const FREE_PACKAGE = {
  id: 'free',
  display_name: 'Free',
  description: 'Free tier — 100 requests/day, 1000 fallback tokens/day, Tier B (3B) only. No card required.',
  monthly_usd: 0,
  monthly_request_quota: 3000,
  allowed_model_tiers: ['cogos-tier-b'],
  active: true,
  is_default: false,
  public_signup: true,
  // The next four fields are owned by the companion daily-caps agent's
  // enforcement code (src/chat-api.js + src/daily-cap.js). Persisting them
  // here is forward-compat: the field shape is locked in the task spec,
  // and writing them out of an authoritative seed prevents a "free package
  // exists but daily caps unset" half-state if the companion's branch
  // hasn't landed yet. The fields are passive data until the companion's
  // middleware reads them.
  daily_request_cap: 100,
  daily_fallback_token_cap: 1000,
  tier: 'cogos-tier-b',
  price_cents_monthly: 0,
  request_budget: 3000,
};

// ---------------------------------------------------------------------------
// Storage primitives
// ---------------------------------------------------------------------------

function ensureStore() {
  const dir = path.dirname(PACKAGES_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(PACKAGES_FILE)) {
    fs.writeFileSync(PACKAGES_FILE, JSON.stringify([]), { mode: 0o600 });
  }
}

function readAll() {
  ensureStore();
  return JSON.parse(fs.readFileSync(PACKAGES_FILE, 'utf8'));
}

function writeAll(records) {
  fs.writeFileSync(PACKAGES_FILE, JSON.stringify(records, null, 2), { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Stripe stub-mode detection
//
// If STRIPE_SECRET_KEY is unset or 'stub', Stripe API calls are skipped
// and stripe_product_id / stripe_price_id are set to deterministic stub
// values. This lets the operator create + manage packages on a fresh
// deploy without ever talking to Stripe — Stripe only gets wired in
// when the operator turns on self-serve signup.
// ---------------------------------------------------------------------------
function stripeStubMode() {
  const k = process.env.STRIPE_SECRET_KEY;
  return !k || k === 'stub' || k === '';
}

function stubIds(packageId, monthlyUsd) {
  return {
    stripe_product_id: `prod_stub_${packageId}`,
    stripe_price_id: `price_stub_${packageId}_${monthlyUsd}`,
  };
}

// ---------------------------------------------------------------------------
// Stripe live-mode sync
// ---------------------------------------------------------------------------

let _stripeClient = null;
function getStripe() {
  if (_stripeClient) return _stripeClient;
  _stripeClient = require('stripe')(process.env.STRIPE_SECRET_KEY, {
    apiVersion: '2024-10-28.acacia',
  });
  return _stripeClient;
}

async function stripeSyncCreate(pkg) {
  if (stripeStubMode()) return stubIds(pkg.id, pkg.monthly_usd);
  const stripe = getStripe();
  const product = await stripe.products.create({
    name: pkg.display_name,
    description: pkg.description || undefined,
    metadata: {
      cogos_package_id: pkg.id,
      monthly_request_quota: String(pkg.monthly_request_quota),
      allowed_model_tiers: pkg.allowed_model_tiers.join(','),
    },
  });
  const price = await stripe.prices.create({
    product: product.id,
    currency: 'usd',
    unit_amount: Math.round(pkg.monthly_usd * 100),
    recurring: { interval: 'month' },
    lookup_key: `cogos_${pkg.id}`,
    metadata: { cogos_package_id: pkg.id },
  });
  return { stripe_product_id: product.id, stripe_price_id: price.id };
}

// Is this a stub-mode ID (created when Stripe wasn't configured)?
// A package created in stub mode has prod_stub_<id> / price_stub_<id>_<usd>
// values that do not exist on Stripe's side, so when we transition to
// live mode we cannot update them — we must promote the package by
// running a fresh stripeSyncCreate against the live Stripe API.
function isStubId(id) {
  if (!id) return false;
  return id.startsWith('prod_stub_') || id.startsWith('price_stub_');
}

// When monthly_usd changes, we cannot edit the existing Stripe Price —
// we must create a new one and archive the old. Stripe Products are
// editable in place. Returns the (possibly new) stripe_price_id.
async function stripeSyncUpdate(oldPkg, newPkg) {
  if (stripeStubMode()) {
    if (oldPkg.monthly_usd !== newPkg.monthly_usd) {
      return stubIds(newPkg.id, newPkg.monthly_usd);
    }
    return {
      stripe_product_id: oldPkg.stripe_product_id,
      stripe_price_id: oldPkg.stripe_price_id,
    };
  }
  // Stub-mode artifact promotion: if the previous package had stub IDs
  // (created when STRIPE_SECRET_KEY was unset), treat this update as a
  // fresh Stripe creation. Bypasses the no-such-product error from
  // stripe.products.update(prod_stub_...).
  if (isStubId(oldPkg.stripe_product_id) || isStubId(oldPkg.stripe_price_id)) {
    logger.info('package_stripe_promote_from_stub', { id: newPkg.id });
    return stripeSyncCreate(newPkg);
  }
  const stripe = getStripe();
  // Orphan-ID promotion: if oldPkg's Stripe IDs reference Products/Prices
  // that don't exist in the CURRENT Stripe environment, treat as fresh
  // create. This catches the test→live transition (test-mode IDs are
  // real and well-formed but absent from live mode) as well as
  // manually-deleted Stripe products. Generalizes the stub-mode catch.
  try {
    if (oldPkg.stripe_product_id) {
      await stripe.products.update(oldPkg.stripe_product_id, {
        name: newPkg.display_name,
        description: newPkg.description || undefined,
        metadata: {
          cogos_package_id: newPkg.id,
          monthly_request_quota: String(newPkg.monthly_request_quota),
          allowed_model_tiers: newPkg.allowed_model_tiers.join(','),
        },
      });
    }
  } catch (e) {
    if (e && (e.message || '').includes('No such')) {
      logger.info('package_stripe_promote_from_orphan', {
        id: newPkg.id,
        orphan_product_id: oldPkg.stripe_product_id,
        reason: e.message,
      });
      return stripeSyncCreate(newPkg);
    }
    throw e;
  }
  if (oldPkg.monthly_usd !== newPkg.monthly_usd && oldPkg.stripe_price_id) {
    // Stripe prices are immutable — create new, archive old.
    const newPrice = await stripe.prices.create({
      product: oldPkg.stripe_product_id,
      currency: 'usd',
      unit_amount: Math.round(newPkg.monthly_usd * 100),
      recurring: { interval: 'month' },
      lookup_key: `cogos_${newPkg.id}_${Date.now()}`,
      metadata: { cogos_package_id: newPkg.id },
    });
    await stripe.prices.update(oldPkg.stripe_price_id, { active: false });
    return {
      stripe_product_id: oldPkg.stripe_product_id,
      stripe_price_id: newPrice.id,
    };
  }
  return {
    stripe_product_id: oldPkg.stripe_product_id,
    stripe_price_id: oldPkg.stripe_price_id,
  };
}

async function stripeSyncDeactivate(pkg) {
  if (stripeStubMode()) return;
  if (!pkg.stripe_price_id) return;
  // Stub IDs don't exist on Stripe — nothing to deactivate.
  if (isStubId(pkg.stripe_price_id)) return;
  const stripe = getStripe();
  try {
    await stripe.prices.update(pkg.stripe_price_id, { active: false });
  } catch (e) {
    logger.warn('stripe_deactivate_price_failed', { id: pkg.id, error: e.message });
  }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function validateNew(input) {
  const errors = [];
  if (!input || typeof input !== 'object') errors.push('body required');
  const id = String(input.id || '').trim();
  if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(id) || id.length > 40) {
    errors.push('id must be lowercase-kebab, 2-40 chars');
  }
  if (!input.display_name || typeof input.display_name !== 'string') {
    errors.push('display_name required (string)');
  }
  const usd = Number(input.monthly_usd);
  if (!Number.isFinite(usd) || usd < 0 || usd > 100000) {
    errors.push('monthly_usd must be a finite number 0..100000');
  }
  const quota = Number(input.monthly_request_quota);
  if (!Number.isInteger(quota) || quota < 0 || quota > 100_000_000) {
    errors.push('monthly_request_quota must be a non-negative integer ≤ 100M');
  }
  if (!Array.isArray(input.allowed_model_tiers) || input.allowed_model_tiers.length === 0) {
    errors.push('allowed_model_tiers must be a non-empty array');
  } else {
    const bad = input.allowed_model_tiers.filter((t) => !KNOWN_TIERS.includes(t));
    if (bad.length) errors.push(`unknown tier(s): ${bad.join(', ')} (valid: ${KNOWN_TIERS.join(', ')})`);
  }
  // Additive validators — optional fields whose default-absent semantics
  // are "feature off." Each branch is its own `if (input.X !== undefined)`
  // so future cards can add sibling clauses without touching this block.
  // KEEP THIS PATTERN: no shared `else` chains.
  if (input.public_signup !== undefined && typeof input.public_signup !== 'boolean') {
    errors.push('public_signup must be a boolean if present');
  }
  // Daily caps (free-tier card, 2026-05-15). Both fields are optional;
  // null/undefined means unlimited at the daily-cap layer (the monthly
  // quota above remains the always-on backstop). When present they must
  // be positive integers — we treat 0 as "always 429", which is a silly
  // tier but a legitimate operator choice so we don't reject it. Negative
  // / fractional / huge values are rejected.
  if (input.daily_request_cap !== undefined && input.daily_request_cap !== null) {
    const drc = Number(input.daily_request_cap);
    if (!Number.isInteger(drc) || drc < 0 || drc > 100_000_000) {
      errors.push('daily_request_cap must be a non-negative integer ≤ 100M (or null)');
    }
  }
  if (input.daily_fallback_token_cap !== undefined && input.daily_fallback_token_cap !== null) {
    const dtc = Number(input.daily_fallback_token_cap);
    if (!Number.isInteger(dtc) || dtc < 0 || dtc > 10_000_000_000) {
      errors.push('daily_fallback_token_cap must be a non-negative integer ≤ 10B (or null)');
    }
  }
  return errors;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function list({ includeInactive = false } = {}) {
  const all = readAll();
  return includeInactive ? all : all.filter((p) => p.active !== false);
}

function get(id) {
  return readAll().find((p) => p.id === id) || null;
}

function findByStripePriceId(priceId) {
  if (!priceId) return null;
  return readAll().find((p) => p.stripe_price_id === priceId) || null;
}

function getDefault() {
  const all = readAll().filter((p) => p.active !== false);
  return all.find((p) => p.is_default) || all[0] || null;
}

async function create(input) {
  const errors = validateNew(input);
  if (errors.length) {
    const e = new Error('validation_failed: ' + errors.join('; '));
    e.errors = errors;
    e.code = 'validation_failed';
    throw e;
  }
  const all = readAll();
  if (all.find((p) => p.id === input.id)) {
    const e = new Error(`package id "${input.id}" already exists`);
    e.code = 'duplicate_id';
    throw e;
  }
  const pkg = {
    id: input.id,
    display_name: input.display_name,
    description: input.description || '',
    monthly_usd: Number(input.monthly_usd),
    monthly_request_quota: Number(input.monthly_request_quota),
    allowed_model_tiers: [...input.allowed_model_tiers],
    // Daily caps — optional; null = unlimited (legacy default for any
    // existing package that pre-dates this card). See validateNew() for
    // the accepted shape. Free-tier package will set both to small ints.
    daily_request_cap:
      input.daily_request_cap === undefined || input.daily_request_cap === null
        ? null
        : Number(input.daily_request_cap),
    daily_fallback_token_cap:
      input.daily_fallback_token_cap === undefined || input.daily_fallback_token_cap === null
        ? null
        : Number(input.daily_fallback_token_cap),
    is_default: Boolean(input.is_default) || false,
    active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    stripe_product_id: null,
    stripe_price_id: null,
    // Additive: public_signup gates whether POST /signup/free will issue
    // a key against this package. Default-absent = not signupable without
    // Stripe. See src/index.js POST /signup/free.
    public_signup: input.public_signup === true,
  };
  // Forward-compat passthrough for fields owned by the companion daily-
  // caps agent. We persist them when present so seed → registry round-
  // trips don't drop the caps. We do NOT validate them here (that's the
  // companion's surface). If the companion's branch hasn't landed, these
  // are inert data; if it has, the middleware reads them off the record.
  for (const field of ['daily_request_cap', 'daily_fallback_token_cap',
                       'tier', 'price_cents_monthly', 'request_budget']) {
    if (input[field] !== undefined) pkg[field] = input[field];
  }
  const stripeFields = await stripeSyncCreate(pkg);
  Object.assign(pkg, stripeFields);
  if (pkg.is_default) {
    all.forEach((p) => { p.is_default = false; });
  }
  all.push(pkg);
  writeAll(all);
  logger.info('package_created', { id: pkg.id, stripe_price_id: pkg.stripe_price_id });
  return pkg;
}

async function update(id, patch) {
  const all = readAll();
  const idx = all.findIndex((p) => p.id === id);
  if (idx === -1) {
    const e = new Error(`package "${id}" not found`);
    e.code = 'not_found';
    throw e;
  }
  const old = all[idx];
  const merged = {
    ...old,
    display_name: patch.display_name !== undefined ? patch.display_name : old.display_name,
    description: patch.description !== undefined ? patch.description : old.description,
    monthly_usd: patch.monthly_usd !== undefined ? Number(patch.monthly_usd) : old.monthly_usd,
    monthly_request_quota: patch.monthly_request_quota !== undefined
      ? Number(patch.monthly_request_quota)
      : old.monthly_request_quota,
    allowed_model_tiers: patch.allowed_model_tiers !== undefined
      ? [...patch.allowed_model_tiers]
      : old.allowed_model_tiers,
    // Daily caps: explicit null in patch clears (back to unlimited);
    // absent keeps the existing value; number coerces through Number().
    daily_request_cap: patch.daily_request_cap !== undefined
      ? (patch.daily_request_cap === null ? null : Number(patch.daily_request_cap))
      : (old.daily_request_cap === undefined ? null : old.daily_request_cap),
    daily_fallback_token_cap: patch.daily_fallback_token_cap !== undefined
      ? (patch.daily_fallback_token_cap === null ? null : Number(patch.daily_fallback_token_cap))
      : (old.daily_fallback_token_cap === undefined ? null : old.daily_fallback_token_cap),
    is_default: patch.is_default !== undefined ? Boolean(patch.is_default) : old.is_default,
    public_signup: patch.public_signup !== undefined
      ? Boolean(patch.public_signup)
      : (old.public_signup === true),
  };
  // Re-validate (treat patch + old as a full record)
  const errors = validateNew({ ...merged });
  if (errors.length) {
    const e = new Error('validation_failed: ' + errors.join('; '));
    e.errors = errors;
    e.code = 'validation_failed';
    throw e;
  }
  const stripeFields = await stripeSyncUpdate(old, merged);
  Object.assign(merged, stripeFields, {
    updated_at: new Date().toISOString(),
  });
  if (merged.is_default && !old.is_default) {
    all.forEach((p) => { p.is_default = false; });
  }
  all[idx] = merged;
  writeAll(all);
  logger.info('package_updated', { id: merged.id, stripe_price_id: merged.stripe_price_id });
  return merged;
}

async function softDelete(id) {
  const all = readAll();
  const idx = all.findIndex((p) => p.id === id);
  if (idx === -1) return false;
  const pkg = all[idx];
  if (pkg.is_default) {
    const e = new Error('cannot delete the default package — set another package as default first');
    e.code = 'is_default';
    throw e;
  }
  pkg.active = false;
  pkg.deactivated_at = new Date().toISOString();
  pkg.updated_at = new Date().toISOString();
  await stripeSyncDeactivate(pkg);
  writeAll(all);
  logger.info('package_deactivated', { id: pkg.id });
  return true;
}

// Pre-seed the default package on first startup if no packages exist.
// Also ensures the FREE_PACKAGE exists — idempotent, so an operator who
// later customizes the starter via /admin/packages doesn't accidentally
// lose the free-tier signup gate. The free package is a separate
// existence check (not gated on "registry empty") so a registry that has
// only the starter still gets free added on next boot.
async function seedIfEmpty() {
  const existing = readAll();
  if (existing.length === 0) {
    try {
      await create({ ...DEFAULT_PACKAGE });
      logger.info('package_default_seeded', { id: DEFAULT_PACKAGE.id });
    } catch (e) {
      logger.error('package_default_seed_failed', { error: e.message });
    }
  }
  // Idempotent free-tier seed. Read fresh after the default create above.
  if (!get(FREE_PACKAGE.id)) {
    try {
      await create({ ...FREE_PACKAGE });
      logger.info('package_free_seeded', { id: FREE_PACKAGE.id });
    } catch (e) {
      logger.error('package_free_seed_failed', { error: e.message });
    }
  }
}

// ---------------------------------------------------------------------------
// Quota helpers (used by chat-api middleware)
// ---------------------------------------------------------------------------

// Resolve which package applies to a given API key record.
// Priority: explicit key.package_id > key.tier matching package id > default.
function resolveForKey(keyRecord) {
  if (!keyRecord) return getDefault();
  if (keyRecord.package_id) {
    const p = get(keyRecord.package_id);
    if (p && p.active !== false) return p;
  }
  if (keyRecord.tier) {
    const p = get(keyRecord.tier);
    if (p && p.active !== false) return p;
  }
  return getDefault();
}

// Compute the start-of-current-month timestamp in ISO form, UTC.
function currentBillingCycleStart(now = new Date()) {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();
}

// Compute the start-of-next-month timestamp (for the quota-reset header).
function nextBillingCycleStart(now = new Date()) {
  const m = now.getUTCMonth();
  return new Date(Date.UTC(now.getUTCFullYear(), m + 1, 1)).toISOString();
}

module.exports = {
  // CRUD
  list,
  get,
  create,
  update,
  softDelete,
  findByStripePriceId,
  getDefault,
  seedIfEmpty,
  // Quota resolution
  resolveForKey,
  currentBillingCycleStart,
  nextBillingCycleStart,
  // Constants (exported for tests + chat-api)
  KNOWN_TIERS,
  DEFAULT_PACKAGE,
  // Internal (exposed for tests)
  _internal: { stripeStubMode, validateNew, stubIds },
};
