#!/usr/bin/env node
'use strict';

// Pricing seed migration · 2026-06-10
//
// Closes Truth Audit C1: the public CogOSHero page advertised
// $49/$199/$499/$999 SKUs but data/packages.json served $29/$99/$299/
// $1500/$8333. This script applies the new lineup so the gateway and
// the page agree.
//
// IDEMPOTENT. Safe to run on:
//   - a fresh deploy (no packages.json yet)
//   - a partial-state deploy (some SKUs already migrated)
//   - a fully-migrated deploy (no-op)
//
// New active self-serve lineup:
//   starter-v3  $19.99 / mo · 20K req  · Tier B          [DEFAULT]
//   plus        $49    / mo · 100K req · Tier A + B      (step it up)
//   pro         $199   / mo · 500K req · Tier A + B
//   business    $499   / mo · 1.5M req · Tier A + B · 99.9% SLA
//
// Legacy SKUs deactivated (NOT deleted) so historical keys still
// resolve: starter $29, operator-pro $99, team $299, compliance $1500,
// enterprise $8333.
//
// Untouched: free, compliance-addon, cap-tier-da1c35, test-pkg.
//
// Enterprise: no self-serve SKU. Customers route via /enterprise-inquiry.
//
// Run: node scripts/seed-pricing-2026-06-10.cjs
//      node scripts/seed-pricing-2026-06-10.cjs --dry-run    (preview)

const path = require('path');
process.env.PACKAGES_FILE = process.env.PACKAGES_FILE
  || path.join(__dirname, '..', 'data', 'packages.json');

const packages = require('../src/packages');

const NEW_SKUS = [
  {
    id: 'starter-v3',
    display_name: 'Starter',
    description: 'Entry self-serve · $19.99 / mo · ~2M output tokens (20K requests at ~100 tokens/request) · 1 API key · Tier B only (Qwen 2.5 3B). Hard cap default — no surprise bills.',
    monthly_usd: 19.99,
    monthly_request_quota: 20000,
    allowed_model_tiers: ['cogos-tier-b'],
    is_default: true,
  },
  {
    id: 'plus',
    display_name: 'Plus',
    description: 'Step it up a notch · $49 / mo · ~10M output tokens (100K requests at ~100 tokens/request) · 2 API keys · Tier A + Tier B (Qwen 2.5 7B + 3B). Replaces the legacy operator-pro $99 SKU at a lower price point.',
    monthly_usd: 49,
    monthly_request_quota: 100000,
    allowed_model_tiers: ['cogos-tier-a', 'cogos-tier-b'],
  },
  {
    id: 'pro',
    display_name: 'Pro',
    description: '$199 / mo · ~50M output tokens (500K requests at ~100 tokens/request) · 5 API keys · Tier A + B + priority worker pool. Replaces the legacy team $299 SKU at a lower price point.',
    monthly_usd: 199,
    monthly_request_quota: 500000,
    allowed_model_tiers: ['cogos-tier-a', 'cogos-tier-b'],
  },
  {
    id: 'business',
    display_name: 'Business',
    description: '$499 / mo · ~150M output tokens (1.5M requests at ~100 tokens/request) · 10 API keys · Tier A + B + 99.9% SLA + team dashboard. Replaces the legacy compliance $1500 SKU at a lower price point.',
    monthly_usd: 499,
    monthly_request_quota: 1500000,
    allowed_model_tiers: ['cogos-tier-a', 'cogos-tier-b'],
  },
];

const LEGACY_TO_DEACTIVATE = [
  'starter',       // was Operator Starter $29 → superseded by starter-v3 $19.99
  'operator-pro',  // $99             → superseded by plus $49
  'team',          // $299            → superseded by pro $199
  'compliance',    // $1500           → superseded by business $499
  'enterprise',    // $8333 self-serve → now phone-call only via /enterprise-inquiry
];

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const log = (...a) => console.log(dryRun ? '[DRY-RUN]' : '[APPLY]', ...a);

  // Idempotent. If the SKU already exists with the right shape, no-op.
  for (const sku of NEW_SKUS) {
    const existing = packages.get(sku.id);
    if (existing) {
      const shapeMatches = (
        existing.monthly_usd === sku.monthly_usd
        && existing.monthly_request_quota === sku.monthly_request_quota
        && JSON.stringify(existing.allowed_model_tiers) === JSON.stringify(sku.allowed_model_tiers)
        && existing.active !== false
      );
      if (shapeMatches) {
        log(sku.id, '— already present + matches, skipping');
        continue;
      }
      log(sku.id, '— exists but shape differs, updating');
      if (!dryRun) {
        await packages.update(sku.id, sku);
      }
    } else {
      log(sku.id, '— creating');
      if (!dryRun) {
        await packages.create(sku);
      }
    }
  }

  // Deactivate legacy SKUs. softDelete refuses to deactivate the
  // current default; the create() of starter-v3 above already flipped
  // is_default off the prior default per packages.create()'s built-in
  // single-default invariant.
  for (const id of LEGACY_TO_DEACTIVATE) {
    const existing = packages.get(id);
    if (!existing) {
      log(id, '— legacy SKU not present, skipping');
      continue;
    }
    if (existing.active === false) {
      log(id, '— already inactive, skipping');
      continue;
    }
    log(id, '— deactivating');
    if (!dryRun) {
      try {
        await packages.softDelete(id);
      } catch (e) {
        if (e.code === 'is_default') {
          // Should not happen if NEW_SKUS already created starter-v3 as
          // default. Surface and continue — operator can investigate.
          console.warn('cannot deactivate ' + id + ' — it is the default. Set another tier as default first.');
        } else {
          throw e;
        }
      }
    }
  }

  log('done.');
}

main().catch((e) => {
  console.error('seed failed:', e.message);
  process.exit(1);
});
