#!/usr/bin/env node
'use strict';

// Compute the substrate-automatic frontier escalation rate from
// data/usage.jsonl.
//
// Used to keep public-facing copy ("<X% historical escalation rate") in
// sync with the actual on-disk evidence. Reports both:
//   raw_rate          — total escalations / total calls (the headline)
//   steady_state_rate — same, excluding any time window where one tenant
//                       saw >= BURST_THRESHOLD escalations in a
//                       BURST_WINDOW_MS span (treated as an outage
//                       incident, not steady-state behavior)
//
// Outputs JSON to stdout + a one-line provenance sentence the page can
// paste verbatim:
//   "Based on N calls across T tenants, YYYY-MM-DD to YYYY-MM-DD."
//
// Run: node scripts/escalation-rate-report.cjs [--json]

const fs = require('fs');
const path = require('path');

const USAGE_FILE = process.env.USAGE_FILE
  || path.join(__dirname, '..', 'data', 'usage.jsonl');

const BURST_THRESHOLD  = Number(process.env.BURST_THRESHOLD)  || 5;     // rows
const BURST_WINDOW_MS  = Number(process.env.BURST_WINDOW_MS)  || 60000; // ms

function readRows() {
  if (!fs.existsSync(USAGE_FILE)) return [];
  return fs.readFileSync(USAGE_FILE, 'utf8')
    .split('\n').filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter((r) => r && r.ts);
}

function findBurstWindows(rows) {
  // Group escalated rows by tenant. For each tenant, slide a window of
  // BURST_WINDOW_MS and flag the first row of any window that contains
  // >= BURST_THRESHOLD escalations.
  const byTenant = new Map();
  for (const r of rows) {
    if (r.was_escalated !== true) continue;
    if (!byTenant.has(r.tenant_id)) byTenant.set(r.tenant_id, []);
    byTenant.get(r.tenant_id).push(r);
  }
  const windows = [];
  for (const [tenant, arr] of byTenant.entries()) {
    arr.sort((a, b) => a.ts.localeCompare(b.ts));
    for (let i = 0; i < arr.length; i++) {
      const t0 = new Date(arr[i].ts).getTime();
      let count = 1;
      let end = t0;
      for (let j = i + 1; j < arr.length; j++) {
        const tj = new Date(arr[j].ts).getTime();
        if (tj - t0 > BURST_WINDOW_MS) break;
        count++;
        end = tj;
      }
      if (count >= BURST_THRESHOLD) {
        windows.push({ tenant, start_ts: arr[i].ts, end_ms: end, count });
        // Skip past this window so we don't double-flag.
        let next = i + 1;
        while (next < arr.length && new Date(arr[next].ts).getTime() <= end) next++;
        i = next - 1;
      }
    }
  }
  return windows;
}

function inAnyBurst(row, windows) {
  const t = new Date(row.ts).getTime();
  for (const w of windows) {
    if (row.tenant_id !== w.tenant) continue;
    const wStart = new Date(w.start_ts).getTime();
    if (t >= wStart && t <= w.end_ms) return true;
  }
  return false;
}

function pct(n, d) { return d > 0 ? (100 * n / d).toFixed(2) + '%' : 'n/a'; }

function main() {
  const rows = readRows();
  if (rows.length === 0) {
    console.error('No usage rows found at', USAGE_FILE);
    process.exit(2);
  }
  const total = rows.length;
  const tenants = new Set(rows.map((r) => r.tenant_id));
  const escAll = rows.filter((r) => r.was_escalated === true);
  const escSov = rows.filter((r) => r.escalation_reason === 'sovereign_error');
  const escMan = rows.filter((r) => r.escalation_reason === 'manual_override');
  const bursts = findBurstWindows(rows);
  const inBurst = rows.filter((r) => inAnyBurst(r, bursts));
  const escInBurst = inBurst.filter((r) => r.was_escalated === true);
  const totalExBurst = total - inBurst.length;
  const escExBurst = escAll.length - escInBurst.length;

  // sovereign_attempts telemetry (post-retry feature). Will only be
  // populated on rows written by the new code path.
  const withRetry = rows.filter((r) => typeof r.sovereign_attempts === 'number' && r.sovereign_attempts > 1);
  const savedByRetry = withRetry.filter((r) => r.was_escalated !== true);

  const report = {
    total_calls: total,
    unique_tenants: tenants.size,
    first_ts: rows[0].ts,
    last_ts: rows[rows.length - 1].ts,
    raw: {
      escalations: escAll.length,
      rate: pct(escAll.length, total),
      sovereign_error: escSov.length,
      manual_override: escMan.length,
    },
    burst_incidents: bursts,
    steady_state: {
      total_calls: totalExBurst,
      escalations: escExBurst,
      rate: pct(escExBurst, totalExBurst),
    },
    retry_telemetry: {
      rows_with_retry: withRetry.length,
      saved_by_retry: savedByRetry.length,
      note: 'Only populated on rows written after sovereign-retry feature commit.',
    },
    provenance_sentence:
      'Based on ' + total + ' calls across ' + tenants.size + ' tenants, ' +
      rows[0].ts.slice(0, 10) + ' to ' + rows[rows.length - 1].ts.slice(0, 10) + '.',
  };

  if (process.argv.includes('--json')) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  console.log('=== ESCALATION-RATE REPORT ===');
  console.log('Source:           ' + USAGE_FILE);
  console.log('Window:           ' + report.first_ts + ' to ' + report.last_ts);
  console.log('Total calls:      ' + total);
  console.log('Unique tenants:   ' + tenants.size);
  console.log();
  console.log('RAW RATE:         ' + report.raw.rate + ' (' + escAll.length + '/' + total + ')');
  console.log('  sovereign_error: ' + escSov.length);
  console.log('  manual_override: ' + escMan.length);
  console.log();
  console.log('BURST INCIDENTS:  ' + bursts.length + ' (≥' + BURST_THRESHOLD + ' escalations in ' + (BURST_WINDOW_MS/1000) + 's window)');
  for (const w of bursts) console.log('  · ' + w.tenant + ' · ' + w.start_ts + ' · ' + w.count + ' escalations');
  console.log();
  console.log('STEADY-STATE:     ' + report.steady_state.rate + ' (' + escExBurst + '/' + totalExBurst + ' excluding burst windows)');
  console.log();
  console.log('RETRY TELEMETRY:  ' + savedByRetry.length + ' calls saved by retry of ' + withRetry.length + ' rows that hit retry path');
  console.log();
  console.log('PROVENANCE LINE (paste on page):');
  console.log('  ' + report.provenance_sentence);
}

main();
