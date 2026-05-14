'use strict';

// SOC 2 evidence-collection endpoints.
//
// Two operator-only routes that an auditor downloads to capture a
// point-in-time snapshot of the live environment without having to
// screenshot the Azure portal or paste shell output. Both are gated by
// the existing adminAuth middleware (X-Admin-Key) and never emit env-var
// values, request bodies, or customer secrets.
//
//   GET /admin/soc2/evidence-bundle
//     Returns a single JSON blob with:
//       - service identity (name, version, uptime, node version, image tag,
//         revision name)
//       - cosign signature status (whether COSIGN_PUBKEY_PEM or _FILE is set)
//       - last 100 admin-action audit rows (key issuance / revocation /
//         package CRUD — pulled from src/keys.js + src/packages.js shape,
//         not from the request/response audit chain)
//       - audit-chain head row count (total rows in data/usage.jsonl)
//       - anomaly-log row count (total rows in data/anomalies.jsonl)
//       - currently-deployed env var NAMES ONLY (never values)
//
//   GET /admin/soc2/control-status
//     Returns the contents of docs/soc2/control-mapping.csv as JSON so the
//     auditor's audit-management tooling can ingest it without parsing CSV.
//     Parsed from disk on each call — there is no in-memory cache; the
//     CSV is the source of truth and lives in-repo so any change is
//     git-auditable.
//
// CONSTRAINTS:
//   - process.env values are NEVER serialized. Only Object.keys(process.env).
//   - The image-tag value comes from CONTAINER_APP_REVISION (Azure-supplied)
//     or IMAGE_TAG (operator-supplied); both are operational metadata, not
//     secrets, but we still treat them as opaque strings and don't reveal
//     them if unset (return null rather than "undefined").
//   - The admin-action log is the last 100 events from src/keys.js
//     readAll() + src/packages.js list({ includeInactive: true }) projected
//     into a homogenous shape. We deliberately don't read winston log files
//     because the auditor doesn't have shell access to those; they'd see
//     them via az log queries.

const fs = require('node:fs');
const path = require('node:path');

const keys = require('./keys');
const usage = require('./usage');
const packages = require('./packages');

// CSV is shipped alongside the source — path is stable relative to this file.
const CONTROL_MAPPING_PATH = path.join(__dirname, '..', 'docs', 'soc2', 'control-mapping.csv');

// Cap the admin-action recap at 100 entries (most recent first) so the
// payload is bounded regardless of operator activity.
const ADMIN_ACTION_RECAP_LIMIT = 100;

// Build the projected admin-action recap by merging key events (issuance +
// revocation) and package CRUD events (create / update / soft-delete inferred
// from the active flag and timestamps available on each record).
//
// IMPORTANT: this is a recap of stored state, not a Winston-log replay. We
// can't reach the Winston log file from inside the request handler in a
// distroless container (no shell, no file system reads outside the project
// data directory). Using the persistent JSON files as the substrate is
// auditor-correct: those are the things that actually changed state.
function buildAdminActionRecap() {
  const events = [];

  // Key issuance + revocation events — projected from data/keys.json shape.
  // Each record produces 1 or 2 events: always one for issue_at, and
  // optionally one for revoked_at when active=false.
  let keyRecords = [];
  try { keyRecords = keys.list(); } catch (_e) { keyRecords = []; }
  for (const r of keyRecords) {
    events.push({
      kind: 'key_issued',
      ts: r.issued_at || null,
      id: r.id,
      tenant_id: r.tenant_id || null,
      scheme: r.scheme || 'bearer',
      tier: r.tier || null,
    });
    if (r.revoked_at) {
      events.push({
        kind: 'key_revoked',
        ts: r.revoked_at,
        id: r.id,
        tenant_id: r.tenant_id || null,
      });
    }
  }

  // Package CRUD events — projected from data/packages.json. We have
  // created_at and updated_at on each package; we surface both when present.
  let packageRecords = [];
  try { packageRecords = packages.list({ includeInactive: true }); } catch (_e) { packageRecords = []; }
  for (const p of packageRecords) {
    if (p.created_at) {
      events.push({
        kind: 'package_created',
        ts: p.created_at,
        id: p.id,
        active: p.active !== false,
      });
    }
    // Only emit a separate 'package_updated' if updated_at differs from
    // created_at — otherwise it's noise (every record has an updated_at).
    if (p.updated_at && p.updated_at !== p.created_at) {
      events.push({
        kind: 'package_updated',
        ts: p.updated_at,
        id: p.id,
        active: p.active !== false,
      });
    }
    // Soft-delete is encoded as active=false. If we have a deactivated_at
    // field surface it explicitly.
    if (p.active === false && p.deactivated_at) {
      events.push({
        kind: 'package_deactivated',
        ts: p.deactivated_at,
        id: p.id,
      });
    }
  }

  // Sort by timestamp descending (most recent first). Rows with null ts go
  // to the end — they're outside our observation window.
  events.sort((a, b) => {
    const ta = a.ts ? Date.parse(a.ts) : 0;
    const tb = b.ts ? Date.parse(b.ts) : 0;
    return tb - ta;
  });

  return events.slice(0, ADMIN_ACTION_RECAP_LIMIT);
}

// Count lines in a JSONL-shaped file without holding the whole file in memory
// for the response. The audit log can grow large; we don't want to OOM the
// gateway on this endpoint. fs.statSync gives size; we sample-count by reading
// the file once — at MB scale this is fine, at GB scale we'd swap for a
// running counter persisted alongside the file (operator-action item).
function countJsonlRows(filePath) {
  try {
    if (!fs.existsSync(filePath)) return 0;
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw) return 0;
    // Lines may end with \n; count non-empty lines.
    let count = 0;
    for (const l of raw.split('\n')) {
      if (l && l.trim()) count += 1;
    }
    return count;
  } catch (_e) {
    return 0;
  }
}

// Determine the path of the usage.jsonl file. Mirrors src/usage.js logic.
function usageFilePath() {
  return process.env.USAGE_FILE
    || path.join(__dirname, '..', 'data', 'usage.jsonl');
}

// Determine the path of the anomalies.jsonl file. Mirrors src/anomaly.js
// logic so we don't have to reach into anomaly's exports — that module
// exports a middleware function, not a clean accessor.
function anomaliesFilePath() {
  return process.env.ANOMALIES_FILE
    || path.join(__dirname, '..', 'data', 'anomalies.jsonl');
}

// Build the evidence-bundle payload. Pure function over current process
// state and on-disk substrate — no request inputs.
function buildEvidenceBundle() {
  // Image tag / revision: operator-supplied or Azure-supplied env vars.
  // We return null if unset rather than "undefined" so the auditor sees a
  // clear absence signal rather than a stringified placeholder.
  const imageTag = process.env.IMAGE_TAG || null;
  const revisionName = process.env.CONTAINER_APP_REVISION_NAME
    || process.env.CONTAINER_APP_REVISION
    || null;

  // Cosign status: published if COSIGN_PUBKEY_PEM is non-empty OR
  // COSIGN_PUBKEY_FILE points at a readable file.
  let cosignPublished = false;
  if (process.env.COSIGN_PUBKEY_PEM && process.env.COSIGN_PUBKEY_PEM.trim().length > 0) {
    cosignPublished = true;
  } else if (process.env.COSIGN_PUBKEY_FILE) {
    try {
      fs.accessSync(process.env.COSIGN_PUBKEY_FILE, fs.constants.R_OK);
      cosignPublished = true;
    } catch (_e) {
      cosignPublished = false;
    }
  }

  // Env var NAMES only — sorted for stable diffing across captures.
  const envVarNames = Object.keys(process.env).sort();

  return {
    schema_version: 1,
    captured_at: new Date().toISOString(),
    service: {
      name: 'cogos-api',
      version: '0.1.0',
      node_version: process.version,
      uptime_s: Math.round(process.uptime()),
      image_tag: imageTag,
      revision_name: revisionName,
    },
    cosign: {
      pubkey_published: cosignPublished,
      pubkey_source: process.env.COSIGN_PUBKEY_PEM
        ? 'env:COSIGN_PUBKEY_PEM'
        : (process.env.COSIGN_PUBKEY_FILE ? 'env:COSIGN_PUBKEY_FILE' : null),
    },
    audit: {
      chain_head_row_count: countJsonlRows(usageFilePath()),
      anomaly_log_row_count: countJsonlRows(anomaliesFilePath()),
    },
    admin_actions_recent: buildAdminActionRecap(),
    env_var_names: envVarNames,
    operator_note: 'Capture this bundle at audit start and at audit close. Diff the two to show no surprise environment changes during the engagement.',
  };
}

// Parse a CSV file with simple-quoted fields. The control-mapping CSV we
// ship is intentionally simple — no embedded quotes — so this parser
// stays simple. If we ever need RFC-4180 escapes we'll swap to a parser
// dependency, but a hand-rolled split is correct for the current file.
function parseControlMappingCsv(rawText) {
  if (!rawText) return { columns: [], rows: [] };
  const lines = rawText.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length === 0) return { columns: [], rows: [] };
  const columns = lines[0].split(',').map((c) => c.trim());
  const rows = [];
  for (let i = 1; i < lines.length; i += 1) {
    const parts = lines[i].split(',');
    // If row has more parts than columns, fold the excess back into the
    // semantic-last column (our_control or evidence_location can contain
    // commas in older revisions; we maintain the 6-column invariant by
    // joining extras into column[2] = our_control).
    const row = {};
    if (parts.length === columns.length) {
      for (let c = 0; c < columns.length; c += 1) {
        row[columns[c]] = (parts[c] || '').trim();
      }
    } else {
      // Defensive: best-effort populate, leave any extras concatenated.
      for (let c = 0; c < columns.length - 1; c += 1) {
        row[columns[c]] = (parts[c] || '').trim();
      }
      const tail = parts.slice(columns.length - 1).join(',').trim();
      row[columns[columns.length - 1]] = tail;
    }
    rows.push(row);
  }
  return { columns, rows };
}

function readControlMapping() {
  let raw = '';
  try {
    raw = fs.readFileSync(CONTROL_MAPPING_PATH, 'utf8');
  } catch (_e) {
    return { columns: [], rows: [], source_path: CONTROL_MAPPING_PATH, error: 'control_mapping_not_readable' };
  }
  const parsed = parseControlMappingCsv(raw);
  return {
    schema_version: 1,
    source_path: 'docs/soc2/control-mapping.csv',
    captured_at: new Date().toISOString(),
    columns: parsed.columns,
    rows: parsed.rows,
    row_count: parsed.rows.length,
    status_counts: parsed.rows.reduce((acc, r) => {
      const s = r.status || 'unknown';
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, {}),
  };
}

module.exports = {
  buildEvidenceBundle,
  readControlMapping,
  // exported for tests
  _internal: { buildAdminActionRecap, countJsonlRows, parseControlMappingCsv },
};
