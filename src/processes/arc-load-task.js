'use strict';

/**
 * arc-load-task · loads an ARC task JSON from a path-jailed directory.
 * Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.2 + §10.5.
 *
 * Inputs:
 *   { task_id: string,
 *     task_dir?: string,       // optional · defaults to substrate-shipped dir
 *     now: string }            // ISO-8601 · PD-I2
 *
 * Outputs:
 *   { task_id, train, test, train_count, test_count, now,
 *     task_dir_resolved,        // realpath of the resolved task dir
 *     corpus_root_resolved }    // realpath of the allowlisted root this
 *                                // task_dir lives under (PD-W12 audit
 *                                // surface; null when the legacy
 *                                // substrate-root jail was used).
 *
 * Path-jail defenses (PD-I6/I7/I8):
 *   - task_id MUST match ^[A-Za-z0-9._-]+$ (no slashes, no .., no spaces).
 *   - task_dir MUST resolve to a directory inside an ALLOWLISTED corpus
 *     root (substrate-shipped OR env-supplied via COGOS_ARC_CORPUS_ROOTS).
 *     This was tightened to "inside the cogos-api repo root" pre-PD-W12;
 *     it now widens to the allowlist while preserving realpath jailing.
 *   - File size cap 1 MiB; JSON shape validated; grids ≤ 30×30; cells 0..9.
 */

const fs = require('node:fs');
const path = require('node:path');
const { loadCorpusRoots, isPathInsideAnyRoot, SUBSTRATE_ROOT } = require('./arc-corpus-allowlist');

const PROCESS_VERSION = 1;
const MAX_BYTES = 1024 * 1024;
const MAX_DIM = 30;
const TASK_ID_RE = /^[A-Za-z0-9._-]+$/;

// Substrate-shipped fixture dir. Operators can extend the allowlist via
// COGOS_ARC_CORPUS_ROOTS (env, colon-separated) or COGOS_ARC_CORPUS_ROOTS_FILE
// (env, points at a JSON file with { "roots": ["<abs>", ...] }) per the
// PD-W12 closure. Default behavior unchanged: only the substrate-shipped
// root is allowed.
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_DIR = SUBSTRATE_ROOT;

function bad(code, message) {
  const err = new Error(message);
  err.code = code;
  throw err;
}

function validateGrid(g, where) {
  if (!Array.isArray(g) || g.length === 0 || g.length > MAX_DIM) {
    bad('invalid_input', `${where}: grid must be a non-empty array of rows, ≤ ${MAX_DIM}`);
  }
  const cols = g[0].length;
  if (!Array.isArray(g[0]) || cols === 0 || cols > MAX_DIM) {
    bad('invalid_input', `${where}: row 0 must be a non-empty array, ≤ ${MAX_DIM}`);
  }
  for (let r = 0; r < g.length; r++) {
    const row = g[r];
    if (!Array.isArray(row) || row.length !== cols) {
      bad('invalid_input', `${where}: row ${r} length ${row && row.length} ≠ row 0 length ${cols}`);
    }
    for (let c = 0; c < cols; c++) {
      const v = row[c];
      if (!Number.isInteger(v) || v < 0 || v > 9) {
        bad('invalid_input', `${where}: row ${r} col ${c} = ${v} is not an integer in [0, 9]`);
      }
    }
  }
}

function arcLoadTask(body) {
  if (!body || typeof body !== 'object') {
    bad('invalid_input', 'arc-load-task: body must be a JSON object');
  }
  if (typeof body.now !== 'string' || !body.now) {
    bad('missing_now',
        'arc-load-task requires body.now (ISO-8601 string) per PROCESS_DETERMINISM PD-I2');
  }
  if (typeof body.task_id !== 'string' || !body.task_id || !TASK_ID_RE.test(body.task_id)) {
    bad('invalid_input', 'arc-load-task: task_id must match ^[A-Za-z0-9._-]+$ (no slashes, no ..)');
  }

  // Path-jail: resolve task_dir, then realpath, then assert it lives
  // inside an allowlisted corpus root (PD-W12 generalization of PD-I7).
  let taskDir = body.task_dir ? String(body.task_dir) : DEFAULT_DIR;
  if (!path.isAbsolute(taskDir)) {
    // Relative task_dir resolves against REPO_ROOT (preserves v0.1
    // behavior for callers that supply "data/arc-tasks" or similar).
    taskDir = path.resolve(REPO_ROOT, taskDir);
  }
  let resolvedDir;
  try {
    resolvedDir = fs.realpathSync(taskDir);
  } catch (e) {
    bad('path_not_found', `arc-load-task: task_dir does not exist · ${e.message}`);
  }
  const allowlist = loadCorpusRoots();
  if (!allowlist.ok) {
    bad('substrate_misconfigured',
        `arc-load-task: corpus allowlist load failed · ${allowlist.message}`);
  }
  let corpusRoot = null;
  for (const root of allowlist.roots) {
    if (resolvedDir === root || resolvedDir.startsWith(root + path.sep)) {
      corpusRoot = root;
      break;
    }
  }
  if (corpusRoot == null) {
    // Surface which roots WERE allowed so operators can debug.
    bad('path_outside_allowlist',
        `arc-load-task: task_dir escapes the corpus allowlist (PD-I7 + PD-W12) · allowed roots: ${allowlist.roots.join(', ')}`);
  }

  const filePath = path.join(resolvedDir, body.task_id + '.json');
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (e) {
    bad('task_not_found', `arc-load-task: ${body.task_id}.json not in ${resolvedDir}`);
  }
  if (stat.size > MAX_BYTES) {
    bad('file_too_large', `arc-load-task: task file exceeds ${MAX_BYTES} bytes (got ${stat.size})`);
  }
  const raw = fs.readFileSync(filePath, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    bad('bad_task_json', `arc-load-task: invalid JSON in ${body.task_id}.json · ${e.message}`);
  }

  if (!parsed || typeof parsed !== 'object'
      || !Array.isArray(parsed.train) || !Array.isArray(parsed.test)) {
    bad('invalid_input', 'arc-load-task: task JSON must have train[] and test[] arrays');
  }

  // Validate every grid in train + test.
  const train = parsed.train.map((p, i) => {
    if (!p || typeof p !== 'object') bad('invalid_input', `train[${i}] not an object`);
    validateGrid(p.input,  `train[${i}].input`);
    validateGrid(p.output, `train[${i}].output`);
    return { input: p.input, output: p.output };
  });
  const test = parsed.test.map((p, i) => {
    if (!p || typeof p !== 'object') bad('invalid_input', `test[${i}] not an object`);
    validateGrid(p.input, `test[${i}].input`);
    if (p.output != null) validateGrid(p.output, `test[${i}].output`);
    return p.output != null
      ? { input: p.input, output: p.output }
      : { input: p.input };
  });

  return {
    task_id:             body.task_id,
    train,
    test,
    train_count:         train.length,
    test_count:          test.length,
    task_dir_resolved:   resolvedDir,
    corpus_root_resolved: corpusRoot,    // PD-W12 audit surface
    now:                 body.now,
    process_version:     PROCESS_VERSION,
  };
}

module.exports = {
  arcLoadTask,
  PROCESS_VERSION,
  REPO_ROOT,
  DEFAULT_DIR,
};
