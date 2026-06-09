'use strict';

/**
 * arc-evaluate · cell-wise grid comparison.
 * Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.4.
 *
 * Pure JS, no LLM, no subjective scoring. Compares predicted vs expected:
 *   - if dims mismatch · accuracy = 0, dims_match = false
 *   - else · accuracy = exact-match-cells / total-cells
 *
 * `correct: true` iff dims match AND every cell matches.
 */

const PROCESS_VERSION = 1;
const MAX_DIM = 30;

function bad(code, message) {
  const err = new Error(message);
  err.code = code;
  throw err;
}

function validateGrid(g, where) {
  if (!Array.isArray(g) || g.length === 0 || g.length > MAX_DIM) {
    bad('invalid_input', `${where}: must be a non-empty array of rows, ≤ ${MAX_DIM}`);
  }
  const cols = g[0].length;
  if (!Array.isArray(g[0]) || cols === 0 || cols > MAX_DIM) {
    bad('invalid_input', `${where}: row 0 must be a non-empty array, ≤ ${MAX_DIM}`);
  }
  for (let r = 0; r < g.length; r++) {
    const row = g[r];
    if (!Array.isArray(row) || row.length !== cols) {
      bad('invalid_input', `${where}: row ${r} length differs from row 0 (${cols})`);
    }
    for (let c = 0; c < cols; c++) {
      const v = row[c];
      if (!Number.isInteger(v) || v < 0 || v > 9) {
        bad('invalid_input', `${where}: row ${r} col ${c} = ${v} not in [0,9]`);
      }
    }
  }
  return { rows: g.length, cols };
}

function arcEvaluate(body) {
  if (!body || typeof body !== 'object') {
    bad('invalid_input', 'arc-evaluate: body must be a JSON object');
  }
  if (typeof body.now !== 'string' || !body.now) {
    bad('missing_now',
        'arc-evaluate requires body.now (ISO-8601 string) per PROCESS_DETERMINISM PD-I2');
  }
  const pred = validateGrid(body.predicted, 'predicted');
  const exp  = validateGrid(body.expected,  'expected');

  const dims_match = pred.rows === exp.rows && pred.cols === exp.cols;
  let cells_total = 0;
  let cells_correct = 0;
  if (dims_match) {
    cells_total = pred.rows * pred.cols;
    for (let r = 0; r < pred.rows; r++) {
      for (let c = 0; c < pred.cols; c++) {
        if (body.predicted[r][c] === body.expected[r][c]) cells_correct++;
      }
    }
  }
  const accuracy = dims_match && cells_total > 0
    ? cells_correct / cells_total
    : 0;
  const correct = dims_match && cells_correct === cells_total;

  return {
    correct,
    cells_total,
    cells_correct,
    accuracy,
    rows_predicted:  pred.rows,
    cols_predicted:  pred.cols,
    rows_expected:   exp.rows,
    cols_expected:   exp.cols,
    dims_match,
    now:             body.now,
    process_version: PROCESS_VERSION,
  };
}

module.exports = {
  arcEvaluate,
  PROCESS_VERSION,
};
