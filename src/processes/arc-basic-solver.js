'use strict';

/**
 * arc-basic-solver · v0.1 trivial transformations.
 * Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.3.
 *
 * Strategies:
 *   - "identity"       · output = deep-copy of input_grid
 *   - "constant_fill"  · output = grid of same dims filled with `color`
 *
 * Both are byte-deterministic on canonicalized input (PD-I1). No
 * pattern matching, no DSL search, no symmetry detection. The substrate
 * EXECUTES the chosen transformation; choosing the right strategy is
 * the caller's problem (or a future solver-class doctrine's).
 */

const PROCESS_VERSION = 1;
const MAX_DIM = 30;
const VALID_STRATEGIES = Object.freeze(['identity', 'constant_fill']);

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

function arcBasicSolver(body) {
  if (!body || typeof body !== 'object') {
    bad('invalid_input', 'arc-basic-solver: body must be a JSON object');
  }
  if (typeof body.now !== 'string' || !body.now) {
    bad('missing_now',
        'arc-basic-solver requires body.now (ISO-8601 string) per PROCESS_DETERMINISM PD-I2');
  }
  if (typeof body.strategy !== 'string' || !VALID_STRATEGIES.includes(body.strategy)) {
    bad('invalid_input',
        `arc-basic-solver: strategy must be one of ${VALID_STRATEGIES.join('|')}`);
  }
  const { rows, cols } = validateGrid(body.input_grid, 'input_grid');

  let predicted;
  if (body.strategy === 'identity') {
    predicted = body.input_grid.map((row) => row.slice());
  } else {  // constant_fill
    if (!Number.isInteger(body.color) || body.color < 0 || body.color > 9) {
      bad('invalid_input',
          'arc-basic-solver: strategy=constant_fill requires color as integer in [0, 9]');
    }
    const c = body.color;
    predicted = Array.from({ length: rows }, () => new Array(cols).fill(c));
  }

  return {
    predicted,
    strategy:        body.strategy,
    rows,
    cols,
    now:             body.now,
    process_version: PROCESS_VERSION,
  };
}

module.exports = {
  arcBasicSolver,
  PROCESS_VERSION,
  VALID_STRATEGIES,
};
