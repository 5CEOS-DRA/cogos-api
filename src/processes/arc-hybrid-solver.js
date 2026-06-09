'use strict';

/**
 * arc-hybrid-solver · uses §10.8 segmentation stats (size, color, bbox,
 * object_count) to pick a constant-fill color WITHOUT taking color from
 * the caller. Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.9
 * (partially closes PD-W15).
 *
 * Strategies (closed in v0.1 per §10.8.4 mirror):
 *   - "majority_color_fill"        · fill R×C with the most-common
 *                                    non-background color across OBJECT
 *                                    CELLS only. Tie → smallest color.
 *   - "largest_object_color_fill"  · fill R×C with the color of the
 *                                    largest object (PD-I9 tie-break).
 *   - "auto"                       · object_count ∈ {0,1} → identity copy
 *                                    object_count ≥ 2  → majority_color_fill
 *                                    Branch surfaced as auto_branch_taken.
 *
 * "Hybrid" means structure-detection (segmentation) feeds value-selection
 * (fill color). NOT an LLM/rule hybrid, NOT a multi-strategy ensemble.
 * Substrate still does no inference; the decision tree is closed.
 *
 * Connectivity: 4 (orthogonal), same-color match — mirrors §10.8 exactly.
 * Background: explicit input only (PD-I10); default 0 (ARC convention).
 *
 * Determinism discipline (PD §8.8 a-d, plus §10.9 invariants):
 *   PD-I11 · majority over object cells only; ties → smallest color value.
 *   PD-I12 · auto branch is a closed tree on object_count (not a heuristic
 *            search). Surface `auto_branch_taken` so the operator can read
 *            which structural rule fired.
 *   PD-I13 · No `color` field on input. Caller does NOT supply the fill
 *            color; the segmentation does. This is the entire point.
 */

const PROCESS_VERSION = 1;
const MAX_DIM = 30;
const VALID_STRATEGIES = Object.freeze([
  'majority_color_fill',
  'largest_object_color_fill',
  'auto',
]);

// 4-connectivity neighbor order: up, left, right, down. Anchored per §8.8(b).
const DR = [-1, 0, 0, 1];
const DC = [ 0, -1, 1, 0];

function bad(code, message) {
  const err = new Error(message);
  err.code = code;
  throw err;
}

function validateGrid(g, where) {
  if (!Array.isArray(g) || g.length === 0 || g.length > MAX_DIM) {
    bad('invalid_input', `${where}: must be a non-empty array of rows, ≤ ${MAX_DIM}`);
  }
  if (!Array.isArray(g[0]) || g[0].length === 0 || g[0].length > MAX_DIM) {
    bad('invalid_input', `${where}: row 0 must be a non-empty array, ≤ ${MAX_DIM}`);
  }
  const cols = g[0].length;
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

function segmentObjects(grid, rows, cols, background) {
  const seen = Array.from({ length: rows }, () => new Array(cols).fill(false));
  const objects = [];
  let nextId = 0;
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      if (seen[r][c]) continue;
      const color = grid[r][c];
      if (color === background) { seen[r][c] = true; continue; }
      const cells = [];
      const queue = [[r, c]];
      let head = 0;
      seen[r][c] = true;
      while (head < queue.length) {
        const [ur, uc] = queue[head++];
        cells.push([ur, uc]);
        for (let k = 0; k < 4; k++) {
          const nr = ur + DR[k];
          const nc = uc + DC[k];
          if (nr < 0 || nr >= rows || nc < 0 || nc >= cols) continue;
          if (seen[nr][nc]) continue;
          if (grid[nr][nc] !== color) continue;
          seen[nr][nc] = true;
          queue.push([nr, nc]);
        }
      }
      cells.sort((a, b) => (a[0] - b[0]) || (a[1] - b[1]));
      let r0 = cells[0][0], c0 = cells[0][1], r1 = r0, c1 = c0;
      for (const [cr, cc] of cells) {
        if (cr < r0) r0 = cr;
        if (cr > r1) r1 = cr;
        if (cc < c0) c0 = cc;
        if (cc > c1) c1 = cc;
      }
      objects.push({
        id: nextId++,
        color,
        size: cells.length,
        cells,
        bbox: { r0, c0, r1, c1 },
      });
    }
  }
  return objects;
}

function largestObjectId(objects) {
  if (objects.length === 0) return null;
  let bestId = objects[0].id;
  let bestSize = objects[0].size;
  for (let i = 1; i < objects.length; i++) {
    const o = objects[i];
    // PD-I9 tie-break: smaller id wins (= scan-order seed).
    if (o.size > bestSize) { bestSize = o.size; bestId = o.id; }
  }
  return bestId;
}

// PD-I11 · majority over OBJECT CELLS only. Tie → smallest color value.
// Iterating objects[] in id order keeps the tally trace stable; the
// tie-break is numeric so it does NOT depend on Map iteration order.
function majorityColor(objects) {
  if (objects.length === 0) return null;
  const counts = new Map();
  for (const o of objects) {
    counts.set(o.color, (counts.get(o.color) || 0) + o.size);
  }
  let bestColor = null;
  let bestCount = -1;
  for (const [color, count] of counts) {
    if (count > bestCount || (count === bestCount && color < bestColor)) {
      bestColor = color;
      bestCount = count;
    }
  }
  return bestColor;
}

function fillGrid(rows, cols, value) {
  return Array.from({ length: rows }, () => new Array(cols).fill(value));
}

function arcHybridSolver(body) {
  if (!body || typeof body !== 'object') {
    bad('invalid_input', 'arc-hybrid-solver: body must be a JSON object');
  }
  if (typeof body.now !== 'string' || !body.now) {
    bad('missing_now',
        'arc-hybrid-solver requires body.now (ISO-8601 string) per PROCESS_DETERMINISM PD-I2');
  }
  if (typeof body.strategy !== 'string' || !VALID_STRATEGIES.includes(body.strategy)) {
    bad('invalid_input',
        `arc-hybrid-solver: strategy must be one of ${VALID_STRATEGIES.join('|')}`);
  }
  // PD-I13 · caller MUST NOT supply a fill color. The whole point of this
  // engine is that segmentation picks the color; accepting a `color` field
  // would re-import the constant_fill failure mode.
  if (body.color !== undefined) {
    bad('invalid_input',
        'arc-hybrid-solver: body.color is forbidden (PD-I13); fill color is derived from segmentation');
  }
  const { rows, cols } = validateGrid(body.input_grid, 'input_grid');

  // PD-I10 · explicit background, default 0. Never inferred.
  let background = 0;
  if (body.background !== undefined) {
    if (!Number.isInteger(body.background) || body.background < 0 || body.background > 9) {
      bad('invalid_input', 'arc-hybrid-solver: background must be an integer in [0, 9]');
    }
    background = body.background;
  }

  const objects = segmentObjects(body.input_grid, rows, cols, background);
  const lid = largestObjectId(objects);
  const maj = majorityColor(objects);

  let predicted;
  let fillColor = null;
  let autoBranchTaken = undefined;

  if (body.strategy === 'majority_color_fill') {
    fillColor = (maj != null) ? maj : background;
    predicted = fillGrid(rows, cols, fillColor);
  } else if (body.strategy === 'largest_object_color_fill') {
    fillColor = (lid != null) ? objects[lid].color : background;
    predicted = fillGrid(rows, cols, fillColor);
  } else {  // 'auto' · PD-I12 closed decision tree
    if (objects.length === 0 || objects.length === 1) {
      autoBranchTaken = 'identity';
      predicted = body.input_grid.map((row) => row.slice());
      fillColor = null;
    } else {
      autoBranchTaken = 'majority_color_fill';
      fillColor = (maj != null) ? maj : background;
      predicted = fillGrid(rows, cols, fillColor);
    }
  }

  const out = {
    predicted,
    strategy:          body.strategy,
    rows,
    cols,
    background,
    objects,
    object_count:      objects.length,
    largest_object_id: lid,
    majority_color:    maj,
    fill_color:        fillColor,
    now:               body.now,
    process_version:   PROCESS_VERSION,
  };
  // Only surface auto_branch_taken when strategy=="auto" so byte-equal
  // canonicalization across strategies stays predictable.
  if (body.strategy === 'auto') {
    out.auto_branch_taken = autoBranchTaken;
  }
  return out;
}

module.exports = {
  arcHybridSolver,
  PROCESS_VERSION,
  VALID_STRATEGIES,
};
