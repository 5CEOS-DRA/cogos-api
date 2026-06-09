'use strict';

/**
 * arc-graph-solver · v0.1 4-connected-component segmentation + simple
 * transforms. Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.8
 * (closes PD-W9).
 *
 * Strategies:
 *   - "segment"              · predicted = deep-copy of input_grid; the
 *                              objects[] field enumerates 4-connected
 *                              same-color components.
 *   - "keep_largest_object"  · predicted = grid of same dims with every
 *                              non-largest-object cell set to background.
 *
 * Connectivity: 4 (orthogonal). Same-color match only. Background defaults
 * to 0 (ARC convention) and is an explicit input field per PD-I10 — never
 * inferred from "most common color."
 *
 * Determinism discipline (PD §8.8 a-d):
 *   (a) Cells scanned in row-major (r=0..R-1, c=0..C-1). The first
 *       unvisited non-background cell seeds object id=0, next seeds id=1,
 *       etc. IDs are pure scan-order.
 *   (b) BFS neighbor order is anchored: up, left, right, down. Not derived
 *       from any input ordering.
 *   (c) cells[] of each object sorted ascending by (r, c).
 *   (d) Tie-break for largest_object_id: smaller id wins (= object whose
 *       seed cell appears first in row-major order). Stable by construction.
 *
 * Does NOT call basic-graph-reachability across the registry; per-cell
 * roundtrips would be O(R*C) HTTP-level calls per grid. Shares the §8.8
 * BFS discipline at the code level. A shared BFS helper module is PD-W14.
 */

const PROCESS_VERSION = 1;
const MAX_DIM = 30;
const VALID_STRATEGIES = Object.freeze(['segment', 'keep_largest_object']);

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
    if (o.size > bestSize) { bestSize = o.size; bestId = o.id; }
  }
  return bestId;
}

function arcGraphSolver(body) {
  if (!body || typeof body !== 'object') {
    bad('invalid_input', 'arc-graph-solver: body must be a JSON object');
  }
  if (typeof body.now !== 'string' || !body.now) {
    bad('missing_now',
        'arc-graph-solver requires body.now (ISO-8601 string) per PROCESS_DETERMINISM PD-I2');
  }
  if (typeof body.strategy !== 'string' || !VALID_STRATEGIES.includes(body.strategy)) {
    bad('invalid_input',
        `arc-graph-solver: strategy must be one of ${VALID_STRATEGIES.join('|')}`);
  }
  const { rows, cols } = validateGrid(body.input_grid, 'input_grid');

  // PD-I10 · explicit background, default 0. Never inferred.
  let background = 0;
  if (body.background !== undefined) {
    if (!Number.isInteger(body.background) || body.background < 0 || body.background > 9) {
      bad('invalid_input', 'arc-graph-solver: background must be an integer in [0, 9]');
    }
    background = body.background;
  }

  const objects = segmentObjects(body.input_grid, rows, cols, background);
  const lid = largestObjectId(objects);

  let predicted;
  if (body.strategy === 'segment') {
    predicted = body.input_grid.map((row) => row.slice());
  } else {
    predicted = Array.from({ length: rows }, () => new Array(cols).fill(background));
    if (lid != null) {
      const obj = objects[lid];
      for (const [r, c] of obj.cells) {
        predicted[r][c] = obj.color;
      }
    }
  }

  return {
    predicted,
    strategy:          body.strategy,
    rows,
    cols,
    background,
    objects,
    object_count:      objects.length,
    largest_object_id: lid,
    now:               body.now,
    process_version:   PROCESS_VERSION,
  };
}

module.exports = {
  arcGraphSolver,
  PROCESS_VERSION,
  VALID_STRATEGIES,
};
