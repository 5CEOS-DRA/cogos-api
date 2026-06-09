'use strict';

// Process Library v0.1 — ARC engine direct tests.
// Covers: arc-basic-solver, arc-graph-solver, arc-hybrid-solver, arc-evaluate.
//
// Pure engine tests (no HTTP / no supertest). Each engine is a pure
// function on `body` per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1
// §10.{3,4,8,9}. We test:
//   - strategy correctness (output shape + chosen color / mask)
//   - structural refusals (missing_now per PD-I2, invalid_input shape)
//   - PD-I1 byte-determinism (N=3 round-trips, deep-equal output)
//   - PD-I13 (arc-hybrid refuses caller-supplied color)
//   - tie-breaks (PD-I9 scan-order, PD-I11 smallest-color)
//
// HTTP surface (auth, receipt, output_hash chaining) is exercised by the
// generic process-output-hash + compose suites; this file stays at the
// engine layer so it runs without spinning up an Express app.

const { arcBasicSolver }  = require('../src/processes/arc-basic-solver');
const { arcGraphSolver }  = require('../src/processes/arc-graph-solver');
const { arcHybridSolver } = require('../src/processes/arc-hybrid-solver');
const { arcEvaluate }     = require('../src/processes/arc-evaluate');

const NOW = '2026-06-09T00:00:00.000Z';

// ─────────────────────────────────────────────────────────────────────
// arc-basic-solver · §10.3
// ─────────────────────────────────────────────────────────────────────

describe('process: arc-basic-solver (§10.3)', () => {
  test('identity · output deep-copies input · same dims', () => {
    const grid = [[0, 1, 2], [3, 4, 5]];
    const r = arcBasicSolver({ strategy: 'identity', input_grid: grid, now: NOW });
    expect(r.predicted).toEqual(grid);
    expect(r.predicted).not.toBe(grid);              // deep copy, not alias
    expect(r.rows).toBe(2);
    expect(r.cols).toBe(3);
    expect(r.now).toBe(NOW);
    expect(r.strategy).toBe('identity');
  });

  test('constant_fill · output is uniform grid of color', () => {
    const r = arcBasicSolver({
      strategy: 'constant_fill', input_grid: [[0, 0], [0, 0]], color: 7, now: NOW,
    });
    expect(r.predicted).toEqual([[7, 7], [7, 7]]);
  });

  test('refuses missing now per PD-I2', () => {
    expect(() => arcBasicSolver({ strategy: 'identity', input_grid: [[0]] }))
      .toThrow(expect.objectContaining({ code: 'missing_now' }));
  });

  test('refuses unknown strategy as invalid_input', () => {
    expect(() => arcBasicSolver({ strategy: 'mirror', input_grid: [[0]], now: NOW }))
      .toThrow(expect.objectContaining({ code: 'invalid_input' }));
  });

  test('refuses constant_fill without color', () => {
    expect(() => arcBasicSolver({ strategy: 'constant_fill', input_grid: [[0]], now: NOW }))
      .toThrow(expect.objectContaining({ code: 'invalid_input' }));
  });

  test('PD-I1 determinism · 3 calls produce deep-equal output', () => {
    const args = { strategy: 'identity', input_grid: [[0, 1], [2, 3]], now: NOW };
    const a = arcBasicSolver({ ...args });
    const b = arcBasicSolver({ ...args });
    const c = arcBasicSolver({ ...args });
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(JSON.stringify(b)).toBe(JSON.stringify(c));
  });
});

// ─────────────────────────────────────────────────────────────────────
// arc-graph-solver · §10.8
// ─────────────────────────────────────────────────────────────────────

describe('process: arc-graph-solver (§10.8)', () => {
  // Grid:  0 1 1
  //        1 1 0
  //        0 0 2
  // Background 0 → one 4-component (color 1, 4 cells, id 0)
  //                + one 1-cell (color 2, id 1)
  const GRID = [[0, 1, 1], [1, 1, 0], [0, 0, 2]];

  test('segment · predicted = deep-copy + objects enumerated', () => {
    const r = arcGraphSolver({ strategy: 'segment', input_grid: GRID, now: NOW });
    expect(r.predicted).toEqual(GRID);
    expect(r.object_count).toBe(2);
    expect(r.objects[0].color).toBe(1);
    expect(r.objects[0].size).toBe(4);
    expect(r.objects[1].color).toBe(2);
    expect(r.objects[1].size).toBe(1);
    expect(r.largest_object_id).toBe(0);
  });

  test('keep_largest_object · non-largest cells → background', () => {
    const r = arcGraphSolver({ strategy: 'keep_largest_object', input_grid: GRID, now: NOW });
    expect(r.predicted).toEqual([[0, 1, 1], [1, 1, 0], [0, 0, 0]]);
  });

  test('PD-I9 tie-break · equal-size objects → smaller id wins', () => {
    // Two 1-cells of different colors. Object id 0 = color 5 (row 0 col 0).
    const grid = [[5, 0], [0, 7]];
    const r = arcGraphSolver({ strategy: 'segment', input_grid: grid, now: NOW });
    expect(r.largest_object_id).toBe(0);
  });

  test('PD-I10 · background defaults to 0 explicitly, never inferred', () => {
    // Grid is 90% 5s with a single 0 cell. Background defaults to 0, so the
    // 5s become objects, the 0 cell is "empty." Inferring would flip them.
    const grid = [[5, 5], [5, 0]];
    const r = arcGraphSolver({ strategy: 'segment', input_grid: grid, now: NOW });
    expect(r.background).toBe(0);
    expect(r.object_count).toBe(1);
    expect(r.objects[0].color).toBe(5);
    expect(r.objects[0].size).toBe(3);
  });

  test('refuses missing now per PD-I2', () => {
    expect(() => arcGraphSolver({ strategy: 'segment', input_grid: GRID }))
      .toThrow(expect.objectContaining({ code: 'missing_now' }));
  });

  test('refuses unknown strategy as invalid_input', () => {
    expect(() => arcGraphSolver({ strategy: 'mirror', input_grid: GRID, now: NOW }))
      .toThrow(expect.objectContaining({ code: 'invalid_input' }));
  });

  test('PD-I1 determinism · 3 calls produce byte-equal JSON', () => {
    const args = { strategy: 'segment', input_grid: GRID, now: NOW };
    const a = JSON.stringify(arcGraphSolver({ ...args }));
    const b = JSON.stringify(arcGraphSolver({ ...args }));
    const c = JSON.stringify(arcGraphSolver({ ...args }));
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  test('zero objects (whole grid is background) → largest_object_id null', () => {
    const r = arcGraphSolver({ strategy: 'segment', input_grid: [[0, 0], [0, 0]], now: NOW });
    expect(r.object_count).toBe(0);
    expect(r.largest_object_id).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────
// arc-hybrid-solver · §10.9
// ─────────────────────────────────────────────────────────────────────

describe('process: arc-hybrid-solver (§10.9)', () => {
  // Grid:  0 1 0
  //        1 0 2
  //        0 0 0
  // Two 1-cells (separate components, color 1, total 2 cells)
  //   + one 2-cell (color 2, total 1 cell).
  // Majority color (by cell count over object cells) = 1.
  // Largest object = first 1-cell (id 0).
  const GRID = [[0, 1, 0], [1, 0, 2], [0, 0, 0]];

  test('majority_color_fill · grid fills with majority color', () => {
    const r = arcHybridSolver({ strategy: 'majority_color_fill', input_grid: GRID, now: NOW });
    expect(r.fill_color).toBe(1);
    expect(r.majority_color).toBe(1);
    expect(r.predicted).toEqual([[1, 1, 1], [1, 1, 1], [1, 1, 1]]);
    expect(r.object_count).toBe(3);
  });

  test('largest_object_color_fill · grid fills with largest object color', () => {
    // Grid:  0 1 1
    //        1 1 2
    //        0 0 0
    // One 4-cell 1-object (largest, id 0, color 1) + one 1-cell 2-object.
    const g = [[0, 1, 1], [1, 1, 2], [0, 0, 0]];
    const r = arcHybridSolver({ strategy: 'largest_object_color_fill', input_grid: g, now: NOW });
    expect(r.fill_color).toBe(1);
    expect(r.largest_object_id).toBe(0);
    expect(r.predicted).toEqual([[1, 1, 1], [1, 1, 1], [1, 1, 1]]);
  });

  test('PD-I11 majority tie-break · two colors tie → smallest color value wins', () => {
    // Two 1-cells (color 1, total size 2) AND two 3-cells (color 3, total size 2).
    // Tie at 2 cells each → majority resolves to color 1 (smallest).
    const g = [[1, 0, 1], [0, 0, 0], [3, 0, 3]];
    const r = arcHybridSolver({ strategy: 'majority_color_fill', input_grid: g, now: NOW });
    expect(r.majority_color).toBe(1);
  });

  test('auto branch · object_count=0 → identity', () => {
    const g = [[0, 0], [0, 0]];
    const r = arcHybridSolver({ strategy: 'auto', input_grid: g, now: NOW });
    expect(r.auto_branch_taken).toBe('identity');
    expect(r.predicted).toEqual(g);
    expect(r.fill_color).toBeNull();
  });

  test('auto branch · object_count=1 → identity', () => {
    const g = [[0, 1, 0], [0, 1, 0], [0, 1, 0]];
    const r = arcHybridSolver({ strategy: 'auto', input_grid: g, now: NOW });
    expect(r.auto_branch_taken).toBe('identity');
    expect(r.predicted).toEqual(g);
    expect(r.object_count).toBe(1);
  });

  test('auto branch · object_count≥2 → majority_color_fill', () => {
    const r = arcHybridSolver({ strategy: 'auto', input_grid: GRID, now: NOW });
    expect(r.auto_branch_taken).toBe('majority_color_fill');
    expect(r.fill_color).toBe(1);
  });

  test('auto_branch_taken only present when strategy=="auto"', () => {
    const r = arcHybridSolver({ strategy: 'majority_color_fill', input_grid: GRID, now: NOW });
    expect(r).not.toHaveProperty('auto_branch_taken');
  });

  test('PD-I13 · refuses caller-supplied body.color', () => {
    expect(() => arcHybridSolver({
      strategy: 'majority_color_fill', input_grid: GRID, color: 3, now: NOW,
    })).toThrow(expect.objectContaining({ code: 'invalid_input' }));
  });

  test('refuses missing now per PD-I2', () => {
    expect(() => arcHybridSolver({ strategy: 'auto', input_grid: [[0, 1]] }))
      .toThrow(expect.objectContaining({ code: 'missing_now' }));
  });

  test('refuses unknown strategy as invalid_input', () => {
    expect(() => arcHybridSolver({ strategy: 'recolor_largest', input_grid: [[0]], now: NOW }))
      .toThrow(expect.objectContaining({ code: 'invalid_input' }));
  });

  test('PD-I1 determinism · 3 calls produce byte-equal JSON', () => {
    const args = { strategy: 'auto', input_grid: GRID, now: NOW };
    const a = JSON.stringify(arcHybridSolver({ ...args }));
    const b = JSON.stringify(arcHybridSolver({ ...args }));
    const c = JSON.stringify(arcHybridSolver({ ...args }));
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  test('zero objects path · majority_color_fill falls back to background', () => {
    const r = arcHybridSolver({
      strategy: 'majority_color_fill', input_grid: [[0, 0], [0, 0]], now: NOW,
    });
    expect(r.majority_color).toBeNull();
    expect(r.fill_color).toBe(0);
    expect(r.predicted).toEqual([[0, 0], [0, 0]]);
  });

  test('explicit non-zero background segments the inverse', () => {
    // With background=1 the 1s become "empty" and the 0s are the objects.
    const r = arcHybridSolver({
      strategy: 'auto', input_grid: [[1, 0, 1], [1, 0, 1]], background: 1, now: NOW,
    });
    expect(r.background).toBe(1);
    expect(r.object_count).toBe(1);                  // both 0-cells connected
    expect(r.objects[0].color).toBe(0);
    expect(r.auto_branch_taken).toBe('identity');    // single object
  });
});

// ─────────────────────────────────────────────────────────────────────
// arc-evaluate · §10.4
// ─────────────────────────────────────────────────────────────────────

describe('process: arc-evaluate (§10.4)', () => {
  test('exact match · correct=true · accuracy=1', () => {
    const g = [[1, 2], [3, 4]];
    const r = arcEvaluate({ predicted: g, expected: g, now: NOW });
    expect(r.correct).toBe(true);
    expect(r.accuracy).toBe(1);
    expect(r.dims_match).toBe(true);
    expect(r.cells_correct).toBe(4);
    expect(r.cells_total).toBe(4);
  });

  test('partial match · correct=false · fractional accuracy', () => {
    const r = arcEvaluate({
      predicted: [[1, 2], [3, 4]], expected: [[1, 0], [3, 4]], now: NOW,
    });
    expect(r.correct).toBe(false);
    expect(r.accuracy).toBe(0.75);
    expect(r.dims_match).toBe(true);
  });

  test('dims mismatch · accuracy=0 · dims_match=false', () => {
    const r = arcEvaluate({
      predicted: [[1, 2]], expected: [[1, 2], [3, 4]], now: NOW,
    });
    expect(r.dims_match).toBe(false);
    expect(r.accuracy).toBe(0);
    expect(r.correct).toBe(false);
  });

  test('refuses missing now per PD-I2', () => {
    expect(() => arcEvaluate({ predicted: [[1]], expected: [[1]] }))
      .toThrow(expect.objectContaining({ code: 'missing_now' }));
  });

  test('PD-I1 determinism · 3 calls produce byte-equal JSON', () => {
    const args = { predicted: [[1, 2]], expected: [[1, 3]], now: NOW };
    const a = JSON.stringify(arcEvaluate({ ...args }));
    const b = JSON.stringify(arcEvaluate({ ...args }));
    const c = JSON.stringify(arcEvaluate({ ...args }));
    expect(a).toBe(b);
    expect(b).toBe(c);
  });
});
