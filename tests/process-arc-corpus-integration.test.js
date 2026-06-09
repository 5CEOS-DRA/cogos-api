'use strict';

/**
 * ARC corpus integration · runs every shipped substrate-test fixture
 * through the full load → solve → evaluate pipeline and asserts the
 * intended solver achieves 100% accuracy on the test pair.
 *
 * This is the load-bearing claim behind the doctrine note inside each
 * fixture's "_doctrine_note" field: each fixture encodes a deterministic
 * rule and the matching solver/strategy must reproduce it exactly.
 *
 * Coverage (2026-06-09):
 *   demo-identity        · arc-basic-solver  · identity         ·  100%
 *   demo-fill5           · arc-basic-solver  · constant_fill=5  ·  100%
 *   demo-majority-color  · arc-hybrid-solver · majority_color_fill · 100%
 *   demo-largest-color   · arc-hybrid-solver · largest_object_color_fill · 100%
 *   demo-keep-largest    · arc-graph-solver  · keep_largest_object · 100%
 *
 * Adding a new fixture: add it to data/arc-tasks/, then add a row here
 * binding (fixture, solver, strategy) to the expected accuracy.
 *
 * NOT a real ARC benchmark. The fixtures are substrate-test corpus, not
 * the actual ARC-AGI corpus (PD-W12 · operator-loadable corpus is still
 * the open wedge). 100% on every demo proves the SUBSTRATE works, NOT
 * that we solved ARC (§10.6 vocabulary lock).
 */

const { arcLoadTask }     = require('../src/processes/arc-load-task');
const { arcBasicSolver }  = require('../src/processes/arc-basic-solver');
const { arcGraphSolver }  = require('../src/processes/arc-graph-solver');
const { arcHybridSolver } = require('../src/processes/arc-hybrid-solver');
const { arcEvaluate }     = require('../src/processes/arc-evaluate');

const NOW = '2026-06-09T00:00:00.000Z';

function runSolver(solver, body) {
  if (solver === 'basic')  return arcBasicSolver(body);
  if (solver === 'graph')  return arcGraphSolver(body);
  if (solver === 'hybrid') return arcHybridSolver(body);
  throw new Error('unknown solver: ' + solver);
}

const CORPUS = [
  { task: 'demo-identity',       solver: 'basic',  strategy: 'identity' },
  { task: 'demo-fill5',          solver: 'basic',  strategy: 'constant_fill', extra: { color: 5 } },
  { task: 'demo-majority-color', solver: 'hybrid', strategy: 'majority_color_fill' },
  { task: 'demo-largest-color',  solver: 'hybrid', strategy: 'largest_object_color_fill' },
  { task: 'demo-keep-largest',   solver: 'graph',  strategy: 'keep_largest_object' },
];

describe('ARC corpus integration · 5 substrate-test fixtures', () => {
  for (const row of CORPUS) {
    test(`${row.task} · ${row.solver}/${row.strategy} · 100% on test pair`, () => {
      const loaded = arcLoadTask({ task_id: row.task, now: NOW });
      expect(loaded.task_id).toBe(row.task);
      expect(loaded.test.length).toBeGreaterThanOrEqual(1);

      // We assert the intended strategy reproduces every TRAIN output AND
      // the TEST output exactly. Training pairs are the "spec" of the
      // encoded rule; if a fixture's training pairs don't all hit 100%
      // with the intended strategy, the fixture's _doctrine_note is wrong.
      const pairs = [...loaded.train, ...loaded.test];
      for (let i = 0; i < pairs.length; i++) {
        const { input, output: expected } = pairs[i];
        const solveArgs = { strategy: row.strategy, input_grid: input, now: NOW, ...(row.extra || {}) };
        const r = runSolver(row.solver, solveArgs);
        const evalResult = arcEvaluate({ predicted: r.predicted, expected, now: NOW });
        expect({ task: row.task, pair: i, accuracy: evalResult.accuracy })
          .toEqual({ task: row.task, pair: i, accuracy: 1 });
        expect(evalResult.correct).toBe(true);
        expect(evalResult.dims_match).toBe(true);
      }
    });
  }
});

describe('ARC corpus integration · cross-checks (negative)', () => {
  test('arc-basic identity on demo-majority-color · accuracy < 1 (fixture is solver-specific)', () => {
    // Sanity check: the wrong strategy does NOT reproduce the rule.
    // Confirms the fixture distinguishes between solvers — otherwise
    // 100% accuracy above would be trivial.
    const loaded = arcLoadTask({ task_id: 'demo-majority-color', now: NOW });
    const { input, output: expected } = loaded.test[0];
    const r = arcBasicSolver({ strategy: 'identity', input_grid: input, now: NOW });
    const evalResult = arcEvaluate({ predicted: r.predicted, expected, now: NOW });
    expect(evalResult.accuracy).toBeLessThan(1);
  });

  test('arc-hybrid auto on demo-keep-largest · accuracy < 1 (auto picks majority not keep)', () => {
    // demo-keep-largest's rule is "keep the largest object's MASK," not
    // "fill everything with one color." arc-hybrid auto with multi-object
    // input takes majority_color_fill branch, which does NOT mask. Should
    // NOT hit 100%.
    const loaded = arcLoadTask({ task_id: 'demo-keep-largest', now: NOW });
    const { input, output: expected } = loaded.test[0];
    const r = arcHybridSolver({ strategy: 'auto', input_grid: input, now: NOW });
    const evalResult = arcEvaluate({ predicted: r.predicted, expected, now: NOW });
    expect(evalResult.accuracy).toBeLessThan(1);
  });
});
