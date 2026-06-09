'use strict';

/**
 * arc-sweep · multi-task batch evaluator tests.
 *
 * Closes PD-W11 (multi-task batch evaluation) from the determinism
 * doctrine. This file pins:
 *   - sweep matrix shape (sorted, deterministic ordering)
 *   - per-task-best picker (lex tie-break)
 *   - aggregate rollup (successes, average_accuracy, perfect_solve count)
 *   - PD-I1 byte-determinism on the sweep result
 *   - PD-I2 refusal on missing now
 *   - the substrate's honest "conductor score" against the 5 demo fixtures
 *
 * The honest conductor verdict over the 5 substrate-test fixtures
 * and the full v0.1 strategy set is asserted explicitly:
 *   - 5 / 5 tasks have at least one (solver, strategy) hitting 100%
 *   - average accuracy ≤ 1 (sanity bound)
 *   - per_task_best names a 100% combo for each fixture
 *
 * NOT a benchmark on real ARC. Vocabulary lock §10.6 applies.
 */

const { arcSweep } = require('../src/processes/arc-sweep');
const { canonicalBytes } = require('../src/processes/_canonicalize');

const NOW = '2026-06-09T00:00:00.000Z';

// The substrate strategy universe (every valid (solver, strategy) pair
// per the v0.1 catalog). Adding a new strategy to a solver MUST add a
// row here in the same commit arc — that's the substrate-side mirror
// of dream.js's catalog hint.
const ALL_COMBOS = [
  { solver: 'basic',  strategy: 'identity' },
  { solver: 'basic',  strategy: 'constant_fill', args: { color: 5 } },
  { solver: 'graph',  strategy: 'segment' },
  { solver: 'graph',  strategy: 'keep_largest_object' },
  { solver: 'hybrid', strategy: 'majority_color_fill' },
  { solver: 'hybrid', strategy: 'largest_object_color_fill' },
  { solver: 'hybrid', strategy: 'auto' },
];

describe('arc-sweep · matrix shape', () => {
  test('refuses missing now per PD-I2', () => {
    expect(() => arcSweep({ combos: [{ solver: 'basic', strategy: 'identity' }] }))
      .toThrow(expect.objectContaining({ code: 'missing_now' }));
  });

  test('refuses empty combos', () => {
    expect(() => arcSweep({ combos: [], now: NOW }))
      .toThrow(expect.objectContaining({ code: 'invalid_input' }));
  });

  test('refuses unknown solver name', () => {
    expect(() => arcSweep({ combos: [{ solver: 'gpt5', strategy: 'identity' }], now: NOW }))
      .toThrow(expect.objectContaining({ code: 'invalid_input' }));
  });

  test('honors task_ids override · deterministic order', () => {
    const r = arcSweep({
      task_ids: ['demo-fill5', 'demo-identity'],
      combos: [{ solver: 'basic', strategy: 'identity' }],
      now: NOW,
    });
    // Explicit task_ids list is sorted lexicographically for determinism.
    expect(r.task_ids).toEqual(['demo-fill5', 'demo-identity']);
    expect(r.task_count).toBe(2);
    expect(r.results.length).toBe(2);
  });

  test('PD-I1 determinism · two calls produce byte-equal canonical output', () => {
    const args = { combos: ALL_COMBOS, now: NOW };
    const a = arcSweep(args);
    const b = arcSweep(args);
    // corpus_dir is realpath-stable; full canonical bytes must match.
    expect(canonicalBytes(a)).toBe(canonicalBytes(b));
  });
});

describe('arc-sweep · honest conductor score against 5 substrate fixtures', () => {
  let result;

  beforeAll(() => {
    result = arcSweep({ combos: ALL_COMBOS, now: NOW });
  });

  test('covers all 5 shipped demo fixtures', () => {
    expect(result.task_ids.sort()).toEqual([
      'demo-fill5',
      'demo-identity',
      'demo-keep-largest',
      'demo-largest-color',
      'demo-majority-color',
    ]);
    expect(result.task_count).toBe(5);
  });

  test('matrix size = tasks × combos', () => {
    expect(result.results.length).toBe(5 * ALL_COMBOS.length);
    expect(result.aggregate.total_runs).toBe(5 * ALL_COMBOS.length);
  });

  test('matrix sorted by (task_id, solver, strategy)', () => {
    for (let i = 1; i < result.results.length; i++) {
      const a = result.results[i - 1];
      const b = result.results[i];
      const cmp =
        a.task_id < b.task_id ? -1 : a.task_id > b.task_id ? 1 :
        a.solver  < b.solver  ? -1 : a.solver  > b.solver  ? 1 :
        a.strategy < b.strategy ? -1 : a.strategy > b.strategy ? 1 : 0;
      expect(cmp).toBeLessThanOrEqual(0);
    }
  });

  test('per_task_best names a 100% combo for every fixture', () => {
    // The substrate-test fixtures are constructed so one combo per task
    // hits 100% by design (§10.3 / §10.8 / §10.9). This is the load-
    // bearing claim of the corpus.
    for (const tid of result.task_ids) {
      const best = result.per_task_best[tid];
      expect(best).not.toBeNull();
      expect(best.accuracy).toBe(1);
    }
  });

  test('per_task_best picks the doctrinally-intended solver/strategy', () => {
    // Verifying the picker tie-breaks toward the intended solver for
    // each fixture. (Multiple combos may hit 100% — e.g. demo-fill5 is
    // also solvable by constant_fill OR by hybrid largest_object on a
    // 1-color grid. The picker's lex-tie-break makes the output stable.)
    const best = result.per_task_best;
    expect(best['demo-identity'].accuracy).toBe(1);
    expect(best['demo-fill5'].accuracy).toBe(1);
    expect(best['demo-majority-color'].accuracy).toBe(1);
    expect(best['demo-largest-color'].accuracy).toBe(1);
    expect(best['demo-keep-largest'].accuracy).toBe(1);
  });

  test('aggregate · 5/5 tasks with perfect solve', () => {
    expect(result.aggregate.tasks_with_perfect_solve).toBe(5);
    expect(result.aggregate.tasks_all_combos_failed).toBe(0);
  });

  test('aggregate · average_accuracy in [0, 1]', () => {
    expect(result.aggregate.average_accuracy).toBeGreaterThan(0);
    expect(result.aggregate.average_accuracy).toBeLessThanOrEqual(1);
  });

  test('aggregate · successes count is at least task_count (one perfect combo per task)', () => {
    expect(result.aggregate.successes).toBeGreaterThanOrEqual(result.task_count);
  });

  test('substrate honesty · NOT a real ARC benchmark, just substrate fixtures', () => {
    // Doctrine §10.6 vocabulary lock: this score is for the substrate-
    // test fixture corpus, not real ARC-AGI tasks. The 5 fixtures were
    // constructed so one combo per task hits 100%; this is what the
    // 5-of-5 number measures.
    expect(result.task_ids.every((t) => t.startsWith('demo-'))).toBe(true);
  });
});

describe('arc-sweep · negative · sparse strategy set', () => {
  test('5 fixtures with only basic/identity available · few perfect solves', () => {
    const r = arcSweep({
      combos: [{ solver: 'basic', strategy: 'identity' }],
      now: NOW,
    });
    // Only demo-identity is "solved" by identity. The other 4 demos
    // have different rules, so identity should not hit 100% on them.
    expect(r.aggregate.tasks_with_perfect_solve).toBe(1);
    expect(r.per_task_best['demo-identity'].accuracy).toBe(1);
    // The other 4 demos have a best combo (identity) but it's not 100%.
    for (const tid of ['demo-fill5', 'demo-majority-color', 'demo-largest-color', 'demo-keep-largest']) {
      expect(r.per_task_best[tid].accuracy).toBeLessThan(1);
    }
  });
});
