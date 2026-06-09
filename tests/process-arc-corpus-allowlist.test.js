'use strict';

/**
 * arc-corpus-allowlist tests · PD-W12 closure.
 *
 * Covers:
 *   - default behavior (no env) preserves v0.1 substrate-shipped root
 *   - COGOS_ARC_CORPUS_ROOTS extends the allowlist
 *   - COGOS_ARC_CORPUS_ROOTS_FILE extends the allowlist
 *   - rejected entries surface in `rejected[]` honestly (not swallowed)
 *   - PD-I1 byte-determinism on the resolved roots[] list
 *   - arc-load-task honors the allowlist (operator-supplied dir works)
 *   - arc-load-task refuses paths outside the allowlist
 *   - response surfaces `corpus_root_resolved` for audit
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const allowlistMod = require('../src/processes/arc-corpus-allowlist');
const { arcLoadTask } = require('../src/processes/arc-load-task');
const { canonicalBytes } = require('../src/processes/_canonicalize');

const NOW = '2026-06-09T00:00:00.000Z';

function mkTempCorpus() {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-arc-corpus-')));
  // Drop one minimal valid task into it so arc-load-task can find it.
  fs.writeFileSync(path.join(dir, 'op-demo.json'), JSON.stringify({
    _doctrine_note: 'PD-W12 test fixture · operator-shipped corpus.',
    train: [{ input: [[1, 0]], output: [[1, 0]] }],
    test:  [{ input: [[2, 3]], output: [[2, 3]] }],
  }));
  return dir;
}

function cleanupDir(d) {
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

describe('arc-corpus-allowlist · loadCorpusRoots()', () => {
  test('default · only substrate-shipped root', () => {
    const r = allowlistMod.loadCorpusRoots({ env: {} });
    expect(r.ok).toBe(true);
    expect(r.roots.length).toBe(1);
    expect(r.roots[0]).toBe(r.substrate_root);
    expect(r.sources.substrate).toBe(true);
    expect(r.sources.env).toBe(false);
    expect(r.sources.config_file).toBe(false);
    expect(r.rejected).toEqual([]);
  });

  test('env var · single root extends allowlist', () => {
    const tmp = mkTempCorpus();
    try {
      const r = allowlistMod.loadCorpusRoots({
        env: { COGOS_ARC_CORPUS_ROOTS: tmp },
      });
      expect(r.ok).toBe(true);
      expect(r.roots).toContain(tmp);
      expect(r.roots).toContain(r.substrate_root);
      expect(r.sources.env).toBe(true);
      expect(r.rejected).toEqual([]);
    } finally { cleanupDir(tmp); }
  });

  test('env var · multiple roots, colon-separated', () => {
    const a = mkTempCorpus();
    const b = mkTempCorpus();
    try {
      const r = allowlistMod.loadCorpusRoots({
        env: { COGOS_ARC_CORPUS_ROOTS: a + ':' + b },
      });
      expect(r.ok).toBe(true);
      expect(r.roots).toContain(a);
      expect(r.roots).toContain(b);
      expect(r.roots.length).toBe(3);   // substrate + a + b
    } finally { cleanupDir(a); cleanupDir(b); }
  });

  test('env var · empty + whitespace entries dropped', () => {
    const tmp = mkTempCorpus();
    try {
      const r = allowlistMod.loadCorpusRoots({
        env: { COGOS_ARC_CORPUS_ROOTS: ':' + tmp + '::  :' },
      });
      expect(r.ok).toBe(true);
      expect(r.roots).toContain(tmp);
      expect(r.rejected).toEqual([]);
    } finally { cleanupDir(tmp); }
  });

  test('env var · non-absolute path rejected (not silently dropped)', () => {
    const r = allowlistMod.loadCorpusRoots({
      env: { COGOS_ARC_CORPUS_ROOTS: 'relative/path' },
    });
    expect(r.ok).toBe(true);
    expect(r.rejected.length).toBe(1);
    expect(r.rejected[0].error).toBe('not_absolute');
    expect(r.roots.length).toBe(1);   // only substrate
  });

  test('env var · non-existent path rejected', () => {
    const r = allowlistMod.loadCorpusRoots({
      env: { COGOS_ARC_CORPUS_ROOTS: '/does/not/exist/' + Date.now() },
    });
    expect(r.ok).toBe(true);
    expect(r.rejected.length).toBe(1);
    expect(r.rejected[0].error).toBe('not_found');
  });

  test('env var · file (not directory) rejected', () => {
    const tmpfile = path.join(os.tmpdir(), 'allowlist-not-a-dir-' + Date.now() + '.txt');
    fs.writeFileSync(tmpfile, 'not a dir');
    try {
      const r = allowlistMod.loadCorpusRoots({
        env: { COGOS_ARC_CORPUS_ROOTS: tmpfile },
      });
      expect(r.ok).toBe(true);
      expect(r.rejected.length).toBe(1);
      expect(r.rejected[0].error).toBe('not_a_directory');
    } finally { try { fs.unlinkSync(tmpfile); } catch (_) {} }
  });

  test('config file · JSON shape honored', () => {
    const corpus = mkTempCorpus();
    const cfgPath = path.join(os.tmpdir(), 'allowlist-cfg-' + Date.now() + '.json');
    fs.writeFileSync(cfgPath, JSON.stringify({ roots: [corpus] }));
    try {
      const r = allowlistMod.loadCorpusRoots({
        env: { COGOS_ARC_CORPUS_ROOTS_FILE: cfgPath },
      });
      expect(r.ok).toBe(true);
      expect(r.roots).toContain(corpus);
      expect(r.sources.config_file).toBe(true);
    } finally { cleanupDir(corpus); try { fs.unlinkSync(cfgPath); } catch (_) {} }
  });

  test('config file · bad JSON surfaces in rejected', () => {
    const cfgPath = path.join(os.tmpdir(), 'allowlist-bad-' + Date.now() + '.json');
    fs.writeFileSync(cfgPath, 'not json at all');
    try {
      const r = allowlistMod.loadCorpusRoots({
        env: { COGOS_ARC_CORPUS_ROOTS_FILE: cfgPath },
      });
      expect(r.ok).toBe(true);
      expect(r.rejected.length).toBe(1);
      expect(r.rejected[0].error).toBe('config_bad_json');
    } finally { try { fs.unlinkSync(cfgPath); } catch (_) {} }
  });

  test('config file · missing roots key rejected', () => {
    const cfgPath = path.join(os.tmpdir(), 'allowlist-noroots-' + Date.now() + '.json');
    fs.writeFileSync(cfgPath, JSON.stringify({ wrong_key: [] }));
    try {
      const r = allowlistMod.loadCorpusRoots({
        env: { COGOS_ARC_CORPUS_ROOTS_FILE: cfgPath },
      });
      expect(r.ok).toBe(true);
      expect(r.rejected.length).toBe(1);
      expect(r.rejected[0].error).toBe('config_bad_shape');
    } finally { try { fs.unlinkSync(cfgPath); } catch (_) {} }
  });

  test('PD-I1 determinism · same env produces byte-equal roots[] across calls', () => {
    const a = mkTempCorpus();
    const b = mkTempCorpus();
    try {
      const env = { COGOS_ARC_CORPUS_ROOTS: b + ':' + a };   // reversed order
      const r1 = allowlistMod.loadCorpusRoots({ env });
      const r2 = allowlistMod.loadCorpusRoots({ env });
      expect(canonicalBytes(r1.roots)).toBe(canonicalBytes(r2.roots));
      // Sorted means r.roots is lex-ordered regardless of env insertion.
      const sorted = [...r1.roots].sort();
      expect(r1.roots).toEqual(sorted);
    } finally { cleanupDir(a); cleanupDir(b); }
  });

  test('dedupe · same realpath supplied twice yields one entry', () => {
    const tmp = mkTempCorpus();
    try {
      const r = allowlistMod.loadCorpusRoots({
        env: { COGOS_ARC_CORPUS_ROOTS: tmp + ':' + tmp },
      });
      expect(r.ok).toBe(true);
      const occurrences = r.roots.filter((p) => p === tmp).length;
      expect(occurrences).toBe(1);
    } finally { cleanupDir(tmp); }
  });
});

describe('arc-corpus-allowlist · isPathInsideAnyRoot()', () => {
  test('exact-match root accepted', () => {
    expect(allowlistMod.isPathInsideAnyRoot('/a/b', ['/a/b'])).toBe(true);
  });
  test('subdirectory accepted', () => {
    expect(allowlistMod.isPathInsideAnyRoot('/a/b/c', ['/a/b'])).toBe(true);
  });
  test('sibling-prefix rejected (no false positives)', () => {
    // /a/b should NOT include /a/bb
    expect(allowlistMod.isPathInsideAnyRoot('/a/bb', ['/a/b'])).toBe(false);
  });
  test('parent path rejected', () => {
    expect(allowlistMod.isPathInsideAnyRoot('/a', ['/a/b'])).toBe(false);
  });
  test('multiple roots · any match accepts', () => {
    expect(allowlistMod.isPathInsideAnyRoot('/y/z', ['/x', '/y'])).toBe(true);
  });
  test('no roots · always false', () => {
    expect(allowlistMod.isPathInsideAnyRoot('/anything', [])).toBe(false);
  });
});

describe('arc-load-task · PD-W12 allowlist integration', () => {
  test('default behavior unchanged · substrate-shipped task loads', () => {
    const r = arcLoadTask({ task_id: 'demo-identity', now: NOW });
    expect(r.task_id).toBe('demo-identity');
    expect(r.corpus_root_resolved).toBeTruthy();
    expect(r.corpus_root_resolved).toBe(allowlistMod.SUBSTRATE_ROOT);
  });

  test('operator-supplied task_dir loads when env-allowlisted', () => {
    const opCorpus = mkTempCorpus();
    const prev = process.env[allowlistMod.ENV_VAR_ROOTS];
    process.env[allowlistMod.ENV_VAR_ROOTS] = opCorpus;
    try {
      const r = arcLoadTask({ task_id: 'op-demo', task_dir: opCorpus, now: NOW });
      expect(r.task_id).toBe('op-demo');
      expect(r.corpus_root_resolved).toBe(opCorpus);
      expect(r.task_dir_resolved).toBe(opCorpus);
      expect(r.train.length).toBe(1);
      expect(r.test.length).toBe(1);
    } finally {
      if (prev == null) delete process.env[allowlistMod.ENV_VAR_ROOTS];
      else process.env[allowlistMod.ENV_VAR_ROOTS] = prev;
      cleanupDir(opCorpus);
    }
  });

  test('task_dir NOT in allowlist is refused with path_outside_allowlist', () => {
    const orphan = mkTempCorpus();
    // No env override — orphan is not allowlisted.
    try {
      expect(() => arcLoadTask({ task_id: 'op-demo', task_dir: orphan, now: NOW }))
        .toThrow(expect.objectContaining({ code: 'path_outside_allowlist' }));
    } finally { cleanupDir(orphan); }
  });

  test('symlink escape · resolved realpath still gated by allowlist', () => {
    const allowed = mkTempCorpus();
    const outside = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'arc-outside-')));
    const linkParent = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'arc-link-')));
    const link = path.join(linkParent, 'escape-link');
    fs.symlinkSync(outside, link);
    const prev = process.env[allowlistMod.ENV_VAR_ROOTS];
    process.env[allowlistMod.ENV_VAR_ROOTS] = allowed;   // only `allowed` is allowlisted
    try {
      // Even though the operator supplies the symlink, realpath resolves
      // to `outside`, which is NOT in the allowlist → refuse.
      expect(() => arcLoadTask({ task_id: 'op-demo', task_dir: link, now: NOW }))
        .toThrow(expect.objectContaining({ code: 'path_outside_allowlist' }));
    } finally {
      if (prev == null) delete process.env[allowlistMod.ENV_VAR_ROOTS];
      else process.env[allowlistMod.ENV_VAR_ROOTS] = prev;
      cleanupDir(allowed); cleanupDir(outside); cleanupDir(linkParent);
    }
  });

  test('task_id still gated by PD-I6 regex (no slashes, no ..)', () => {
    // Path-traversal in task_id rejected before any disk access.
    expect(() => arcLoadTask({ task_id: '../passwd', now: NOW }))
      .toThrow(expect.objectContaining({ code: 'invalid_input' }));
    expect(() => arcLoadTask({ task_id: 'foo/bar', now: NOW }))
      .toThrow(expect.objectContaining({ code: 'invalid_input' }));
  });
});
