'use strict';

/**
 * arc-corpus-allowlist · operator-loadable ARC corpus root registry.
 * Closes PD-W12 from COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §10.7
 * ("Operator-loadable ARC corpus path · per-tenant task_dir").
 *
 * Problem statement: v0.1 path-jail in arc-load-task accepts only
 * `task_dir`s that resolve inside the cogos-api repo root. Operators
 * who want to ship their own ARC corpus had to either fork cogos-api
 * or copy tasks into `cogos-api/data/arc-tasks/`. Neither scales.
 *
 * This module replaces "inside cogos-api repo root" with "inside any
 * allowlisted corpus root." The allowlist is operator-authored at
 * substrate-startup time and is treated as a doctrine-bound config:
 * adding a root MUST be a deliberate operator act, not a runtime
 * mutation.
 *
 * Sources of allowlisted roots, in priority order:
 *   1. The substrate-shipped root (`cogos-api/data/arc-tasks/`). ALWAYS
 *      present. Removing it would break the shipped fixture corpus.
 *   2. Env var COGOS_ARC_CORPUS_ROOTS (colon-separated absolute paths
 *      like PATH). Per-process; operator controls it at substrate-
 *      startup. Best for "I'm running my own corpus on this box."
 *   3. Optional config file at COGOS_ARC_CORPUS_ROOTS_FILE (JSON shape:
 *      { "roots": ["<abs path>", ...] }). Best for declarative ops.
 *
 * Every supplied root is REALPATH-RESOLVED and must:
 *   - be an absolute path
 *   - exist
 *   - be a directory
 *   - not be a symlink (the realpath is what's stored)
 *
 * PD-I1 binding: same env + same disk state → byte-equal allowlist
 * (roots are sorted before being committed to the resolved set so the
 * canonical bytes don't depend on env var iteration order).
 *
 * Per-tenant scoping (different tenants see different corpora) is the
 * remaining v0.2 wedge — requires threading tenant_id through the
 * engine, which means an auth-aware wrapBody. Documented in §10.7.
 */

const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SUBSTRATE_ROOT = path.join(REPO_ROOT, 'data', 'arc-tasks');

const ENV_VAR_ROOTS = 'COGOS_ARC_CORPUS_ROOTS';
const ENV_VAR_FILE  = 'COGOS_ARC_CORPUS_ROOTS_FILE';

function _realpathDir(p, label) {
  let stat;
  try { stat = fs.statSync(p); }
  catch (e) { return { ok: false, error: 'not_found', message: `${label}: ${p} does not exist` }; }
  if (!stat.isDirectory()) {
    return { ok: false, error: 'not_a_directory', message: `${label}: ${p} is not a directory` };
  }
  try {
    return { ok: true, realpath: fs.realpathSync(p) };
  } catch (e) {
    return { ok: false, error: 'realpath_failed', message: `${label}: realpath ${p} · ${e.message}` };
  }
}

function _parseEnvRoots(envValue) {
  if (typeof envValue !== 'string' || envValue.length === 0) return [];
  // Colon-separated like PATH. Trim each. Empty entries dropped (so a
  // leading or trailing : doesn't introduce an empty root).
  return envValue.split(':').map((s) => s.trim()).filter((s) => s.length > 0);
}

function _loadConfigFileRoots(filePath) {
  if (!filePath) return { ok: true, roots: [] };
  let raw;
  try { raw = fs.readFileSync(filePath, 'utf8'); }
  catch (e) {
    return { ok: false, error: 'config_read_failed',
             message: `corpus roots config file unreadable · ${e.message}` };
  }
  let parsed;
  try { parsed = JSON.parse(raw); }
  catch (e) {
    return { ok: false, error: 'config_bad_json',
             message: `corpus roots config file is not JSON · ${e.message}` };
  }
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.roots)) {
    return { ok: false, error: 'config_bad_shape',
             message: `corpus roots config must be { roots: [string, ...] }` };
  }
  return { ok: true, roots: parsed.roots };
}

/**
 * loadCorpusRoots() · returns the canonical allowlist for this process.
 *
 * Result:
 *   { ok: true,
 *     roots: [string, ...]    // realpath'd absolute dirs, deduped, sorted
 *     substrate_root: string,  // the always-present substrate root
 *     sources: { substrate: true, env: bool, config_file: bool },
 *     rejected: [{ path, error, message }, ...]  // honest gap surface
 *   }
 *
 * Determinism: the resolved roots[] is the union of supplied roots
 * (deduplicated by realpath, sorted lexicographically). Same env + same
 * disk produces byte-equal output across calls.
 *
 * Bad entries (non-existent, non-dir, non-absolute) are SURFACED in
 * `rejected[]` rather than silently dropped. The substrate stays
 * honest about what the operator typed vs. what got allowlisted.
 */
function loadCorpusRoots(opts) {
  opts = opts || {};
  const env = opts.env || process.env;
  const rejected = [];
  const candidates = [];

  // Source 1 · substrate-shipped root. Always allowed.
  const substrateCheck = _realpathDir(SUBSTRATE_ROOT, 'substrate-shipped root');
  if (!substrateCheck.ok) {
    // This is a substrate bug, not an operator error.
    return {
      ok: false,
      error: 'substrate_root_unavailable',
      message: substrateCheck.message,
      roots: [],
      substrate_root: SUBSTRATE_ROOT,
      sources: { substrate: false, env: false, config_file: false },
      rejected: [],
    };
  }
  candidates.push({ path: SUBSTRATE_ROOT, realpath: substrateCheck.realpath });

  // Source 2 · env var.
  const envRoots = _parseEnvRoots(env[ENV_VAR_ROOTS]);
  for (const raw of envRoots) {
    if (!path.isAbsolute(raw)) {
      rejected.push({ path: raw, error: 'not_absolute',
                      message: `env root must be absolute · got "${raw}"` });
      continue;
    }
    const r = _realpathDir(raw, `env root ${raw}`);
    if (!r.ok) { rejected.push({ path: raw, error: r.error, message: r.message }); continue; }
    candidates.push({ path: raw, realpath: r.realpath });
  }

  // Source 3 · config file (env-supplied path).
  let configFileUsed = false;
  const cfgPath = env[ENV_VAR_FILE];
  if (cfgPath) {
    const cfg = _loadConfigFileRoots(cfgPath);
    if (!cfg.ok) {
      rejected.push({ path: cfgPath, error: cfg.error, message: cfg.message });
    } else {
      configFileUsed = true;
      for (const raw of cfg.roots) {
        if (typeof raw !== 'string' || !path.isAbsolute(raw)) {
          rejected.push({ path: String(raw), error: 'not_absolute',
                          message: `config root must be an absolute string` });
          continue;
        }
        const r = _realpathDir(raw, `config root ${raw}`);
        if (!r.ok) { rejected.push({ path: raw, error: r.error, message: r.message }); continue; }
        candidates.push({ path: raw, realpath: r.realpath });
      }
    }
  }

  // Dedupe by realpath; sort for byte-determinism.
  const dedup = new Map();
  for (const c of candidates) dedup.set(c.realpath, c);
  const roots = [...dedup.values()].map((c) => c.realpath).sort();

  return {
    ok: true,
    roots,
    substrate_root: substrateCheck.realpath,
    sources: {
      substrate:   true,
      env:         envRoots.length > 0,
      config_file: configFileUsed,
    },
    rejected,
  };
}

/**
 * isPathInsideAnyRoot(absPath, roots) · returns true iff absPath is
 * inside one of the supplied roots (or equals it). Uses path.sep so the
 * check works on POSIX and Windows. Caller MUST pass realpath'd inputs.
 */
function isPathInsideAnyRoot(absPath, roots) {
  if (typeof absPath !== 'string' || !Array.isArray(roots)) return false;
  for (const root of roots) {
    if (absPath === root) return true;
    if (absPath.startsWith(root + path.sep)) return true;
  }
  return false;
}

module.exports = {
  loadCorpusRoots,
  isPathInsideAnyRoot,
  SUBSTRATE_ROOT,
  ENV_VAR_ROOTS,
  ENV_VAR_FILE,
};
