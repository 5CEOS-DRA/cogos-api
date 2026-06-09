'use strict';

/**
 * int-factor · pinned-script Python engine.
 * Per COGOS_PROCESS_DETERMINISM_DOCTRINE_v0.1 §8.
 *
 * Spawn contract:
 *   - script:  _python/int-factor.v1.py · operator-authored, read-only
 *   - script_hash: sha256 of the file content, computed at module load,
 *     surfaced on every response, committed into output_hash.
 *   - stdin:  canonical JSON of args (only `n` + `now` are passed).
 *   - stdout: JSON the JS wrapper parses + wraps with metadata.
 *   - env:    scrubbed per §8.3 (PYTHONHASHSEED=0, no user-site,
 *             no HOME / AWS / SSH, minimal PATH, LANG=C).
 *   - cwd:    /tmp (read-only-by-convention from the script's POV;
 *             script does no file IO per §8.2 + PD-HN-7).
 *   - shell:  false (per §8.3, NEVER true).
 *   - timeout, maxBuffer: §8.3 limits.
 *
 * The JS wrapper enforces the determinism gate (body.now per PD-I2)
 * + input range BEFORE spawning, so an obviously-bad call doesn't
 * pay for a subprocess round-trip. The Python script enforces the
 * same checks defensively — both layers refuse, neither falls back.
 */

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const SCRIPT_PATH = path.join(__dirname, '_python', 'int-factor.v1.py');
const SCRIPT_HASH = 'sha256:' + crypto
  .createHash('sha256')
  .update(fs.readFileSync(SCRIPT_PATH))
  .digest('hex');

const PROCESS_VERSION = 1;
const MAX_N = 1e12;
const TIMEOUT_MS = 5_000;
const MAX_OUTPUT_BYTES = 64 * 1024;

// §8.3 scrubbed env. Nothing beyond what the script genuinely needs.
const SAFE_ENV = Object.freeze({
  PYTHONHASHSEED:          '0',
  PYTHONDONTWRITEBYTECODE: '1',
  PYTHONNOUSERSITE:        '1',
  PATH:                    '/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin',
  LANG:                    'C',
  LC_ALL:                  'C',
});

function intFactor(body) {
  // PD-I2 · time anchor from input only.
  if (!body || typeof body !== 'object' || typeof body.now !== 'string' || !body.now) {
    const err = new Error(
      'int-factor requires body.now (ISO-8601 string) per PROCESS_DETERMINISM PD-I2.'
    );
    err.code = 'missing_now';
    throw err;
  }
  // Input range check (defense in depth · script also checks).
  if (typeof body.n !== 'number'
      || !Number.isInteger(body.n)
      || body.n < 2
      || body.n > MAX_N) {
    const err = new Error('int-factor requires body.n to be an integer in [2, 1e12].');
    err.code = 'invalid_input';
    throw err;
  }

  // Canonical-bytes input · only the two fields the script reads.
  const inputStr = JSON.stringify({ n: body.n, now: body.now });

  const r = spawnSync('python3', [SCRIPT_PATH], {
    input:     inputStr,
    encoding:  'utf8',
    timeout:   TIMEOUT_MS,
    maxBuffer: MAX_OUTPUT_BYTES,
    env:       SAFE_ENV,
    cwd:       '/tmp',
    shell:     false,
  });

  if (r.error) {
    const err = new Error('int-factor python spawn failed · ' + r.error.message);
    err.code = 'spawn_failed';
    throw err;
  }
  if (r.status !== 0) {
    const stderrTail = (r.stderr || '').slice(0, 200);
    const err = new Error('int-factor python exited ' + r.status + ': ' + stderrTail);
    err.code = 'python_error';
    throw err;
  }
  let parsed;
  try {
    parsed = JSON.parse(r.stdout || '');
  } catch (e) {
    const err = new Error('int-factor python returned invalid JSON · ' + e.message);
    err.code = 'bad_output';
    throw err;
  }

  // §8.5 · script_hash + process_version into every response · committed
  // into output_hash via canonicalize at the compose layer.
  return {
    ...parsed,
    process_version: PROCESS_VERSION,
    script_hash:     SCRIPT_HASH,
  };
}

module.exports = {
  intFactor,
  PROCESS_VERSION,
  SCRIPT_PATH,
  SCRIPT_HASH,
  MAX_N,
};
