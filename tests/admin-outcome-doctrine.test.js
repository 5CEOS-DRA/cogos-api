'use strict';

// Phase 1 acceptance criterion F: Outcome Doctrine compliance on
// admin response strings. Per Outcome Doctrine v0.1 (locked in
// 5ceos-platform-internal memory dir as
// project_outcome_doctrine_v0_1_2026_05_27.md) O-NEVER-1: customer-
// facing copy in admin endpoints + sibling analytics router must not
// contain anthropomorphic verbs.
//
// This guard test reads admin.js + admin-analytics.js source files,
// strips comments (which can be educational, not customer-facing),
// and asserts that the remaining source contains no anthropomorphic
// verbs at word boundaries.
//
// Scope: source files written/modified in Phase 1 of the cogos CLI
// substrate plan. Other source files have their own guard tests
// when their commands ship in later phases.

const fs = require('fs');
const path = require('path');

const FORBIDDEN_VERBS = [
  'understands',
  'thinks',
  'decides',
  'knows',
  'believes',
  'wants',
];

// Strip JS // line comments and /* */ block comments. Not bulletproof
// (won't handle // inside strings perfectly) but sufficient for
// express handler source where strings are unlikely to contain //.
// Edge cases would conservatively flag rather than silently pass.
function stripComments(src) {
  // Remove block comments first
  src = src.replace(/\/\*[\s\S]*?\*\//g, ' ');
  // Then remove line comments (// to end-of-line)
  src = src.replace(/\/\/[^\n]*/g, ' ');
  return src;
}

const FILES_UNDER_GUARD = [
  path.join(__dirname, '..', 'src', 'routers', 'admin.js'),
  path.join(__dirname, '..', 'src', 'routers', 'admin-analytics.js'),
];

describe('Outcome Doctrine compliance — admin source files', () => {
  for (const file of FILES_UNDER_GUARD) {
    const rel = path.relative(path.join(__dirname, '..'), file);

    test(`${rel} contains no anthropomorphic verbs in non-comment source`, () => {
      const raw = fs.readFileSync(file, 'utf8');
      const stripped = stripComments(raw);
      const violations = [];

      for (const verb of FORBIDDEN_VERBS) {
        const re = new RegExp(`\\b${verb}\\b`, 'i');
        if (re.test(stripped)) {
          // Find the line in the original for diagnostic context
          const lines = raw.split('\n');
          for (let i = 0; i < lines.length; i++) {
            if (re.test(stripComments(lines[i]))) {
              violations.push(`${rel}:${i + 1}: "${verb}" — "${lines[i].trim()}"`);
            }
          }
        }
      }

      if (violations.length > 0) {
        throw new Error(
          'Outcome Doctrine violation (O-NEVER-1): anthropomorphic verbs in non-comment source.\n'
          + violations.join('\n')
          + '\n\nForbidden verbs: ' + FORBIDDEN_VERBS.join(', ')
          + '\nDoctrine: project_outcome_doctrine_v0_1_2026_05_27 (operator memory dir)',
        );
      }
    });
  }

  test('stripComments helper itself behaves correctly (smoke test)', () => {
    // Block comment removed
    expect(stripComments('a/*decides*/b').includes('decides')).toBe(false);
    // Line comment removed
    expect(stripComments('a // knows\nb').includes('knows')).toBe(false);
    // Non-comment word kept
    expect(stripComments('const decides = 1;').includes('decides')).toBe(true);
  });
});
