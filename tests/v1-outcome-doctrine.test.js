'use strict';

// Phase 2 acceptance criterion F: Outcome Doctrine compliance on the
// /v1/* Zone B surface (intents catalog + viewport reads + apps/build
// push/status).
//
// Per Outcome Doctrine v0.1 (project_outcome_doctrine_v0_1_2026_05_27)
// O-NEVER-1: customer-facing response copy must not contain
// anthropomorphic verbs.
//
// Mirror of admin-outcome-doctrine.test.js (Phase 1 admin) — scans
// src/routers/v1.js where the Zone B handlers live + asserts the
// non-comment source contains no anthropomorphic verbs at word
// boundaries.

const fs = require('fs');
const path = require('path');

const FORBIDDEN_VERBS = [
  'understands',
  'thinks',
  'decides',
  'knows',
  'believes',
  'wants',
  'remembers',
  'feels',
  'realizes',
];

function stripComments(src) {
  src = src.replace(/\/\*[\s\S]*?\*\//g, ' ');
  src = src.replace(/\/\/[^\n]*/g, ' ');
  return src;
}

const FILES_UNDER_GUARD = [
  path.join(__dirname, '..', 'src', 'routers', 'v1.js'),
  path.join(__dirname, '..', 'src', 'internal-trust.js'),
  path.join(__dirname, '..', 'src', 'usage.js'),  // Phase 3: extended for Zone C mutation chain
];

describe('Outcome Doctrine compliance — Phase 2 v1 + internal-trust', () => {
  for (const file of FILES_UNDER_GUARD) {
    const rel = path.relative(path.join(__dirname, '..'), file);

    test(`${rel} contains no anthropomorphic verbs in non-comment source`, () => {
      const raw = fs.readFileSync(file, 'utf8');
      const stripped = stripComments(raw);
      const violations = [];

      for (const verb of FORBIDDEN_VERBS) {
        const re = new RegExp(`\\b${verb}\\b`, 'i');
        if (re.test(stripped)) {
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
          + '\nDoctrine: project_outcome_doctrine_v0_1_2026_05_27',
        );
      }
    });
  }
});
