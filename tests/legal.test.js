'use strict';

// Smoke + content tests for the legal/compliance pages served from the
// gateway itself. The DPA, BAA, and GDPR Art. 28 docs are templates that
// counsel must complete before execution — we just verify the routes are
// wired, the docs render as HTML, the TEMPLATE banner is present, and
// the signature block exists. Anything more specific would become
// brittle every time legal counsel asks for a wording tweak.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-api-legal-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.OLLAMA_URL = 'http://ollama.test';
process.env.DEFAULT_MODEL = 'qwen2.5:3b-instruct';

const request = require('supertest');
const { createApp } = require('../src/index');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function buildApp() {
  return createApp();
}

describe('legal templates — DPA / BAA / GDPR Art. 28', () => {
  const cases = [
    {
      route: '/dpa',
      mustInclude: [
        'Data Processing Addendum',
        'Controller',
        'Processor',
        'Sub-processor',
        'Standard Contractual Clauses',
        '72',                 // 72-hour breach notification
        'thirty (30) days',   // deletion window
      ],
    },
    {
      route: '/baa',
      mustInclude: [
        'Business Associate Agreement',
        'HIPAA',
        'Covered Entity',
        'Business Associate',
        '164.504(e)',         // the controlling CFR
        '164.524',            // individual access
        '164.526',            // amendment
        '164.528',            // accounting of disclosures
        'HHS',                // secretary access
      ],
    },
    {
      route: '/gdpr',
      mustInclude: [
        'GDPR',
        'Article 28',
        'Controller',
        'Processor',
        '(a)',
        '(h)',
        'Standard Contractual Clauses',
      ],
    },
  ];

  for (const { route, mustInclude } of cases) {
    test(`GET ${route} → 200, HTML, with TEMPLATE banner + signature block`, async () => {
      const app = buildApp();
      const res = await request(app).get(route);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/text\/html/);

      const body = res.text;
      // Counsel-review banner — present + uppercase.
      expect(body).toContain('TEMPLATE');
      expect(body).toContain('counsel review');
      // Signature block — every template has By:/Name:/Title:/Date: rows.
      expect(body).toMatch(/By:\s*_+/);
      expect(body).toMatch(/Name:\s*\[/);
      expect(body).toMatch(/Title:\s*\[/);
      expect(body).toMatch(/Date:\s*_+/);

      for (const needle of mustInclude) {
        expect(body).toContain(needle);
      }
    });
  }

  test('all three templates link back to /sub-processors', async () => {
    const app = buildApp();
    for (const route of ['/dpa', '/baa', '/gdpr']) {
      const res = await request(app).get(route);
      expect(res.text).toContain('/sub-processors');
    }
  });

  test('templates do NOT claim SOC 2 Type II certification (only audit engaged)', async () => {
    // Hard never per the brief — until the SOC 2 report lands we say
    // "engaged / report expected" and not "certified".
    const app = buildApp();
    for (const route of ['/dpa', '/baa', '/gdpr']) {
      const res = await request(app).get(route);
      expect(res.text).not.toMatch(/SOC\s*2[^.]*certified/i);
    }
  });
});

describe('GET /sub-processors', () => {
  test('returns 200 HTML listing Azure / Stripe / GitHub', async () => {
    const app = buildApp();
    const res = await request(app).get('/sub-processors');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    expect(res.text).toContain('Microsoft Azure');
    expect(res.text).toContain('Stripe');
    expect(res.text).toContain('GitHub');
    // Last-updated date is rendered.
    expect(res.text).toContain('Last updated:');
  });
});

describe('existing legal pages remain green', () => {
  // Belt + braces: make sure adding the new exports didn't regress the
  // original three pages.
  for (const route of ['/terms', '/privacy', '/aup']) {
    test(`GET ${route} → 200 HTML`, async () => {
      const app = buildApp();
      const res = await request(app).get(route);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/text\/html/);
    });
  }
});
