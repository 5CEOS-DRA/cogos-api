'use strict';

// Tests for the public /trust dashboard.
//
// Goals:
//   1. GET /trust returns 200 with HTML
//   2. Page renders a known status word (Operational | Degraded | Outage)
//   3. Strict CSP header is present on the response (must continue to deny
//      inline script execution)
//   4. The page body contains NO `<script>` tags with inline content —
//      the CSP would block them at parse time and inline scripts are an
//      easy regression vector to introduce by accident

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-trust-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.OLLAMA_URL = 'http://ollama.test';
process.env.DEFAULT_MODEL = 'qwen2.5:3b-instruct';

const request = require('supertest');
const { createApp } = require('../src/index');
const trust = require('../src/trust');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

describe('GET /trust', () => {
  test('returns 200 and HTML content-type', async () => {
    const app = createApp();
    const res = await request(app).get('/trust');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
  });

  test('page renders a known status word', async () => {
    const app = createApp();
    const res = await request(app).get('/trust');
    expect(res.text).toMatch(/Operational|Degraded|Outage/);
  });

  test('strict CSP header is present', async () => {
    const app = createApp();
    const res = await request(app).get('/trust');
    const csp = res.headers['content-security-policy'];
    expect(csp).toBeDefined();
    // Defense-in-depth: confirm the CSP still denies inline scripts. The
    // gateway-wide CSP is "script-src 'self'" (no 'unsafe-inline').
    expect(csp).toMatch(/script-src 'self'/);
    expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
  });

  test('contains no inline <script> tags with bodies', async () => {
    const app = createApp();
    const res = await request(app).get('/trust');
    // An inline script would be `<script>...code...</script>`. External
    // script tags (`<script src="..."></script>`) are allowed by CSP and
    // are also absent from this page — but the regex below specifically
    // flags non-empty inline bodies as a regression.
    const inlineScript = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
    let m;
    const inlineBodies = [];
    while ((m = inlineScript.exec(res.text)) !== null) {
      if (m[1] && m[1].trim().length > 0) inlineBodies.push(m[1].trim().slice(0, 80));
    }
    expect(inlineBodies).toEqual([]);
  });

  test('shows the image tag tile and tenant audit link', async () => {
    const app = createApp();
    const res = await request(app).get('/trust');
    expect(res.text).toContain('Image tag');
    expect(res.text).toContain('/v1/audit');
  });

  test('mirrors at least one SECURITY.md §3 claim verbatim by ID', async () => {
    const app = createApp();
    const res = await request(app).get('/trust');
    // §3.3 Response signature (HMAC) is the canonical shipped claim — if
    // this drops out of the table, the section has regressed.
    expect(res.text).toContain('&sect;3.3');
    expect(res.text).toContain('Response signature (HMAC)');
  });

  test('renders an honest placeholder for advisories when none published', async () => {
    const app = createApp();
    const res = await request(app).get('/trust');
    expect(res.text).toMatch(/No published advisories/i);
  });

  test('NAV link to /trust is present on /cookbook and /whitepaper', async () => {
    const app = createApp();
    const ck = await request(app).get('/cookbook');
    expect(ck.text).toMatch(/href="\/trust"/);
    const wp = await request(app).get('/whitepaper');
    expect(wp.text).toMatch(/href="\/trust"/);
  });
});

describe('trust.formatUptime', () => {
  test('days + hours when >= 24h', () => {
    expect(trust.formatUptime(86400 * 2 + 3600 * 3)).toBe('2 days 3 hours');
  });
  test('hours + min when 1h..24h', () => {
    expect(trust.formatUptime(3600 + 120)).toBe('1 hour 2 min');
  });
  test('min + sec when < 1h', () => {
    expect(trust.formatUptime(125)).toBe('2 min 5 sec');
  });
  test('seconds when < 1 min', () => {
    expect(trust.formatUptime(7)).toBe('7 sec');
  });
  test('coerces garbage to 0', () => {
    expect(trust.formatUptime('nope')).toBe('0 sec');
  });
});

describe('trust.buildTrustState', () => {
  test('respects COGOS_IMAGE_TAG env override', () => {
    const prev = process.env.COGOS_IMAGE_TAG;
    process.env.COGOS_IMAGE_TAG = 'cogos-api--0000099';
    try {
      const s = trust.buildTrustState({ healthOk: true });
      expect(s.imageTag).toBe('cogos-api--0000099');
      expect(s.status).toBe('operational');
      expect(s.statusLabel).toBe('Operational');
    } finally {
      if (prev === undefined) delete process.env.COGOS_IMAGE_TAG;
      else process.env.COGOS_IMAGE_TAG = prev;
    }
  });

  test('falls back to package.json version when env is unset', () => {
    const prev = process.env.COGOS_IMAGE_TAG;
    delete process.env.COGOS_IMAGE_TAG;
    try {
      const s = trust.buildTrustState({ healthOk: true });
      expect(typeof s.imageTag).toBe('string');
      expect(s.imageTag.length).toBeGreaterThan(0);
    } finally {
      if (prev !== undefined) process.env.COGOS_IMAGE_TAG = prev;
    }
  });

  test('cosign.published is false when no pubkey env is configured', () => {
    const prev1 = process.env.COSIGN_PUBKEY_PEM;
    const prev2 = process.env.COSIGN_PUBKEY_FILE;
    delete process.env.COSIGN_PUBKEY_PEM;
    delete process.env.COSIGN_PUBKEY_FILE;
    try {
      const s = trust.buildTrustState({ healthOk: true });
      expect(s.cosign.published).toBe(false);
      expect(s.cosign.detail).toMatch(/pending/i);
    } finally {
      if (prev1 !== undefined) process.env.COSIGN_PUBKEY_PEM = prev1;
      if (prev2 !== undefined) process.env.COSIGN_PUBKEY_FILE = prev2;
    }
  });

  test('cosign.published is true when COSIGN_PUBKEY_PEM is a valid PEM', () => {
    const prev = process.env.COSIGN_PUBKEY_PEM;
    process.env.COSIGN_PUBKEY_PEM
      = '-----BEGIN PUBLIC KEY-----\nMFkwEwYH/test/payload/abc\n-----END PUBLIC KEY-----\n';
    try {
      const s = trust.buildTrustState({ healthOk: true });
      expect(s.cosign.published).toBe(true);
      expect(s.cosign.detail).toMatch(/cosign pubkey served/i);
    } finally {
      if (prev === undefined) delete process.env.COSIGN_PUBKEY_PEM;
      else process.env.COSIGN_PUBKEY_PEM = prev;
    }
  });

  test('loads pentest history from PENTEST_HISTORY_FILE when set', () => {
    const file = path.join(tmpDir, 'pentest.json');
    fs.writeFileSync(file, JSON.stringify({
      entries: [{
        date: '2026-04-01',
        scope: 'unit-test scope',
        severity_counts: { high: 1, low: 2 },
        fix_cadence_summary: 'all fixed in 7d',
      }],
    }));
    const prev = process.env.PENTEST_HISTORY_FILE;
    process.env.PENTEST_HISTORY_FILE = file;
    try {
      const s = trust.buildTrustState({ healthOk: true });
      expect(s.pentestHistory.length).toBe(1);
      expect(s.pentestHistory[0].scope).toBe('unit-test scope');
    } finally {
      if (prev === undefined) delete process.env.PENTEST_HISTORY_FILE;
      else process.env.PENTEST_HISTORY_FILE = prev;
    }
  });
});

describe('trust.trustHtml direct render', () => {
  test('degraded state renders the Degraded label and styling class', () => {
    const html = trust.trustHtml({
      status: 'degraded',
      statusLabel: 'Degraded',
      imageTag: 'test-tag',
      uptimeSeconds: 100,
      cosign: { published: false, detail: 'Cosign pubkey publication pending' },
      advisories: [],
      pentestHistory: [],
      renderedAt: '2026-05-14T00:00:00.000Z',
    });
    expect(html).toMatch(/Degraded/);
    expect(html).toMatch(/banner degraded/);
  });

  test('renders advisories when provided', () => {
    const html = trust.trustHtml({
      status: 'operational',
      statusLabel: 'Operational',
      imageTag: 'x',
      uptimeSeconds: 1,
      cosign: { published: false, detail: 'pending' },
      advisories: [{
        id: 'COGOS-2026-001',
        date: '2026-05-14',
        severity: 'medium',
        summary: 'Sample advisory for unit-test rendering.',
      }],
      pentestHistory: [],
      renderedAt: '2026-05-14T00:00:00.000Z',
    });
    expect(html).toContain('COGOS-2026-001');
    expect(html).toContain('Sample advisory for unit-test rendering.');
  });

  test('escapes HTML in dynamic state fields', () => {
    const html = trust.trustHtml({
      status: 'operational',
      statusLabel: 'Operational',
      imageTag: '<script>alert(1)</script>',
      uptimeSeconds: 0,
      cosign: { published: false, detail: '<img onerror=alert(1)>' },
      advisories: [],
      pentestHistory: [],
      renderedAt: '2026-05-14T00:00:00.000Z',
    });
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).not.toContain('<img onerror=alert(1)>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });
});
