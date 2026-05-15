'use strict';

// Anomaly detector — Security Hardening Card #5. Shadow-mode contract:
// observe + log + counter, NEVER block. Tests cover threshold semantics,
// fire-once-per-window, eviction, log shape, and shadow-mode invariant.

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const request = require('supertest');

let tmpDir;
let anomaliesFile;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-anom-test-'));
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  anomaliesFile = path.join(tmpDir, 'anomalies.jsonl');
  process.env.ANOMALIES_FILE = anomaliesFile;
  // Tight TTL so the eviction test runs without sleeping.
  process.env.ANOMALY_BUCKET_TTL_MS = '120000'; // 2 min default for most tests
  jest.resetModules();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

// Build a paired (app, anomaly) where both come from the SAME module
// registry — otherwise jest.resetModules() between the two requires would
// hand us separate in-memory state and the test would race itself.
function freshPair() {
  jest.resetModules();
  const anom = require('../src/anomaly');
  const { createApp } = require('../src/index');
  return { app: createApp(), anom };
}

function freshApp() {
  return freshPair().app;
}

async function issueKey(app, tenantId, tier = 'starter') {
  const res = await request(app)
    .post('/admin/keys')
    .set('X-Admin-Key', process.env.ADMIN_KEY)
    .send({ tenant_id: tenantId, tier });
  return res.body;
}

function readAnomalies() {
  if (!fs.existsSync(anomaliesFile)) return [];
  const raw = fs.readFileSync(anomaliesFile, 'utf8');
  return raw.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
}

describe('anomaly detector — shadow mode', () => {
  test('11 auth-4xx from one IP within 60s → fires "auth_brute_force_suspected" exactly once', async () => {
    const app = freshApp();
    // Hit a bearer-auth route with no token → 401 each call.
    for (let i = 0; i < 11; i += 1) {
      const r = await request(app).get('/v1/models');
      expect(r.status).toBe(401);
    }
    const events = readAnomalies();
    const fires = events.filter((e) => e.kind === 'auth_brute_force_suspected');
    expect(fires.length).toBe(1);
    expect(fires[0].subject_type).toBe('ip');
    expect(fires[0].window_seconds).toBe(60);
    expect(fires[0].threshold).toBe(10);
    expect(fires[0].count).toBeGreaterThan(10);
    expect(fires[0].context).toEqual(expect.objectContaining({
      last_path: '/v1/models',
    }));
  });

  test('10 auth-4xx does NOT fire (threshold is strict >)', async () => {
    const app = freshApp();
    for (let i = 0; i < 10; i += 1) {
      const r = await request(app).get('/v1/models');
      expect(r.status).toBe(401);
    }
    const events = readAnomalies();
    const fires = events.filter((e) => e.kind === 'auth_brute_force_suspected');
    expect(fires.length).toBe(0);
  });

  test('4 honeypot hits from one IP → fires "scanner_active"', async () => {
    const app = freshApp();
    // /.env, /wp-admin, /.git/config, /xmlrpc.php — all honeypot paths.
    await request(app).get('/.env');
    await request(app).get('/wp-admin');
    await request(app).get('/.git/config');
    await request(app).get('/xmlrpc.php');
    const events = readAnomalies();
    const fires = events.filter((e) => e.kind === 'scanner_active');
    expect(fires.length).toBe(1);
    expect(fires[0].subject_type).toBe('ip');
    expect(fires[0].threshold).toBe(3);
  });

  test('shadow-mode contract — fired anomaly does NOT change response status', async () => {
    const app = freshApp();
    // 11 calls: the 11th crosses the threshold and fires. Every call still
    // returns 401 (the auth-fail status), NOT 429 / 503 / anything else.
    const statuses = [];
    for (let i = 0; i < 11; i += 1) {
      const r = await request(app).get('/v1/models');
      statuses.push(r.status);
    }
    expect(new Set(statuses)).toEqual(new Set([401]));
    // And the fire DID happen, so we know the test is exercising the path.
    expect(readAnomalies().some((e) => e.kind === 'auth_brute_force_suspected')).toBe(true);
  });

  test('per-(tenant, app) schema_violation counter increments only when req.apiKey is set', async () => {
    const { app, anom } = freshPair();
    anom._test.reset();
    // Unauthenticated 401 on /v1/chat/completions should NOT increment any
    // tenant schema_violation counter (no req.apiKey). Multi-app rollout:
    // bucket key is `${tenant_id}:app:${app_id}` — pre-multi-app keys land
    // in the `_default` app bucket.
    await request(app).post('/v1/chat/completions').send({});
    expect(anom._test.getCounter('tenant', 'tenant-x:app:_default', 'schema_violation')).toBe(0);

    // Authenticated tenant call. Without OLLAMA_ENDPOINT configured the
    // upstream is unavailable, so chat-api responds with non-200 — exactly
    // the kind of failure the schema_violation signal is supposed to catch.
    const { api_key } = await issueKey(app, 'tenant-x');
    const res = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({ model: 'qwen2.5:3b-instruct', messages: [{ role: 'user', content: 'hi' }] });
    // Tenant counter should have been incremented for this call IF status
    // != 200. Verify whichever way the upstream resolves.
    const c = anom._test.getCounter('tenant', 'tenant-x:app:_default', 'schema_violation');
    if (res.status === 200) {
      expect(c).toBe(0);
    } else {
      expect(c).toBe(1);
    }
  });

  test('anomaly event lands in the configured ANOMALIES_FILE', async () => {
    const app = freshApp();
    for (let i = 0; i < 11; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await request(app).get('/v1/models');
    }
    expect(fs.existsSync(anomaliesFile)).toBe(true);
    const events = readAnomalies();
    expect(events.length).toBeGreaterThanOrEqual(1);
  });

  test('anomaly log is JSONL (one JSON object per line) and parses correctly', async () => {
    // Force two distinct anomalies and assert the file is line-delimited
    // JSON with every line a valid object having the locked shape.
    const { anom } = freshPair();
    anom._test.reset();
    anom._test.forceFire('auth_brute_force_suspected');
    anom._test.forceFire('scanner_active');
    const raw = fs.readFileSync(anomaliesFile, 'utf8');
    const lines = raw.split('\n').filter((l) => l.length > 0);
    expect(lines.length).toBe(2);
    lines.forEach((line) => {
      // Must NOT have a trailing comma or array wrapper.
      expect(line.startsWith('{')).toBe(true);
      expect(line.endsWith('}')).toBe(true);
      const ev = JSON.parse(line);
      expect(ev).toEqual(expect.objectContaining({
        ts: expect.any(String),
        kind: expect.any(String),
        severity: expect.any(String),
        subject_type: expect.any(String),
        subject_value: expect.any(String),
        window_seconds: expect.any(Number),
        count: expect.any(Number),
        threshold: expect.any(Number),
        context: expect.any(Object),
      }));
      // Timestamp is ISO 8601 (parseable).
      expect(Number.isFinite(Date.parse(ev.ts))).toBe(true);
    });
  });

  test('after the TTL elapses, the IP bucket is evicted on next observe()', async () => {
    // Drive eviction via the test helper (age + force-sweep) rather than
    // sleeping 6 minutes in a unit test.
    const { app, anom } = freshPair();
    anom._test.reset();
    // Generate one bucket.
    await request(app).get('/v1/models');
    expect(anom._test.bucketCount()).toBe(1);
    // Age every bucket past TTL and past the sweep-gating 30s window.
    anom._test.ageAllBuckets(anom._test.BUCKET_TTL_MS + 60_000);
    // Next observe triggers maybeSweep().
    await request(app).get('/.env'); // honeypot path — different bucket entry
    // The previously-aged bucket should have been evicted. The new
    // honeypot hit added one bucket. Counter for the new IP key only.
    expect(anom._test.bucketCount()).toBeLessThanOrEqual(1);
  });

  test('per-(tenant, app) schema_violation buckets — apps inside one tenant are independent', async () => {
    // Two keys, same tenant, different apps. A schema_violation hit
    // against one app must increment its own bucket only; the other
    // app's bucket stays at 0. (IP-based counters cross apps — that
    // path stays single-bucket-per-IP and is covered by the auth-4xx
    // tests above.)
    const { app, anom } = freshPair();
    anom._test.reset();
    const k1 = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-multi', app_id: 'app1' });
    const k2 = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-multi', app_id: 'app2' });
    expect(k1.body.app_id).toBe('app1');
    expect(k2.body.app_id).toBe('app2');

    // Easiest deterministic trigger of the schema_violation observer:
    // a 400 status from /v1/chat/completions (e.g. missing messages).
    // The observer fires whenever req.apiKey is set AND status !== 200
    // AND path is /v1/chat/completions. Going through the auth + bad
    // body path is much more robust than relying on an upstream call
    // to fail in a given direction across test environments.
    const r1 = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${k1.body.api_key}`)
      .send({}); // missing messages → 400 with req.apiKey populated
    expect(r1.status).toBe(400);

    // Bucket subject_value shape: `${tenant_id}:app:${app_id}`.
    const app1Counter = anom._test.getCounter(
      'tenant', 'tenant-multi:app:app1', 'schema_violation');
    const app2Counter = anom._test.getCounter(
      'tenant', 'tenant-multi:app:app2', 'schema_violation');
    expect(app1Counter).toBe(1);
    expect(app2Counter).toBe(0);
  });

  test('per-(tenant, app) buckets: keys with default app land in the _default app bucket', async () => {
    // Key issued without app_id → app_id='_default'. Its
    // schema_violation observations land in the `_default` bucket,
    // NOT a bare-tenant bucket. Pre-multi-app rows + new defaulted
    // rows therefore share the same bucket, which is exactly what
    // back-compat needs.
    const { app, anom } = freshPair();
    anom._test.reset();
    const { api_key } = await issueKey(app, 'tenant-default-only');
    // 400 (missing messages) is the deterministic non-200 trigger. The
    // observer increments the schema_violation counter whenever
    // req.apiKey is set, the path is /v1/chat/completions, and status
    // != 200 — see src/anomaly.js comment block (c).
    const r = await request(app)
      .post('/v1/chat/completions')
      .set('Authorization', `Bearer ${api_key}`)
      .send({});
    expect(r.status).toBe(400);

    const defaultCounter = anom._test.getCounter(
      'tenant', 'tenant-default-only:app:_default', 'schema_violation');
    // Bare-tenant key (legacy shape) is NOT used anymore — confirm it
    // stayed empty. This guards against a regression where someone
    // partially threads app_id and bypasses the new bucket key.
    const bareTenantCounter = anom._test.getCounter(
      'tenant', 'tenant-default-only', 'schema_violation');
    expect(defaultCounter).toBe(1);
    expect(bareTenantCounter).toBe(0);
  });

  test('subject_type and subject_value are server-determined enums/values (no client-controlled content)', async () => {
    // The fields kind/severity/subject_type are enums chosen by the
    // server. subject_value is `ip` (from req.ip) or `tenant`
    // (from req.apiKey.tenant_id) — both server-resolved.
    // Free-form bytes (user-agent, path) live only in context.
    const app = freshApp();
    for (let i = 0; i < 11; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await request(app)
        .get('/v1/models')
        .set('User-Agent', '<script>alert(1)</script>');
    }
    const events = readAnomalies();
    const fire = events.find((e) => e.kind === 'auth_brute_force_suspected');
    expect(['ip', 'tenant', 'global']).toContain(fire.subject_type);
    expect(['warn', 'error']).toContain(fire.severity);
    expect([
      'auth_brute_force_suspected',
      'scanner_active',
      'schema_failure_spike',
      'latency_drift_detected',
    ]).toContain(fire.kind);
    // UA is opaque — passes through unmolested into context, NEVER into
    // any of the typed enum fields.
    expect(fire.context.ua).toBe('<script>alert(1)</script>');
    expect(fire.subject_value).not.toMatch(/<script>/);
  });

  test('default mode (ANOMALY_FAIL_CLOSED unset) — fire does NOT ban; isBlocked stays 0', async () => {
    // Shadow contract: even when the threshold is crossed, the IP is not
    // banned and follow-on requests get the natural status, not 429.
    delete process.env.ANOMALY_FAIL_CLOSED;
    const { app, anom } = freshPair();
    anom._test.reset();
    for (let i = 0; i < 11; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      const r = await request(app).get('/v1/models');
      expect(r.status).toBe(401);
    }
    // The fire happened in shadow mode, but no ban was set.
    expect(anom.isBlocked('::ffff:127.0.0.1')).toBe(0);
    expect(anom.isBlocked('127.0.0.1')).toBe(0);
    expect(anom._test.bansCount()).toBe(0);
  });
});

describe('anomaly detector — fail-closed mode (ANOMALY_FAIL_CLOSED=1)', () => {
  beforeEach(() => {
    process.env.ANOMALY_FAIL_CLOSED = '1';
    // Use a generous per-IP rate limit so 11 auth-failures don't 429 us
    // before they fire the brute-force threshold.
    process.env.RATE_LIMIT_IP_PER_MIN = '200';
  });
  afterEach(() => {
    delete process.env.ANOMALY_FAIL_CLOSED;
    delete process.env.RATE_LIMIT_IP_PER_MIN;
  });

  test('11 auth-4xx from one IP → IP is banned, next request returns 429', async () => {
    const { app, anom } = freshPair();
    anom._test.reset();
    // First 11 calls are 401 (no auth). The 11th crosses the threshold
    // (strict >, threshold=10) and fires auth_brute_force_suspected,
    // which in fail-closed mode sets a 5-min ban on the IP.
    for (let i = 0; i < 11; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await request(app).get('/v1/models');
    }
    // The next request from the same IP should now 429 (banned), not 401.
    const r = await request(app).get('/v1/models');
    expect(r.status).toBe(429);
    expect(r.body.error.type).toBe('rate_limit_exceeded');
    expect(Number(r.headers['retry-after'])).toBeGreaterThan(0);
    // Ban duration is ~5 min so retry-after should be in (0, 300].
    expect(Number(r.headers['retry-after'])).toBeLessThanOrEqual(300);
    expect(anom._test.bansCount()).toBeGreaterThan(0);
  });

  test('4 honeypot hits → IP banned for 15 min', async () => {
    const { app, anom } = freshPair();
    anom._test.reset();
    await request(app).get('/.env');
    await request(app).get('/wp-admin');
    await request(app).get('/.git/config');
    await request(app).get('/xmlrpc.php');
    // 4 honeypots > threshold=3 → fires scanner_active → 15-min ban.
    const r = await request(app).get('/health');
    expect(r.status).toBe(429);
    // 15 min = 900s; retry-after lives in (0, 900].
    expect(Number(r.headers['retry-after'])).toBeGreaterThan(300);
    expect(Number(r.headers['retry-after'])).toBeLessThanOrEqual(900);
  });

  test('schema_failure_spike (per-tenant) is log-only even in fail-closed mode', async () => {
    const { app, anom } = freshPair();
    anom._test.reset();
    // Issue a key so we have a tenant.
    const issue = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-pay', tier: 'starter' });
    // Forge a per-tenant fire by manipulating the bucket counter past
    // threshold and triggering observe via a non-200 chat completion.
    // Simpler: just verify the helper says no IP is banned even though
    // many tenant-scoped fires could happen. We can't trivially fire a
    // schema_failure_spike from supertest without a working upstream;
    // instead, force a ban via forceBan and verify it's IP-keyed, and
    // verify the schema_violation counter increment doesn't change the
    // bans count.
    anom._test.forceBan('1.2.3.4', 1000);
    expect(anom._test.bansCount()).toBe(1);
    // Confirm only IP-scoped fires modify bans — emit a tenant counter
    // bump and confirm bans count is unchanged.
    anom._test.forceFire('schema_failure_spike');
    expect(anom._test.bansCount()).toBe(1);
    // And the issued key call doesn't 429 against the legit IP.
    const r = await request(app)
      .get('/v1/models')
      .set('Authorization', `Bearer ${issue.body.api_key}`);
    expect(r.status).not.toBe(429);
  });

  test('forceBan + isBlocked work as expected; ban expires past untilMs', async () => {
    const { anom } = freshPair();
    anom._test.reset();
    anom._test.forceBan('10.0.0.1', 1000); // 1 second
    expect(anom.isBlocked('10.0.0.1')).toBeGreaterThan(Date.now());
    expect(anom.isBlocked('10.0.0.2')).toBe(0);
    // Simulate expiry by forcing the ban into the past.
    anom._test.forceBan('10.0.0.1', -1);
    expect(anom.isBlocked('10.0.0.1')).toBe(0);
  });

  test('scanner_active + recent valid auth → key is quarantined', async () => {
    // Key lifecycle card commit 3/3: the combo of a scanner-active fire
    // AND a recent (≤60s) successful customer auth from the same IP is
    // the only auto-quarantine trigger. fail-closed mode only.
    const { app, anom } = freshPair();
    const keys = require('../src/keys');
    anom._test.reset();
    const issue = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-quarantine-fc' });
    expect(issue.status).toBe(201);
    // Pre-seed the recent-auth tracker on both the IPv4 + IPv4-mapped-IPv6
    // forms supertest may resolve to.
    anom._test.recordRecentAuth('127.0.0.1', issue.body.key_id);
    anom._test.recordRecentAuth('::ffff:127.0.0.1', issue.body.key_id);
    // 4 honeypot hits → fires scanner_active.
    await request(app).get('/.env');
    await request(app).get('/wp-admin');
    await request(app).get('/.git/config');
    await request(app).get('/xmlrpc.php');
    const rec = keys.findById(issue.body.key_id);
    expect(rec.quarantined_at).toEqual(expect.any(Number));
    expect(rec.quarantine_reason).toBe('scanner_active+valid_auth');
  });
});

describe('anomaly detector — quarantine NOT triggered in shadow mode', () => {
  // Pair test: in shadow mode the same scanner+auth combo must NOT
  // quarantine the key. Quarantine is fail-closed-style; we don't
  // auto-disable customer keys in observe-only mode.
  beforeEach(() => {
    delete process.env.ANOMALY_FAIL_CLOSED;
  });
  test('scanner_active + recent auth in SHADOW mode does NOT quarantine', async () => {
    const { app, anom } = freshPair();
    const keys = require('../src/keys');
    anom._test.reset();
    const issue = await request(app)
      .post('/admin/keys')
      .set('X-Admin-Key', process.env.ADMIN_KEY)
      .send({ tenant_id: 'tenant-quarantine-shadow' });
    anom._test.recordRecentAuth('127.0.0.1', issue.body.key_id);
    anom._test.recordRecentAuth('::ffff:127.0.0.1', issue.body.key_id);
    await request(app).get('/.env');
    await request(app).get('/wp-admin');
    await request(app).get('/.git/config');
    await request(app).get('/xmlrpc.php');
    const rec = keys.findById(issue.body.key_id);
    expect(rec.quarantined_at).toBeFalsy();
  });
});
