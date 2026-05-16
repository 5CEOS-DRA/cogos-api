'use strict';

// Tests for /admin/health/deep — the deep health-check endpoint that
// Application Insights Availability Tests hit. Verifies:
//   - X-Admin-Key gating (401 without, 200/503 with)
//   - shape contract (the 5 fields the runbook + alert rules read)
//   - rolling counters: anomaly_events_last_hour, daily_cap_fires_today
//   - tail-window p99 sampled from usage.jsonl
//   - status code flips to 503 when chain_ok=false OR thresholds breached
//   - graceful degradation when source files are missing

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

let tmpDir;
let app;
let request;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-health-deep-test-'));
  process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
  process.env.ANOMALIES_FILE = path.join(tmpDir, 'anomalies.jsonl');
  process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
  process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
  process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
  process.env.CHECKPOINTS_FILE = path.join(tmpDir, 'audit-checkpoints.jsonl');
  process.env.HONEYPOTS_FILE = path.join(tmpDir, 'honeypots.jsonl');
  process.env.NOTIFY_SIGNUPS_FILE = path.join(tmpDir, 'notify-signups.jsonl');
  process.env.USAGE_ROLLUP_DIR = tmpDir;
  process.env.USAGE_ROLLUP_FIRST_DELAY_MS = '999999';
  process.env.USAGE_ROLLUP_INTERVAL_MS = '999999';
  jest.resetModules();
  request = require('supertest');
  app = require('../src/index').createApp();
});

afterEach(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

function writeJsonl(name, rows) {
  fs.writeFileSync(
    path.join(tmpDir, name),
    rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''),
  );
}

describe('/admin/health/deep — auth', () => {
  test('no X-Admin-Key → 401', async () => {
    const res = await request(app).get('/admin/health/deep');
    expect(res.status).toBe(401);
  });

  test('wrong X-Admin-Key → 401', async () => {
    const res = await request(app)
      .get('/admin/health/deep')
      .set('X-Admin-Key', 'nope');
    expect(res.status).toBe(401);
  });
});

describe('/admin/health/deep — empty substrate', () => {
  test('all files missing → 200 with zeros + chain_ok true (empty chain)', async () => {
    const res = await request(app)
      .get('/admin/health/deep')
      .set('X-Admin-Key', 'test-admin-key-very-long');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.chain_ok).toBe(true);
    expect(res.body.audit_writes_per_min).toBe(0);
    expect(res.body.daily_cap_fires_today).toBe(0);
    expect(res.body.anomaly_events_last_hour).toBe(0);
    expect(res.body.inference_p99_5min_ms).toBe(0);
    expect(Array.isArray(res.body.checks_failed)).toBe(true);
    expect(res.body.checks_failed.length).toBe(0);
    expect(typeof res.body.duration_ms).toBe('number');
  });
});

describe('/admin/health/deep — counters', () => {
  test('counts daily_quota_* events from today only', async () => {
    const today = new Date().toISOString().slice(0, 10);
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000)
      .toISOString().slice(0, 10);
    writeJsonl('rate-limits.jsonl', [
      // 3 today — counted
      { ts: `${today}T01:00:00.000Z`, kind: 'daily_quota_request', tenant_id: 'a' },
      { ts: `${today}T02:00:00.000Z`, kind: 'daily_quota_token', tenant_id: 'a' },
      { ts: `${today}T03:00:00.000Z`, kind: 'daily_quota_request', tenant_id: 'b' },
      // not a daily-cap fire — ignored
      { ts: `${today}T01:30:00.000Z`, kind: 'rate_limit_ip', tenant_id: 'a' },
      // yesterday — ignored
      { ts: `${yesterday}T01:00:00.000Z`, kind: 'daily_quota_request', tenant_id: 'a' },
    ]);
    const res = await request(app)
      .get('/admin/health/deep')
      .set('X-Admin-Key', 'test-admin-key-very-long');
    expect(res.status).toBe(200);
    expect(res.body.daily_cap_fires_today).toBe(3);
  });

  test('counts scanner_active + auth_brute_force_suspected in last hour', async () => {
    const now = Date.now();
    const tenMinAgo = new Date(now - 10 * 60 * 1000).toISOString();
    const halfHourAgo = new Date(now - 30 * 60 * 1000).toISOString();
    const twoHoursAgo = new Date(now - 2 * 60 * 60 * 1000).toISOString();
    writeJsonl('anomalies.jsonl', [
      { ts: tenMinAgo, kind: 'scanner_active', ip: '1.2.3.4' },
      { ts: halfHourAgo, kind: 'auth_brute_force_suspected', ip: '5.6.7.8' },
      // wrong kind — ignored
      { ts: tenMinAgo, kind: 'anomalous_traffic', ip: '9.9.9.9' },
      // too old — ignored
      { ts: twoHoursAgo, kind: 'scanner_active', ip: '10.10.10.10' },
    ]);
    const res = await request(app)
      .get('/admin/health/deep')
      .set('X-Admin-Key', 'test-admin-key-very-long');
    expect(res.status).toBe(200);
    expect(res.body.anomaly_events_last_hour).toBe(2);
  });

  test('inference_p99_5min_ms reflects recent latencies', async () => {
    const now = Date.now();
    const sample = [];
    for (let i = 0; i < 10; i += 1) {
      sample.push({
        ts: new Date(now - (i * 30 * 1000)).toISOString(),
        tenant_id: 'a',
        prompt_tokens: 1,
        completion_tokens: 1,
        latency_ms: (i + 1) * 100, // 100, 200, ..., 1000
        status: 'success',
      });
    }
    writeJsonl('usage.jsonl', sample);
    const res = await request(app)
      .get('/admin/health/deep')
      .set('X-Admin-Key', 'test-admin-key-very-long');
    expect(res.status).toBe(200);
    // p99 of [100..1000] nearest-rank = 1000
    expect(res.body.inference_p99_5min_ms).toBe(1000);
    expect(res.body.audit_writes_per_min).toBeGreaterThan(0);
  });
});

describe('/admin/health/deep — thresholds flip ok=false + 503', () => {
  test('>50 daily_quota fires today flips ok=false + 503', async () => {
    const today = new Date().toISOString().slice(0, 10);
    const rows = [];
    for (let i = 0; i < 51; i += 1) {
      rows.push({ ts: `${today}T01:00:0${i % 10}.000Z`, kind: 'daily_quota_request', tenant_id: `t${i}` });
    }
    writeJsonl('rate-limits.jsonl', rows);
    const res = await request(app)
      .get('/admin/health/deep')
      .set('X-Admin-Key', 'test-admin-key-very-long');
    expect(res.status).toBe(503);
    expect(res.body.ok).toBe(false);
    expect(res.body.daily_cap_fires_today).toBe(51);
  });

  test('>10 anomaly events in last hour flips ok=false + 503', async () => {
    const nowIso = new Date().toISOString();
    const rows = [];
    for (let i = 0; i < 11; i += 1) {
      rows.push({ ts: nowIso, kind: 'scanner_active', ip: `1.2.3.${i}` });
    }
    writeJsonl('anomalies.jsonl', rows);
    const res = await request(app)
      .get('/admin/health/deep')
      .set('X-Admin-Key', 'test-admin-key-very-long');
    expect(res.status).toBe(503);
    expect(res.body.ok).toBe(false);
    expect(res.body.anomaly_events_last_hour).toBe(11);
  });

  test('p99 latency > 15s flips ok=false + 503', async () => {
    const now = Date.now();
    const rows = [];
    for (let i = 0; i < 10; i += 1) {
      rows.push({
        ts: new Date(now - i * 30 * 1000).toISOString(),
        tenant_id: 'a',
        prompt_tokens: 1, completion_tokens: 1,
        latency_ms: 20000,
        status: 'success',
      });
    }
    writeJsonl('usage.jsonl', rows);
    const res = await request(app)
      .get('/admin/health/deep')
      .set('X-Admin-Key', 'test-admin-key-very-long');
    expect(res.status).toBe(503);
    expect(res.body.ok).toBe(false);
    expect(res.body.inference_p99_5min_ms).toBe(20000);
  });
});

describe('/admin/health/deep — shape contract', () => {
  test('has all 6 fields the runbook + alert rules read', async () => {
    const res = await request(app)
      .get('/admin/health/deep')
      .set('X-Admin-Key', 'test-admin-key-very-long');
    const required = [
      'ok',
      'ts',
      'chain_ok',
      'audit_writes_per_min',
      'daily_cap_fires_today',
      'anomaly_events_last_hour',
      'inference_p99_5min_ms',
      'duration_ms',
    ];
    for (const k of required) {
      expect(res.body).toHaveProperty(k);
    }
  });
});
