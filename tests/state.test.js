'use strict';

/**
 * /v1/state · per-key stateful substrate · HTTP-boundary tests.
 *
 * Engine determinism is proven at the platform layer
 * (5ceos-platform-internal/backend/tests/substrate-keyState.test.js,
 * 23 cases). These tests prove the HTTP boundary preserves the
 * journal integrity end-to-end, AND that the 5Law conflict check
 * correctly consumes stored state when use_stored_state=true.
 */

process.env.NODE_ENV = 'test';
process.env.ADMIN_KEY = 'test-admin-key-very-long';

const fs = require('fs');
const path = require('path');
const os = require('os');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cogos-state-test-'));
process.env.KEYS_FILE = path.join(tmpDir, 'keys.json');
process.env.USAGE_FILE = path.join(tmpDir, 'usage.jsonl');
process.env.PACKAGES_FILE = path.join(tmpDir, 'packages.json');
process.env.HONEYPOTS_FILE = path.join(tmpDir, 'honeypots.jsonl');
process.env.RATE_LIMITS_FILE = path.join(tmpDir, 'rate-limits.jsonl');
process.env.STATE_DIR = path.join(tmpDir, 'state');

const request = require('supertest');
const { createApp } = require('../src/index');

afterAll(() => {
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
});

async function issueKey(app, tenantId, tier = 'starter') {
  const res = await request(app).post('/admin/keys').set('X-Admin-Key', process.env.ADMIN_KEY).send({ tenant_id: tenantId, tier });
  return res.body;
}

describe('state · auth + shape', () => {
  test('POST /v1/state/matters without auth → 401', async () => {
    const app = createApp();
    const res = await request(app).post('/v1/state/matters').send({ matter: { id: 'M1' } });
    expect(res.status).toBe(401);
  });

  test('POST /v1/state/matters · missing body → 400 with receipt', async () => {
    const app = createApp();
    const issued = await issueKey(app, 'state-shape-' + Date.now());
    const res = await request(app).post('/v1/state/matters').set('Authorization', 'Bearer ' + issued.api_key).send({});
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_input');
    expect(res.body.receipt.deterministic_hash).toMatch(/^sha256:/);
  });
});

describe('state · happy path · single matter upsert', () => {
  test('upsert matter then read state · journal length 1, state_hash anchors row', async () => {
    const app = createApp();
    const tenant = 'state-happy-' + Date.now();
    const issued = await issueKey(app, tenant);
    const auth = 'Bearer ' + issued.api_key;

    const upsert = await request(app).post('/v1/state/matters').set('Authorization', auth).send({
      matter: { id: 'M_a', status: 'active', practice_area: 'corporate' },
    });
    expect(upsert.status).toBe(200);
    expect(upsert.body.state_version).toBe(1);
    expect(upsert.body.state_hash).toMatch(/^sha256:/);
    expect(upsert.body.rows).toHaveLength(1);

    const read = await request(app).get('/v1/state').set('Authorization', auth);
    expect(read.status).toBe(200);
    expect(read.body.state_version).toBe(1);
    expect(read.body.matters.M_a.status).toBe('active');
    expect(read.body.state_hash).toBe(upsert.body.state_hash);
    expect(read.body.anchor).toMatch(/^sha256:/);
  });
});

describe('state · batch upsert + parties + archive + remove', () => {
  test('full mutation surface · journal integrity preserved end-to-end', async () => {
    const app = createApp();
    const tenant = 'state-full-' + Date.now();
    const issued = await issueKey(app, tenant);
    const auth = 'Bearer ' + issued.api_key;

    // batch upsert 2 matters
    let r = await request(app).post('/v1/state/matters').set('Authorization', auth).send({
      matters: [
        { id: 'M1', status: 'active', practice_area: 'corp' },
        { id: 'M2', status: 'active', practice_area: 'tax' },
      ],
    });
    expect(r.body.state_version).toBe(2);

    // parties on M1
    r = await request(app).post('/v1/state/parties').set('Authorization', auth).send({
      matter_id: 'M1',
      parties: [
        { id: 'p1', party_role: 'client',  display_name: 'Acme' },
        { id: 'p2', party_role: 'adverse', display_name: 'Globex' },
      ],
    });
    expect(r.body.state_version).toBe(3);

    // remove a party
    r = await request(app).post('/v1/state/parties/remove').set('Authorization', auth).send({
      matter_id: 'M1', party_ids: ['p2'],
    });
    expect(r.body.state_version).toBe(4);

    // archive M2
    r = await request(app).post('/v1/state/matters/M2/archive').set('Authorization', auth).send({});
    expect(r.body.state_version).toBe(5);

    // verify final state
    const read = await request(app).get('/v1/state').set('Authorization', auth);
    expect(read.body.state_version).toBe(5);
    expect(read.body.matters.M1.status).toBe('active');
    expect(read.body.matters.M2.status).toBe('closed');
    expect(read.body.parties.M1).toHaveLength(1);
    expect(read.body.parties.M1[0].id).toBe('p1');
  });
});

describe('state · journal endpoint exposes hash-chained rows', () => {
  test('journal returns chained rows with verifiable prev_hash linkage', async () => {
    const app = createApp();
    const tenant = 'state-journal-' + Date.now();
    const issued = await issueKey(app, tenant);
    const auth = 'Bearer ' + issued.api_key;

    await request(app).post('/v1/state/matters').set('Authorization', auth).send({ matter: { id: 'M_x', status: 'active' } });
    await request(app).post('/v1/state/matters').set('Authorization', auth).send({ matter: { id: 'M_y', status: 'closed' } });

    const j = await request(app).get('/v1/state/journal').set('Authorization', auth);
    expect(j.status).toBe(200);
    expect(j.body.rows).toHaveLength(2);
    expect(j.body.anchor).toMatch(/^sha256:/);
    // row 0's prev_hash must equal the anchor
    expect(j.body.rows[0].prev_hash).toBe(j.body.anchor);
    // row 1's prev_hash must equal row 0's row_hash
    expect(j.body.rows[1].prev_hash).toBe(j.body.rows[0].row_hash);
  });
});

describe('state · per-tenant isolation', () => {
  test('two keys see independent journals · no cross-bleed', async () => {
    const app = createApp();
    const issuedA = await issueKey(app, 'tenantA-' + Date.now());
    const issuedB = await issueKey(app, 'tenantB-' + Date.now());

    await request(app).post('/v1/state/matters').set('Authorization', 'Bearer ' + issuedA.api_key).send({ matter: { id: 'A1', status: 'active' } });
    await request(app).post('/v1/state/matters').set('Authorization', 'Bearer ' + issuedB.api_key).send({ matter: { id: 'B1', status: 'active' } });

    const stateA = await request(app).get('/v1/state').set('Authorization', 'Bearer ' + issuedA.api_key);
    const stateB = await request(app).get('/v1/state').set('Authorization', 'Bearer ' + issuedB.api_key);

    expect(stateA.body.matters.A1).toBeDefined();
    expect(stateA.body.matters.B1).toBeUndefined();
    expect(stateB.body.matters.B1).toBeDefined();
    expect(stateB.body.matters.A1).toBeUndefined();
    // Different anchors per key
    expect(stateA.body.anchor).not.toBe(stateB.body.anchor);
  });
});

describe('state · 5Law conflict-check use_stored_state integration', () => {
  test('journal-in firm graph once, then conflict check against stored state', async () => {
    const app = createApp();
    const tenant = 'state-5law-' + Date.now();
    const issued = await issueKey(app, tenant);
    const auth = 'Bearer ' + issued.api_key;

    // Journal a firm matter where Acme is a current client.
    await request(app).post('/v1/state/matters').set('Authorization', auth).send({
      matter: { id: 'M_old', status: 'active', practice_area: 'corporate' },
    });
    await request(app).post('/v1/state/parties').set('Authorization', auth).send({
      matter_id: 'M_old',
      parties: [{ id: 'p_acme', party_role: 'client', display_name: 'Acme' }],
    });

    // Now run a conflict check WITHOUT supplying firm_matters · use stored.
    const check = await request(app).post('/v1/process/5law-conflict-check').set('Authorization', auth).send({
      use_stored_state: true,
      target_matter: { id: 'M_new', status: 'inquiry', practice_area: 'litigation' },
      target_parties: [
        { id: 'p_new1', party_role: 'client', display_name: 'Bob' },
        { id: 'p_new2', party_role: 'adverse', display_name: 'Acme' },
      ],
    });

    expect(check.status).toBe(200);
    expect(check.body.rows.length).toBeGreaterThan(0);
    const da = check.body.rows.find((r) => r.rule_id === 'C_DIRECT_ADVERSITY');
    expect(da).toBeDefined();
    expect(da.conflicting_matter_id).toBe('M_old');
    // The response carries the state_version/state_hash so the receipt
    // also commits to which point-in-time of the journal was queried.
    expect(check.body.state_version).toBe(2);
    expect(check.body.state_hash).toMatch(/^sha256:/);
  });

  test('use_stored_state=false (or absent) ignores the journal entirely', async () => {
    const app = createApp();
    const tenant = 'state-no-stored-' + Date.now();
    const issued = await issueKey(app, tenant);
    const auth = 'Bearer ' + issued.api_key;

    // Put something in the journal · which a non-stored-state call must ignore.
    await request(app).post('/v1/state/matters').set('Authorization', auth).send({
      matter: { id: 'M_irrelevant', status: 'active', practice_area: 'corp' },
    });

    // Conflict check WITHOUT use_stored_state · supplies its own firm_matters.
    const check = await request(app).post('/v1/process/5law-conflict-check').set('Authorization', auth).send({
      target_matter: { id: 'M_new', status: 'inquiry', practice_area: 'litigation' },
      target_parties: [
        { id: 'p1', party_role: 'client', display_name: 'Bob' },
        { id: 'p2', party_role: 'adverse', display_name: 'Acme' },
      ],
      firm_matters: [],
      parties_by_matter_id: {},
    });

    expect(check.status).toBe(200);
    expect(check.body.rows).toEqual([]);
    // No state_version when stored-state isn't used.
    expect(check.body.state_version).toBeUndefined();
  });
});

describe('state · billing · one usage row per write, none per read', () => {
  test('write emits usage row; read does not', async () => {
    const app = createApp();
    const tenant = 'state-bill-' + Date.now();
    const issued = await issueKey(app, tenant);
    const auth = 'Bearer ' + issued.api_key;

    await request(app).post('/v1/state/matters').set('Authorization', auth).send({ matter: { id: 'X', status: 'active' } });
    await request(app).get('/v1/state').set('Authorization', auth);
    await request(app).get('/v1/state/journal').set('Authorization', auth);

    const audit = await request(app).get('/v1/audit').set('Authorization', auth);
    const stateRows = (audit.body.rows || []).filter((r) => r.route && r.route.startsWith('/v1/state'));
    expect(stateRows).toHaveLength(1);
    expect(stateRows[0].model).toBe('process:key-state-v1');
    expect(stateRows[0].route).toBe('/v1/state/matters');
  });
});
