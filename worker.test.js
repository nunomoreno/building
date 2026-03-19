/**
 * Kerno Worker Tests
 * Runs in Node.js 20 (native fetch, crypto.subtle, crypto.randomUUID).
 * Supabase calls are intercepted via vi.stubGlobal('fetch', ...).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import worker from './worker.js';

// ── Helpers ──────────────────────────────────────────────────────────────────

const BASE = 'https://worker.example.com';
const ENV  = { SUPABASE_API_KEY: 'test', ANTHROPIC_API_KEY: 'test', BREVO_API_KEY: 'test' };
// No RATE_LIMIT_KV → rate limiting is skipped in every test

function req(path, { method = 'GET', body, session } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (session) headers['X-Session-Token'] = session;
  return new Request(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

/**
 * Stubs global fetch.
 * handlers: array of [urlSubstring, responseData | (url, opts) => data]
 * Unmatched requests return [].
 */
function stubFetch(handlers = []) {
  vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
    const urlStr = url?.toString() ?? '';
    for (const [pattern, responder] of handlers) {
      if (urlStr.includes(pattern)) {
        const data = typeof responder === 'function' ? responder(urlStr, opts) : responder;
        return new Response(JSON.stringify(data), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }
    return new Response('[]', { status: 200, headers: { 'Content-Type': 'application/json' } });
  }));
}

/** A session stub: returns a valid, non-expired member row for a given token. */
function sessionMember(overrides = {}) {
  return {
    id:                  overrides.id          ?? 'aaaaaaaa-0000-0000-0000-000000000001',
    username:            overrides.username     ?? 'alice',
    role:                overrides.role         ?? 'user',
    permissions:         overrides.permissions  ?? [],
    session_expires_at:  new Date(Date.now() + 3_600_000).toISOString(), // 1 h ahead
  };
}

afterEach(() => { vi.unstubAllGlobals(); });

// ── CORS ─────────────────────────────────────────────────────────────────────

describe('CORS', () => {
  it('OPTIONS returns 200 with CORS headers', async () => {
    const res = await worker.fetch(req('/', { method: 'OPTIONS' }), ENV);
    expect(res.status).toBe(200);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('https://nunomoreno.github.io');
  });
});

// ── Auth gate ────────────────────────────────────────────────────────────────

describe('Auth gate', () => {
  it('returns 401 with no session token', async () => {
    stubFetch([]); // no Supabase match → validateSession gets empty array
    const res = await worker.fetch(req('/projects'), ENV);
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.code).toBe('UNAUTHENTICATED');
  });

  it('returns 401 with expired/unknown session token', async () => {
    stubFetch([['members?select=', []]]); // Supabase returns no member
    const res = await worker.fetch(req('/projects', { session: 'bad-token' }), ENV);
    expect(res.status).toBe(401);
  });

  it('bypasses auth for /login', async () => {
    stubFetch([['members?username=', []]]); // no matching user → 401 AUTH_FAILED
    const res = await worker.fetch(req('/login', { method: 'POST', body: { username: 'x', password: 'y' } }), ENV);
    // We get AUTH_FAILED (not UNAUTHENTICATED) — proves the route was reached
    const body = await res.json();
    expect(body.code).toBe('AUTH_FAILED');
  });

  it('bypasses auth for /register', async () => {
    // Weak password → 400 WEAK_PASSWORD before any DB call
    const res = await worker.fetch(req('/register', { method: 'POST', body: { username: 'bob', password: 'weak' } }), ENV);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.code).toBe('WEAK_PASSWORD');
  });

  it('/test-store bypasses auth (debug route)', async () => {
    stubFetch([['projects?select=', []]]);
    const res = await worker.fetch(req('/test-store'), ENV);
    expect(res.status).toBe(200);
  });
});

// ── POST /login ───────────────────────────────────────────────────────────────

describe('POST /login', () => {
  it('returns 400 when username or password missing', async () => {
    const res = await worker.fetch(req('/login', { method: 'POST', body: {} }), ENV);
    expect(res.status).toBe(400);
  });

  it('returns 401 AUTH_FAILED for wrong credentials', async () => {
    stubFetch([['members?username=', []]]);
    const res = await worker.fetch(req('/login', { method: 'POST', body: { username: 'nobody', password: 'Password1!' } }), ENV);
    expect(res.status).toBe(401);
    expect((await res.json()).code).toBe('AUTH_FAILED');
  });

  it('returns 200 with token on valid credentials', async () => {
    const member = { id: 'aaaa-0001', username: 'alice', role: 'user', display_name: null, avatar_url: null };
    stubFetch([
      ['members?username=', [member]],          // password check query
      ['members?id=eq.aaaa-0001', {}],           // PATCH session token
      ['group_members?member_id=eq.aaaa-0001', []], // getMembership
    ]);
    const res = await worker.fetch(req('/login', { method: 'POST', body: { username: 'alice', password: 'AnyPassword1!' } }), ENV);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(typeof body.token).toBe('string');
    expect(body.username).toBe('alice');
  });
});

// ── POST /register ────────────────────────────────────────────────────────────

describe('POST /register — password validation', () => {
  const tryRegister = (password) =>
    worker.fetch(req('/register', { method: 'POST', body: { username: 'newuser', password } }), ENV);

  it('rejects password shorter than 10 chars', async () => {
    const res = await tryRegister('Abc1!');
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('WEAK_PASSWORD');
  });

  it('rejects password with no uppercase', async () => {
    const res = await tryRegister('alllowercase1!');
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('WEAK_PASSWORD');
  });

  it('rejects password with no lowercase', async () => {
    const res = await tryRegister('ALLUPPERCASE1!');
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('WEAK_PASSWORD');
  });

  it('rejects password with no number', async () => {
    const res = await tryRegister('NoNumbers!!A');
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('WEAK_PASSWORD');
  });

  it('rejects password with no special character', async () => {
    const res = await tryRegister('NoSpecialChar1');
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('WEAK_PASSWORD');
  });

  it('rejects username longer than 50 chars', async () => {
    const res = await worker.fetch(req('/register', { method: 'POST', body: {
      username: 'a'.repeat(51), password: 'ValidPass1!'
    }}), ENV);
    expect(res.status).toBe(400);
  });

  it('rejects invalid email format', async () => {
    const res = await worker.fetch(req('/register', { method: 'POST', body: {
      username: 'bob', password: 'ValidPass1!', email: 'not-an-email'
    }}), ENV);
    expect(res.status).toBe(400);
  });

  it('accepts a valid registration', async () => {
    stubFetch([
      ['members?username=eq.newuser', []],    // duplicate check → none found
      ['members', { id: 'new-id' }],          // INSERT
    ]);
    const res = await worker.fetch(req('/register', { method: 'POST', body: {
      username: 'newuser', password: 'ValidPass1!'
    }}), ENV);
    expect(res.status).toBe(200);
    expect((await res.json()).success).toBe(true);
  });

  it('rejects duplicate username with 409', async () => {
    stubFetch([['members?username=eq.taken', [{ id: 'existing' }]]]);
    const res = await worker.fetch(req('/register', { method: 'POST', body: {
      username: 'taken', password: 'ValidPass1!'
    }}), ENV);
    expect(res.status).toBe(409);
  });
});

// ── Authorization checks ──────────────────────────────────────────────────────

describe('Authorization', () => {
  it('GET /projects returns 200 for valid session', async () => {
    const member = sessionMember();
    stubFetch([
      ['members?select=', [member]],
      ['projects?data->>owner_username=eq.alice', []],
      ['projects?data::text=ilike.*"assignee":"alice"*', []],
      ['projects?data::text=ilike.*@alice*', []],
    ]);
    const res = await worker.fetch(req('/projects', { session: 'valid-token' }), ENV);
    expect(res.status).toBe(200);
  });

  it('DELETE /projects/:id blocked for non-owner user', async () => {
    const member = sessionMember({ username: 'alice', role: 'user' });
    stubFetch([
      ['members?select=', [member]],                                          // session
      ['projects?id=eq.proj-1&select=data', [{ data: { owner_username: 'bob' } }]], // ownership check
    ]);
    const res = await worker.fetch(req('/projects/proj-1', { method: 'DELETE', session: 'valid-token' }), ENV);
    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe('FORBIDDEN');
  });

  it('DELETE /projects/:id allowed for the owner', async () => {
    const member = sessionMember({ username: 'alice', role: 'user' });
    stubFetch([
      ['members?select=', [member]],
      ['projects?id=eq.proj-1&select=data', [{ data: { owner_username: 'alice' } }]],
      ['projects?id=eq.proj-1', {}], // DELETE call
    ]);
    const res = await worker.fetch(req('/projects/proj-1', { method: 'DELETE', session: 'valid-token' }), ENV);
    expect(res.status).toBe(200);
  });

  it('DELETE /projects/:id allowed for admin', async () => {
    const admin = sessionMember({ username: 'admin', role: 'admin' });
    stubFetch([
      ['members?select=', [admin]],
      ['projects?id=eq.proj-1&select=data', [{ data: { owner_username: 'someone-else' } }]],
      ['projects?id=eq.proj-1', {}],
    ]);
    const res = await worker.fetch(req('/projects/proj-1', { method: 'DELETE', session: 'admin-token' }), ENV);
    expect(res.status).toBe(200);
  });

  it('POST /groups returns 403 for non-admin', async () => {
    const member = sessionMember({ role: 'user' });
    stubFetch([['members?select=', [member]]]);
    const res = await worker.fetch(req('/groups', { method: 'POST', session: 'tok', body: { name: 'Lab A' } }), ENV);
    expect(res.status).toBe(403);
  });

  it('DELETE /members/:id returns 403 for non-admin', async () => {
    const member = sessionMember({ role: 'user' });
    stubFetch([['members?select=', [member]]]);
    const res = await worker.fetch(req('/members/some-id', { method: 'DELETE', session: 'tok' }), ENV);
    expect(res.status).toBe(403);
  });

  it('PUT /members/:id blocked when non-admin updates another user', async () => {
    const alice = sessionMember({ id: 'id-alice', username: 'alice', role: 'user' });
    stubFetch([['members?select=', [alice]]]);
    const res = await worker.fetch(req('/members/id-bob', { method: 'PUT', session: 'tok', body: { display_name: 'hacked' } }), ENV);
    expect(res.status).toBe(403);
  });

  it('POST /settings/:key returns 403 for non-admin', async () => {
    const member = sessionMember({ role: 'user' });
    stubFetch([['members?select=', [member]]]);
    const res = await worker.fetch(req('/settings/request-types', { method: 'POST', session: 'tok', body: {} }), ENV);
    expect(res.status).toBe(403);
  });
});

// ── Booking validation ────────────────────────────────────────────────────────

describe('POST /bookings — input validation', () => {
  const RES_ID  = 'aaaaaaaa-0000-0000-0000-000000000001';
  const validBooking = {
    resource_id: RES_ID,
    date:        '2099-12-01',
    start_time:  '09:00',
    end_time:    '10:00',
    full_day:    false,
  };

  it('rejects invalid resource_id (not a UUID)', async () => {
    const member = sessionMember({ role: 'admin' });
    stubFetch([['members?select=', [member]]]);
    const res = await worker.fetch(req('/bookings', { method: 'POST', session: 'tok', body: {
      ...validBooking, resource_id: 'not-a-uuid'
    }}), ENV);
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('VALIDATION_ERROR');
  });

  it('rejects invalid status value', async () => {
    const member = sessionMember({ role: 'admin' });
    stubFetch([['members?select=', [member]]]);
    const res = await worker.fetch(req('/bookings', { method: 'POST', session: 'tok', body: {
      ...validBooking, status: 'hacked'
    }}), ENV);
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('VALIDATION_ERROR');
  });

  it('rejects notes over 1000 chars', async () => {
    const member = sessionMember({ role: 'admin' });
    stubFetch([['members?select=', [member]]]);
    const res = await worker.fetch(req('/bookings', { method: 'POST', session: 'tok', body: {
      ...validBooking, notes: 'x'.repeat(1001)
    }}), ENV);
    expect(res.status).toBe(400);
    expect((await res.json()).code).toBe('VALIDATION_ERROR');
  });

  it('rejects booking without resource permission (non-admin)', async () => {
    const member = sessionMember({ role: 'user', permissions: [] }); // no permissions
    stubFetch([['members?select=', [member]]]);
    const res = await worker.fetch(req('/bookings', { method: 'POST', session: 'tok', body: validBooking }), ENV);
    expect(res.status).toBe(403);
  });
});

// ── 404 ───────────────────────────────────────────────────────────────────────

describe('404', () => {
  it('returns 404 for unknown routes', async () => {
    const member = sessionMember();
    stubFetch([['members?select=', [member]]]);
    const res = await worker.fetch(req('/nonexistent', { session: 'tok' }), ENV);
    expect(res.status).toBe(404);
  });
});
