import { Hono } from 'hono';
import { sign, verify } from 'hono/jwt';

const app = new Hono();

const PI_API_BASE = '[api.minepi.com](https://api.minepi.com/v2)';
const PI_HORIZON = '[api.testnet.minepi.com](https://api.testnet.minepi.com)';
// Pi calls from a Worker, with your Server API Key from env.
// Secrets arrive on `env` — never in the bundle.
const piServer = (env) => ({
  headers: {
    Authorization: `Key ${env.PI_API_KEY}`,
    'Content-Type': 'application/json',
  },
});

// ── Session: signed JWT, not a memory Map ───────────────────────────
// Workers don't share memory across invocations, so sessions
// must be stateless. Sign a short-lived token instead.
async function makeSession(env, pioneer) {
  const exp = Math.floor(Date.now() / 1000) + 60 * 60; // 1 hour
  return await sign({ ...pioneer, exp }, env.SESSION_SECRET);
}

async function requirePiUser(c, next) {
  const cookie = c.req.header('Cookie') || '';
  const match = cookie.match(/pi_session=([^;]+)/);
  if (!match) return c.json({ error: 'Not authenticated' }, 401);

  try {
    const payload = await verify(match[1], c.env.SESSION_SECRET);
    c.set('pioneer', { uid: payload.uid, username: payload.username });
    await next();
  } catch {
    return c.json({ error: 'Session invalid or expired' }, 401);
  }
}

// ── 1. Verify the Pioneer's access token against /me ────────────────
app.post('/api/auth/verify', async (c) => {
  const { accessToken } = await c.req.json();
  if (!accessToken) return c.json({ error: 'accessToken required' }, 400);

  const res = await fetch(`${PI_API_BASE}/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) return c.json({ error: 'Authentication failed' }, 401);

  const user = await res.json();
  const token = await makeSession(c.env, { uid: user.uid, username: user.username });

  c.header(
    'Set-Cookie',
    `pi_session=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=3600`
  );
  return c.json({ uid: user.uid, username: user.username });
});

// ── 2. U2A payment: approve then complete ───────────────────────────
// The SDK blocks until /approve returns, so keep this fast —
// a single fetch out, nothing else in the path.
app.post('/api/payments/approve', async (c) => {
  const { paymentId } = await c.req.json();
  const res = await fetch(`${PI_API_BASE}/payments/${paymentId}/approve`, {
    method: 'POST',
    headers: piServer(c.env),
  });
  const data = await res.json();
  if (!res.ok) return c.json({ error: 'Approval failed' }, 500);
  return c.json(data);
});

app.post('/api/payments/complete', async (c) => {
  const { paymentId, txid } = await c.req.json();
  const res = await fetch(`${PI_API_BASE}/payments/${paymentId}/complete`, {
    method: 'POST',
    headers: piServer(c.env),
    body: JSON.stringify({ txid }),
  });
  const data = await res.json();
  if (!res.ok) return c.json({ error: 'Completion failed' }, 500);
  return c.json(data);
});

// ── 3. Blockchain reads via Horizon ─────────────────────────────────
app.get('/api/blockchain/account/:address', async (c) => {
  const { address } = c.req.param();
  const res = await fetch(`${PI_HORIZON}/accounts/${address}`);
  if (!res.ok) return c.json({ error: 'Account not found on Pi blockchain' }, 404);

  const data = await res.json();
  const native = data.balances.find((b) => b.asset_type === 'native');
  return c.json({
    address: data.account_id,
    balance: native ? native.balance : '0',
    sequence: data.sequence,
  });
});

app.get('/api/blockchain/payments/:address', async (c) => {
  const { address } = c.req.param();
  const res = await fetch(
    `${PI_HORIZON}/accounts/${address}/payments?order=desc&limit=20&include_failed=false`
  );
  if (!res.ok) return c.json({ error: 'Could not read ledger' }, 500);

  const data = await res.json();
  return c.json(
    data._embedded.records.map((p) => ({
      id: p.id,
      type: p.type,
      amount: p.amount,
      asset: p.asset_type === 'native' ? 'Pi' : p.asset_code,
      from: p.from,
      to: p.to,
      txid: p.transaction_hash,
      createdAt: p.created_at,
    }))
  );
});

// Anything not matched and not a static asset → serve the SPA.
app.get('*', (c) => c.env.ASSETS.fetch(c.req.raw));

export default app;
