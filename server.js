import express from 'express';
import axios from 'axios';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import 'dotenv/config';

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

const PI_API_BASE = process.env.PI_API_BASE;
const PI_API_KEY = process.env.PI_API_KEY;

// Axios client carrying your Server API Key on every Pi call.
const piServer = axios.create({
  baseURL: PI_API_BASE,
  timeout: 20000,
  headers: { Authorization: `Key ${PI_API_KEY}` },
});

const sessions = new Map(); // token -> { uid, username }

// ── 1. Verify the Pioneer's access token against /me ────────────────
// The frontend's accessToken is untrusted until this succeeds.
async function requirePiUser(req, res, next) {
  const token = req.cookies.pi_session;
  const session = token && sessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const { data } = await axios.get(`${PI_API_BASE}/me`, {
      headers: { Authorization: `Bearer ${session.accessToken}` },
    });
    req.pioneer = { uid: data.uid, username: data.username };
    next();
  } catch (err) {
    res.status(401).json({ error: 'Pi token invalid or expired' });
  }
}

app.post('/api/auth/verify', async (req, res) => {
  const { accessToken } = req.body;
  if (!accessToken) return res.status(400).json({ error: 'accessToken required' });

  try {
    // Pi Platform API /me — Bearer with the Pioneer's token.
    const { data } = await axios.get(`${PI_API_BASE}/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const sessionId = crypto.randomUUID();
    sessions.set(sessionId, { accessToken, uid: data.uid, username: data.username });
    res.cookie('pi_session', sessionId, {
      httpOnly: true,
      sameSite: 'none',
      secure: true,
      maxAge: 3600_000,
    });
    res.json({ uid: data.uid, username: data.username });
  } catch (err) {
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// ── 2. U2A payment: approve then complete ───────────────────────────
// Pi calls these from the frontend callbacks; the SDK blocks
// until the server approves, so speed matters here.
app.post('/api/payments/approve', async (req, res) => {
  const { paymentId } = req.body;
  try {
    const { data } = await piServer.post(`/payments/${paymentId}/approve`);
    console.log(`Approved ${paymentId} for ${data.amount} Pi`);
    res.json(data);
  } catch (err) {
    console.error('Approve failed:', err.response?.data || err.message);
    res.status(500).json({ error: 'Approval failed' });
  }
});

app.post('/api/payments/complete', async (req, res) => {
  const { paymentId, txid } = req.body;
  try {
    // Verify the txid against your own records / the blockchain
    // before releasing goods — never trust it blindly.
    const { data } = await piServer.post(`/payments/${paymentId}/complete`, { txid });
    console.log(`Completed ${paymentId} tx ${txid}`);
    res.json(data);
  } catch (err) {
    console.error('Complete failed:', err.response?.data || err.message);
    res.status(500).json({ error: 'Completion failed' });
  }
});

// ── 3. Blockchain reads: proxy to Horizon so no key leaks ──────────
// Public, no auth — but proxied so the frontend talks to one origin.
const PI_HORIZON = '[api.mainnet.minepi.com](https://api.mainnet.minepi.com)';

app.get('/api/blockchain/account/:address', async (req, res) => {
  try {
    const { data } = await axios.get(
      `${PI_HORIZON}/accounts/${req.params.address}`
    );
    const native = data.balances.find((b) => b.asset_type === 'native');
    res.json({
      address: data.account_id,
      balance: native ? native.balance : '0',
      sequence: data.sequence,
    });
  } catch (err) {
    res.status(404).json({ error: 'Account not found on Pi blockchain' });
  }
});

app.get('/api/blockchain/payments/:address', async (req, res) => {
  try {
    const { data } = await axios.get(
      `${PI_HORIZON}/accounts/${req.params.address}/payments`,
      { params: { order: 'desc', limit: 20, include_failed: false } }
    );
    res.json(
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
  } catch (err) {
    res.status(500).json({ error: 'Could not read ledger' });
  }
});

// ── 4. A2U payout from the app wallet (Stellar-signed) ─────────────
// Requires your app wallet's private seed. Uncomment only when
// you have a funded app wallet and understand the risk.
//
// import PiNetwork from 'pi-backend';
// const pi = new PiNetwork(PI_API_KEY, process.env.PI_WALLET_SEED);
// app.post('/api/payout', async (req, res) => {
//   const payment = await pi.createPayment({
//     amount: req.body.amount,
//     memo: 'Reward',
//     metadata: { reason: req.body.reason },
//     uid: req.body.uid,
//   });
//   res.json(payment);
// });

app.listen(process.env.PORT || 3000, () =>
  console.log(`Pi app running on :${process.env.PORT || 3000}`)
);
