'use strict';
/*
 * Private Messenger — self-hosted relay server.
 *
 * What it does:
 *   - Serves the PWA (../public) over HTTP.
 *   - Runs a WebSocket relay at /ws.
 *   - Authenticates each client with a signature challenge (proves they own
 *     the private key behind their public ID) so nobody can impersonate an ID.
 *   - Routes end-to-end ENCRYPTED messages from sender to recipient by ID.
 *   - Queues messages for offline recipients and flushes on reconnect.
 *
 * What it does NOT do:
 *   - It never sees message plaintext. Bodies are encrypted client-side
 *     (ECDH + AES-GCM). The server only sees {from, to, ts, ciphertext}.
 *
 * Storage: a single JSON file (data/queue.json) for the offline queue.
 * Fine for a small trusted group. Swap for a real DB if you scale.
 */

const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const qrcode = require('qrcode');
const webpush = require('web-push');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
// Persist state to a mounted disk when DATA_DIR is set (survives redeploys),
// otherwise fall back to a local folder (ephemeral on Render).
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const QUEUE_FILE = path.join(DATA_DIR, 'queue.json');
const SUBS_FILE = path.join(DATA_DIR, 'subs.json');
const MAX_QUEUE_PER_USER = 200;       // cap offline backlog per recipient
const MAX_MSG_BYTES = 12 * 1024 * 1024; // allow encrypted photos (~ up to a few MB)

// Web Push (content-less notifications). Keys come from env so the private key
// is never committed. If absent, push is simply disabled.
const OWNER_TOKEN = process.env.OWNER_TOKEN || '';   // master-only cloud backup gate
const VAPID_PUBLIC = process.env.VAPID_PUBLIC || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE || '';
// Apple's web push rejects an invalid VAPID "subject" (e.g. a .local mailto),
// which is why iOS delivery can fail while Android/FCM accepts it.
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'https://coca-cola-u5p0.onrender.com';
let PUSH_ENABLED = !!(VAPID_PUBLIC && VAPID_PRIVATE);
if (PUSH_ENABLED) {
  try {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE);
  } catch (e) {
    console.warn('Invalid VAPID keys — push disabled:', e.message);
    PUSH_ENABLED = false;   // bad keys must not crash the server
  }
}

// ---------------------------------------------------------------------------
// Offline queue (file-backed)
// ---------------------------------------------------------------------------
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
let queue = {};   // { recipientId: [envelope, ...] }
try {
  queue = JSON.parse(fs.readFileSync(QUEUE_FILE, 'utf8'));
} catch (_) {
  queue = {};
}
let saveTimer = null;
function persistQueue() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(QUEUE_FILE, JSON.stringify(queue), () => {});
  }, 200);
}
function enqueue(id, env) {
  if (!queue[id]) queue[id] = [];
  queue[id].push(env);
  if (queue[id].length > MAX_QUEUE_PER_USER) queue[id].shift();
  persistQueue();
}
function drain(id) {
  const items = queue[id] || [];
  delete queue[id];
  persistQueue();
  return items;
}

// --- Push subscriptions (file-backed) --------------------------------------
let subs = {};   // { userId: PushSubscription }
try { subs = JSON.parse(fs.readFileSync(SUBS_FILE, 'utf8')); } catch (_) { subs = {}; }
let subsTimer = null;
function persistSubs() {
  clearTimeout(subsTimer);
  subsTimer = setTimeout(() => fs.writeFile(SUBS_FILE, JSON.stringify(subs), () => {}), 200);
}
// Send a CONTENT-LESS push (no sender, no text) — just "you have a new message".
let lastPushError = null;   // for diagnostics via /healthz
async function sendPush(id) {
  if (!PUSH_ENABLED || !subs[id]) return;
  try {
    await webpush.sendNotification(subs[id], JSON.stringify({ t: 'msg' }));
  } catch (err) {
    lastPushError = { at: Date.now(), status: err && err.statusCode, body: err && String(err.body || err.message || '').slice(0, 200) };
    if (err && (err.statusCode === 404 || err.statusCode === 410)) {
      delete subs[id]; persistSubs();   // subscription expired/gone
    }
  }
}

// --- Owner-only cloud backup (a single encrypted blob, gated by OWNER_TOKEN) -
const BACKUP_FILE = path.join(DATA_DIR, 'backups.json');
let backups = {};   // { slot: encryptedBlobString }  (slot = hash of the owner token)
try { backups = JSON.parse(fs.readFileSync(BACKUP_FILE, 'utf8')); } catch (_) { backups = {}; }
function persistBackups() { fs.writeFile(BACKUP_FILE, JSON.stringify(backups), () => {}); }
function tokenOk(t) {
  if (!OWNER_TOKEN || typeof t !== 'string' || t.length !== OWNER_TOKEN.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(t), Buffer.from(OWNER_TOKEN)); } catch { return false; }
}
function slotFor(t) { return crypto.createHash('sha256').update(t).digest('hex'); }

// ---------------------------------------------------------------------------
// HTTP + static + QR helper
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '4mb' }));

// Render any string payload as a QR PNG. The client uses this to show its
// identity QR (the identity JSON is passed as ?data=...).
app.get('/qr', async (req, res) => {
  const data = req.query.data;
  if (!data || data.length > 4096) return res.status(400).send('bad data');
  try {
    res.type('png');
    res.send(await qrcode.toBuffer(String(data), { margin: 1, width: 512, errorCorrectionLevel: 'M' }));
  } catch (e) {
    res.status(500).send('qr error');
  }
});

app.get('/healthz', (_req, res) => res.json({
  ok: true, online: clients.size,
  pushEnabled: PUSH_ENABLED, subject: VAPID_SUBJECT,
  subCount: Object.keys(subs).length, lastPushError,
}));

// Public VAPID key + whether push is configured on this server.
app.get('/vapid', (_req, res) => res.json({ enabled: PUSH_ENABLED, key: VAPID_PUBLIC }));

// Whether owner cloud-backup is configured on this server (no secret revealed).
app.get('/cloud-status', (_req, res) => res.json({ enabled: !!OWNER_TOKEN }));

// Store the owner's encrypted backup blob. Requires the owner token.
app.post('/cloud-backup', (req, res) => {
  const { token, blob } = req.body || {};
  if (!tokenOk(token)) return res.status(403).json({ error: 'forbidden' });
  if (typeof blob !== 'string' || blob.length > 3_500_000) return res.status(400).json({ error: 'bad blob' });
  backups[slotFor(token)] = blob; persistBackups();
  res.json({ ok: true });
});

// Fetch the owner's encrypted backup blob back. Requires the owner token.
app.post('/cloud-restore', (req, res) => {
  const { token } = req.body || {};
  if (!tokenOk(token)) return res.status(403).json({ error: 'forbidden' });
  const blob = backups[slotFor(token)];
  if (!blob) return res.status(404).json({ error: 'no backup' });
  res.json({ blob });
});

app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

const server = http.createServer(app);

// ---------------------------------------------------------------------------
// WebSocket relay
// ---------------------------------------------------------------------------
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: MAX_MSG_BYTES });
const clients = new Map();   // id -> ws  (authenticated connections)

function send(ws, obj) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
}

// Compute the ID we expect for a given signing public key (base64url spki).
// Must match the client's fingerprint(): base64url(SHA-256(spkiBytes))[0..21].
function fingerprint(spkB64url) {
  const raw = Buffer.from(spkB64url.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const hash = crypto.createHash('sha256').update(raw).digest();
  return hash.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '').slice(0, 22);
}

// Verify an ECDSA P-256 signature (raw r||s, 64 bytes) over `nonce` using the
// client's spki public key. Node's verify wants DER, so convert raw -> DER.
function verifySig(spkB64url, nonceB64, sigB64) {
  try {
    const spki = Buffer.from(spkB64url.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const keyObj = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    const nonce = Buffer.from(nonceB64, 'base64');
    const rawSig = Buffer.from(sigB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    if (rawSig.length !== 64) return false;
    const der = rawToDer(rawSig);
    return crypto.verify('sha256', nonce, { key: keyObj, dsaEncoding: 'der' }, der);
  } catch (e) {
    return false;
  }
}

// Convert a raw (r||s) ECDSA signature to DER encoding.
function rawToDer(raw) {
  let r = raw.slice(0, 32);
  let s = raw.slice(32, 64);
  const trim = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]); return b; };
  r = trim(r); s = trim(s);
  const seqLen = 2 + r.length + 2 + s.length;
  return Buffer.concat([
    Buffer.from([0x30, seqLen, 0x02, r.length]), r,
    Buffer.from([0x02, s.length]), s,
  ]);
}

wss.on('connection', (ws) => {
  ws.isAuthed = false;
  ws.id = null;
  ws.nonce = null;

  const authTimeout = setTimeout(() => { if (!ws.isAuthed) ws.close(4001, 'auth timeout'); }, 15000);

  ws.on('message', (buf) => {
    let msg;
    try { msg = JSON.parse(buf.toString()); } catch (_) { return; }

    // --- Step 1: client announces id + signing pubkey; we send a challenge.
    if (msg.type === 'hello' && !ws.isAuthed) {
      if (typeof msg.id !== 'string' || typeof msg.spk !== 'string') return ws.close(4002, 'bad hello');
      if (fingerprint(msg.spk) !== msg.id) return ws.close(4003, 'id/key mismatch');
      ws.pendingId = msg.id;
      ws.pendingSpk = msg.spk;
      ws.nonce = crypto.randomBytes(32).toString('base64');
      return send(ws, { type: 'challenge', nonce: ws.nonce });
    }

    // --- Step 2: client returns signature over the nonce; we verify.
    if (msg.type === 'auth' && !ws.isAuthed) {
      if (!ws.nonce || typeof msg.sig !== 'string') return ws.close(4004, 'bad auth');
      if (!verifySig(ws.pendingSpk, ws.nonce, msg.sig)) return ws.close(4005, 'bad signature');
      ws.isAuthed = true;
      ws.id = ws.pendingId;
      clearTimeout(authTimeout);
      // one connection per id: drop any previous
      const prev = clients.get(ws.id);
      if (prev && prev !== ws) prev.close(4006, 'replaced');
      clients.set(ws.id, ws);
      send(ws, { type: 'ready' });
      // flush any queued messages
      for (const env of drain(ws.id)) send(ws, env);
      return;
    }

    if (!ws.isAuthed) return; // ignore anything else pre-auth

    // --- Relay an end-to-end encrypted message. Body is opaque to us.
    if (msg.type === 'msg') {
      if (typeof msg.to !== 'string' || typeof msg.ct !== 'object') return;
      const env = { type: 'msg', from: ws.id, to: msg.to, ts: Date.now(), mid: msg.mid || null, kind: msg.kind || 'text', ct: msg.ct };
      const dest = clients.get(msg.to);
      if (dest) { send(dest, env); send(ws, { type: 'ack', mid: env.mid, status: 'delivered' }); }
      else { enqueue(msg.to, env); send(ws, { type: 'ack', mid: env.mid, status: 'queued' }); sendPush(msg.to); }
      return;
    }

    // --- Register/refresh a Web Push subscription for this user.
    if (msg.type === 'push-subscribe') {
      if (msg.sub && typeof msg.sub === 'object') { subs[ws.id] = msg.sub; persistSubs(); }
      return;
    }

    // --- Mutual add: when A scans B's QR, A sends its own card so B auto-adds A.
    if (msg.type === 'introduce') {
      if (typeof msg.to !== 'string' || !msg.card || typeof msg.card !== 'object') return;
      const env = { type: 'introduce', from: ws.id, card: msg.card };
      const dest = clients.get(msg.to);
      if (dest) send(dest, env); else { enqueue(msg.to, env); sendPush(msg.to); }
      return;
    }

    // --- Typing indicator (also opaque metadata, only relayed if peer online).
    if (msg.type === 'typing') {
      const dest = clients.get(msg.to);
      if (dest) send(dest, { type: 'typing', from: ws.id, on: !!msg.on });
      return;
    }

    // --- Read receipt.
    if (msg.type === 'read') {
      const dest = clients.get(msg.to);
      if (dest) send(dest, { type: 'read', from: ws.id, mids: msg.mids || [] });
      return;
    }

    // --- Presence probe: is a contact currently online?
    if (msg.type === 'ping-presence') {
      send(ws, { type: 'presence', id: msg.id, online: clients.has(msg.id) });
      return;
    }
  });

  ws.on('close', () => {
    clearTimeout(authTimeout);
    if (ws.id && clients.get(ws.id) === ws) clients.delete(ws.id);
  });
  ws.on('error', () => {});
});

// keepalive: drop dead sockets
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isDead) return ws.terminate();
    ws.isDead = true;
    try { ws.ping(); } catch (_) {}
  });
}, 30000);
wss.on('connection', (ws) => { ws.isDead = false; ws.on('pong', () => { ws.isDead = false; }); });

server.listen(PORT, () => {
  console.log(`Private Messenger server listening on http://localhost:${PORT}`);
  console.log(`WebSocket relay at ws path /ws`);
});
