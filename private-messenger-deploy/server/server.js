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
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const DATA_DIR = path.join(__dirname, 'data');
const QUEUE_FILE = path.join(DATA_DIR, 'queue.json');
const MAX_QUEUE_PER_USER = 500;      // cap offline backlog per recipient
const MAX_MSG_BYTES = 64 * 1024;      // reject absurdly large frames

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

// ---------------------------------------------------------------------------
// HTTP + static + QR helper
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '256kb' }));

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

app.get('/healthz', (_req, res) => res.json({ ok: true, online: clients.size }));

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
      const env = { type: 'msg', from: ws.id, to: msg.to, ts: Date.now(), mid: msg.mid || null, ct: msg.ct };
      const dest = clients.get(msg.to);
      if (dest) { send(dest, env); send(ws, { type: 'ack', mid: env.mid, status: 'delivered' }); }
      else { enqueue(msg.to, env); send(ws, { type: 'ack', mid: env.mid, status: 'queued' }); }
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
