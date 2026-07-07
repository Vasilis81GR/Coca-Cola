/*
 * app.js — glue: identity, connection, QR pairing, chat, disappearing
 * messages, photos, count-only notifications + web push.
 */
(() => {
  const $ = (s) => document.querySelector(s);
  const enc = new TextEncoder(), dec = new TextDecoder();
  const EPHEMERAL_MS = 30 * 60 * 1000;   // messages vanish 30 min after being read
  const IMG_MAX = 1024;                   // max photo dimension (px) before sending
  const IMG_QUALITY = 0.6;

  let me = null;                 // { id, name, card, signPriv, dhPriv }
  let ws = null, connected = false, reconnectTimer = null;
  const keyCache = new Map();    // peerId -> AES CryptoKey
  let contacts = new Map();      // id -> contact
  let currentPeer = null;        // open conversation id
  let scanStream = null, scanRAF = null;
  let pendingAdd = null;         // card awaiting confirmation
  let vapidKey = null, pushEnabled = false;
  let sessionPass = null, ownerToken = null, cloudEnabled = false;   // owner cloud backup

  // Android install prompt: capture the event so we can offer a one-tap install button.
  let deferredPrompt = null;
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault(); deferredPrompt = e;
    document.querySelectorAll('.install-app').forEach(b => b.classList.remove('hidden'));
  });
  window.addEventListener('appinstalled', () => {
    deferredPrompt = null;
    document.querySelectorAll('.install-app').forEach(b => b.classList.add('hidden'));
  });

  // --- utilities ------------------------------------------------------------
  const encodeCard = (card) => C.b64url(enc.encode(JSON.stringify(card)));
  const decodeCard = (p) => JSON.parse(dec.decode(C.b64urlToBuf(p)));
  const identityLink = (card) => `${location.origin}/#add=${encodeCard(card)}`;

  function avatarColor(id) {
    let h = 0; for (const c of id) h = (h * 31 + c.charCodeAt(0)) % 360;
    return `hsl(${h} 55% 45%)`;
  }
  function setAvatar(el, name, id) {
    el.textContent = (name || '?').trim().charAt(0).toUpperCase();
    el.style.background = avatarColor(id || name || 'x');
  }
  const fmtTime = (ts) => new Date(ts).toLocaleTimeString('el-GR', { hour: '2-digit', minute: '2-digit' });
  function fmtDay(ts) {
    const d = new Date(ts), now = new Date();
    if (d.toDateString() === now.toDateString()) return 'Σήμερα';
    const y = new Date(now); y.setDate(now.getDate() - 1);
    if (d.toDateString() === y.toDateString()) return 'Χθες';
    return d.toLocaleDateString('el-GR', { day: '2-digit', month: '2-digit', year: 'numeric' });
  }
  let toastTimer;
  function toast(msg) {
    const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.add('hidden'), 2600);
  }
  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

  // --- identity -------------------------------------------------------------
  // Returns the boot state: 'ready' (loaded), 'locked' (needs password), 'new'.
  async function bootState() {
    const encId = await DB.kvGet('identity-enc');
    const pub = await DB.kvGet('identity-pub');
    if (encId && pub) return { state: 'locked', pub };
    const legacy = await DB.kvGet('identity');      // pre-password installs
    if (legacy) { me = legacy; return { state: 'ready' }; }
    return { state: 'new' };
  }
  async function createIdentity(name, password) {
    const bundle = await C.generateIdentity();
    const card = await C.identityCard(bundle, name);
    me = { id: card.id, name, card, signPriv: bundle.signPriv, dhPriv: bundle.dhPriv };
    sessionPass = password;
    await DB.kvSet('identity-pub', { id: card.id, name, card });
    await DB.kvSet('identity-enc', await C.wrapIdentity(bundle, password));
  }
  async function unlock(password) {
    const encId = await DB.kvGet('identity-enc');
    const pub = await DB.kvGet('identity-pub');
    const privs = await C.unwrapIdentity(encId, password);   // throws on wrong password
    me = { id: pub.id, name: pub.name, card: pub.card, signPriv: privs.signPriv, dhPriv: privs.dhPriv };
    sessionPass = password;
  }
  function setInstallQr() {
    const src = '/qr?data=' + encodeURIComponent(location.origin);
    ['#installQr', '#installQrLock', '#inviteQr'].forEach(sel => { const el = $(sel); if (el) el.src = src; });
  }
  async function keyFor(peer) {
    if (keyCache.has(peer.id)) return keyCache.get(peer.id);
    const k = await C.deriveKey(me.dhPriv, peer.epk, me.id, peer.id);
    keyCache.set(peer.id, k);
    return k;
  }

  // --- websocket ------------------------------------------------------------
  function connect() {
    clearTimeout(reconnectTimer);
    const url = (location.protocol === 'https:' ? 'wss' : 'ws') + '://' + location.host + '/ws';
    ws = new WebSocket(url);
    setConn('σύνδεση…');
    ws.onopen = () => ws.send(JSON.stringify({ type: 'hello', id: me.id, spk: me.card.spk }));
    ws.onmessage = async (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (m.type === 'challenge') {
        ws.send(JSON.stringify({ type: 'auth', sig: await C.signNonce(me.signPriv, m.nonce) }));
      } else if (m.type === 'ready') {
        connected = true; setConn('συνδεδεμένος');
        resendPending();
        flushIntroduce();
        registerPush();
        if (currentPeer) probePresence(currentPeer);
      } else if (m.type === 'msg') { await onIncoming(m); }
      else if (m.type === 'introduce') { await onIntroduce(m); }
      else if (m.type === 'ack') { await onAck(m); }
      else if (m.type === 'typing') { if (m.from === currentPeer) showTyping(m.on); }
      else if (m.type === 'read') { await onReadReceipt(m); }
      else if (m.type === 'presence') { if (m.id === currentPeer) $('#peerState').textContent = m.online ? 'online' : 'εκτός σύνδεσης'; }
    };
    ws.onclose = () => { connected = false; setConn('εκτός σύνδεσης'); reconnectTimer = setTimeout(connect, 2500); };
    ws.onerror = () => { try { ws.close(); } catch {} };
  }
  function wsSend(obj) { if (ws && ws.readyState === WebSocket.OPEN) { ws.send(JSON.stringify(obj)); return true; } return false; }
  function setConn(t) { const e = $('#connState'); if (e) e.textContent = t; }
  function probePresence(id) { wsSend({ type: 'ping-presence', id }); }

  // --- sending --------------------------------------------------------------
  async function sendText(text) {
    const peer = contacts.get(currentPeer);
    if (!peer || !text.trim()) return;
    const mid = crypto.randomUUID();
    const msg = { mid, peer: peer.id, dir: 'out', kind: 'text', text, ts: Date.now(), status: 'sending' };
    await DB.putMessage(msg);
    appendMessage(msg); scrollDown();
    await bumpContact(peer.id, 'Μήνυμα', msg.ts);
    const ct = await C.encrypt(await keyFor(peer), text);
    wsSend({ type: 'msg', to: peer.id, mid, kind: 'text', ct });
  }
  async function sendImage(dataUrl) {
    const peer = contacts.get(currentPeer);
    if (!peer) return;
    const mid = crypto.randomUUID();
    const msg = { mid, peer: peer.id, dir: 'out', kind: 'image', img: dataUrl, ts: Date.now(), status: 'sending' };
    await DB.putMessage(msg);
    appendMessage(msg); scrollDown();
    await bumpContact(peer.id, '📷 Φωτογραφία', msg.ts);
    const ct = await C.encrypt(await keyFor(peer), dataUrl);
    wsSend({ type: 'msg', to: peer.id, mid, kind: 'image', ct });
  }
  async function resendPending() {
    for (const peer of contacts.values()) {
      const msgs = await DB.messagesFor(peer.id);
      for (const m of msgs) {
        if (m.dir === 'out' && m.status === 'sending') {
          const payload = m.kind === 'image' ? m.img : m.text;
          const ct = await C.encrypt(await keyFor(peer), payload);
          wsSend({ type: 'msg', to: peer.id, mid: m.mid, kind: m.kind, ct });
        }
      }
    }
  }
  async function onAck(m) {
    const msg = await DB.getMessage(m.mid);
    if (!msg) return;
    msg.status = m.status === 'delivered' ? 'delivered' : 'queued';
    await DB.putMessage(msg); updateTick(msg);
  }
  async function onReadReceipt(m) {
    const exp = m.expireAt || (Date.now() + EPHEMERAL_MS);
    for (const mid of (m.mids || [])) {
      const msg = await DB.getMessage(mid);
      if (msg && msg.dir === 'out') {
        msg.status = 'read';
        if (!msg.expireAt) { msg.readAt = Date.now(); msg.expireAt = exp; }  // same instant as the reader
        await DB.putMessage(msg); updateTick(msg); markExpiring(msg);
      }
    }
  }

  // --- receiving ------------------------------------------------------------
  async function onIncoming(m) {
    const peer = contacts.get(m.from);
    if (!peer) return;                 // not a contact -> ignore
    let payload;
    try { payload = await C.decrypt(await keyFor(peer), m.ct); }
    catch { payload = null; }
    const kind = m.kind === 'image' ? 'image' : 'text';
    const msg = { mid: m.mid || crypto.randomUUID(), peer: peer.id, dir: 'in', kind, ts: m.ts || Date.now() };
    if (kind === 'image') msg.img = payload || '';
    else msg.text = payload == null ? '⚠️ (αποτυχία αποκρυπτογράφησης)' : payload;
    await DB.putMessage(msg);

    if (currentPeer === peer.id && !document.hidden) {
      appendMessage(msg); scrollDown();
      markRead(peer.id, [msg]);        // seen immediately -> starts the 30' timer
    } else {
      await bumpContact(peer.id, kind === 'image' ? '📷 Φωτογραφία' : 'Μήνυμα', msg.ts, true);
      notifyCount();
    }
  }

  // --- disappearing messages ------------------------------------------------
  // Mark given incoming messages as read: start their 30' countdown + tell sender.
  async function markRead(peerId, msgs) {
    const now = Date.now(), exp = now + EPHEMERAL_MS;
    const newMids = [];
    for (const msg of msgs) {
      if (msg.dir !== 'in') continue;
      if (!msg.expireAt) {
        msg.readAt = now; msg.expireAt = exp;
        await DB.putMessage(msg); markExpiring(msg);
        newMids.push(msg.mid);
      }
    }
    // send the receipt with the exact expiry so BOTH sides delete at the same time
    if (newMids.length) wsSend({ type: 'read', to: peerId, mids: newMids, expireAt: exp });
  }
  // Reflect an expireAt onto the DOM node so the ticker shows a countdown.
  function markExpiring(msg) {
    const el = document.querySelector(`.msg[data-mid="${msg.mid}"]`);
    if (el && msg.expireAt) el.dataset.expire = msg.expireAt;
  }
  async function purgeMessage(mid) {
    await DB.delMessage(mid);
    const el = document.querySelector(`.msg[data-mid="${mid}"]`);
    if (el) el.remove();
  }
  // One global 1s ticker updates every visible countdown and deletes at zero.
  setInterval(() => {
    const now = Date.now();
    document.querySelectorAll('.msg[data-expire]').forEach((el) => {
      const exp = +el.dataset.expire;
      const left = exp - now;
      const cd = el.querySelector('.countdown');
      if (left <= 0) { purgeMessage(el.dataset.mid); return; }
      if (cd) { const s = Math.ceil(left / 1000); cd.textContent = `⏱ ${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`; }
    });
  }, 1000);
  // Periodic + on-load sweep also clears expired messages in closed conversations.
  async function sweepExpired() {
    const now = Date.now();
    for (const m of await DB.allMessages()) if (m.expireAt && m.expireAt <= now) await DB.delMessage(m.mid);
  }
  setInterval(sweepExpired, 15000);

  // --- notifications (COUNT ONLY — never reveals sender or text) ------------
  function unreadTotal() { let n = 0; for (const c of contacts.values()) n += (c.unread || 0); return n; }
  function notifyCount() {
    const n = unreadTotal();
    updateBadge(n);
    toast(n === 1 ? '1 νέο μήνυμα' : `${n} νέα μηνύματα`);
    if (document.hidden && 'Notification' in window && Notification.permission === 'granted') {
      try { new Notification('🟡 Bigman', { body: n === 1 ? '1 νέο μήνυμα' : `${n} νέα μηνύματα`, icon: '/icons/icon-192.png', tag: 'pm-count', renotify: true }); } catch {}
    }
  }
  function updateBadge(n) {
    try { if (n > 0) navigator.setAppBadge && navigator.setAppBadge(n); else navigator.clearAppBadge && navigator.clearAppBadge(); } catch {}
  }

  // --- web push (content-less) ----------------------------------------------
  async function registerPush() {
    try {
      if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
      if (vapidKey === null) {
        const r = await fetch('/vapid').then(x => x.json()).catch(() => null);
        pushEnabled = !!(r && r.enabled); vapidKey = r && r.key ? r.key : '';
      }
      if (!pushEnabled || !vapidKey) return;
      // Do NOT auto-request permission here — iOS blocks it outside a user gesture.
      // The "Enable notifications" button asks for permission on tap.
      if (!('Notification' in window) || Notification.permission !== 'granted') return;
      const reg = await navigator.serviceWorker.ready;
      let sub = await reg.pushManager.getSubscription();
      if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlB64ToU8(vapidKey) });
      wsSend({ type: 'push-subscribe', sub: sub.toJSON ? sub.toJSON() : sub });
    } catch (e) { /* push optional */ }
  }
  function urlB64ToU8(b64) {
    const pad = '='.repeat((4 - b64.length % 4) % 4);
    const s = (b64 + pad).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(s); const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  // --- contacts -------------------------------------------------------------
  async function loadContacts() {
    const list = await DB.allContacts();
    contacts = new Map(list.map(c => [c.id, c]));
    renderContacts();
  }
  async function bumpContact(id, last, ts, unread) {
    const c = contacts.get(id); if (!c) return;
    c.last = last; c.lastTs = ts;
    if (unread) c.unread = (c.unread || 0) + 1;
    await DB.putContact(c); renderContacts();
  }
  function renderContacts() {
    const wrap = $('#contactList'); wrap.innerHTML = '';
    const list = [...contacts.values()].sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
    $('#emptyContacts').classList.toggle('hidden', list.length > 0);
    for (const c of list) {
      const el = document.createElement('div');
      el.className = 'contact' + (c.id === currentPeer ? ' active' : '');
      el.innerHTML = `
        <div class="avatar"></div>
        <div class="info">
          <div class="name">${escapeHtml(c.name)}</div>
          <div class="last">${c.last ? escapeHtml(c.last) : 'Νέα επαφή'}</div>
        </div>
        <div style="text-align:right">
          <div class="time">${c.lastTs ? fmtTime(c.lastTs) : ''}</div>
          ${c.unread ? `<div class="badge">${c.unread}</div>` : ''}
        </div>`;
      setAvatar(el.querySelector('.avatar'), c.name, c.id);
      el.onclick = () => openConversation(c.id);
      wrap.appendChild(el);
    }
  }

  // --- conversation ---------------------------------------------------------
  async function openConversation(id) {
    currentPeer = id;
    const peer = contacts.get(id);
    peer.unread = 0; await DB.putContact(peer);
    updateBadge(unreadTotal());
    $('#chat').classList.remove('no-peer');
    $('#app').classList.add('show-chat');
    $('#peerName').textContent = peer.name;
    setAvatar($('#peerAvatar'), peer.name, peer.id);
    $('#peerState').textContent = '';
    probePresence(id);
    const msgs = await DB.messagesFor(id);
    const box = $('#messages'); box.innerHTML = '';
    let lastDay = '';
    for (const m of msgs) {
      const day = fmtDay(m.ts);
      if (day !== lastDay) { addDaySep(day); lastDay = day; }
      appendMessage(m);
    }
    scrollDown(); renderContacts();
    markRead(id, msgs.filter(m => m.dir === 'in'));   // opening = reading -> timers start
  }
  function addDaySep(text) { const d = document.createElement('div'); d.className = 'daysep'; d.textContent = text; $('#messages').appendChild(d); }

  function appendMessage(m) {
    const el = document.createElement('div');
    el.className = 'msg ' + m.dir; el.dataset.mid = m.mid;
    if (m.expireAt) el.dataset.expire = m.expireAt;
    let body;
    if (m.kind === 'image') body = `<img class="photo" src="${m.img || ''}" alt="φωτογραφία" />`;
    else body = `<div class="body">${escapeHtml(m.text || '')}</div>`;
    el.innerHTML = `${body}
      <div class="meta">${fmtTime(m.ts)}${m.dir === 'out' ? `<span class="tick">${tick(m.status)}</span>` : ''}</div>
      <div class="countdown"></div>`;
    if (m.kind === 'image') { const img = el.querySelector('.photo'); img.onclick = () => openPhoto(m.img); }
    $('#messages').appendChild(el);
  }
  function tick(status) { if (status === 'read') return '✓✓'; if (status === 'delivered') return '✓✓'; if (status === 'queued') return '✓'; return '🕓'; }
  function updateTick(msg) {
    const el = document.querySelector(`.msg[data-mid="${msg.mid}"] .tick`);
    if (el) { el.textContent = tick(msg.status); el.style.color = msg.status === 'read' ? '#ffd7d9' : ''; }
  }
  function scrollDown() { const b = $('#messages'); b.scrollTop = b.scrollHeight; }
  let typingHideTimer;
  function showTyping(on) {
    const t = $('#typing');
    if (on) { t.textContent = 'πληκτρολογεί…'; t.classList.remove('hidden'); clearTimeout(typingHideTimer); typingHideTimer = setTimeout(() => t.classList.add('hidden'), 4000); }
    else t.classList.add('hidden');
  }
  function openPhoto(src) { if (!src) return; $('#photoFull').src = src; $('#photoModal').classList.remove('hidden'); }

  // --- image compression ----------------------------------------------------
  function fileToCompressedDataUrl(file) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        let { width: w, height: h } = img;
        if (w > h && w > IMG_MAX) { h = Math.round(h * IMG_MAX / w); w = IMG_MAX; }
        else if (h >= w && h > IMG_MAX) { w = Math.round(w * IMG_MAX / h); h = IMG_MAX; }
        const cv = document.createElement('canvas'); cv.width = w; cv.height = h;
        cv.getContext('2d').drawImage(img, 0, 0, w, h);
        resolve(cv.toDataURL('image/jpeg', IMG_QUALITY));
      };
      img.onerror = reject;
      const fr = new FileReader();
      fr.onload = () => { img.src = fr.result; };
      fr.onerror = reject; fr.readAsDataURL(file);
    });
  }

  // --- QR: show / scan / add ------------------------------------------------
  function showMyQr() {
    const link = identityLink(me.card);
    $('#qrImg').src = '/qr?data=' + encodeURIComponent(link);
    $('#myIdShort').textContent = 'ID: ' + me.id;
    const lf = $('#linkField'); if (lf) { lf.value = link; lf.onclick = () => { lf.select(); }; }
    $('#qrModal').classList.remove('hidden');
  }
  async function startScan() {
    $('#scanModal').classList.remove('hidden'); $('#scanStatus').textContent = '';
    try {
      scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      const v = $('#scanVideo'); v.srcObject = scanStream; await v.play(); scanLoop();
    } catch (e) { $('#scanStatus').textContent = 'Δεν έχω πρόσβαση στην κάμερα (χρειάζεται HTTPS + άδεια).'; }
  }
  function scanLoop() {
    const v = $('#scanVideo');
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    const tick = () => {
      if (!scanStream) return;
      if (v.readyState === v.HAVE_ENOUGH_DATA) {
        canvas.width = v.videoWidth; canvas.height = v.videoHeight;
        ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
        if (code && code.data) { handleScanned(code.data); return; }
      }
      scanRAF = requestAnimationFrame(tick);
    };
    scanRAF = requestAnimationFrame(tick);
  }
  function stopScan() { if (scanRAF) cancelAnimationFrame(scanRAF); scanRAF = null; if (scanStream) { scanStream.getTracks().forEach(t => t.stop()); scanStream = null; } }
  // Decode a QR code from an uploaded image file (gallery / received photo).
  function decodeQrFromFile(file) {
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        const cv = document.createElement('canvas');
        cv.width = img.naturalWidth; cv.height = img.naturalHeight;
        cv.getContext('2d').drawImage(img, 0, 0);
        try {
          const d = cv.getContext('2d').getImageData(0, 0, cv.width, cv.height);
          const code = jsQR(d.data, d.width, d.height);
          resolve(code && code.data ? code.data : null);
        } catch { resolve(null); }
      };
      img.onerror = () => resolve(null);
      const fr = new FileReader(); fr.onload = () => { img.src = fr.result; }; fr.onerror = () => resolve(null); fr.readAsDataURL(file);
    });
  }
  function handleScanned(data) { stopScan(); $('#scanModal').classList.add('hidden'); const card = parseIdentity(data); if (!card) return toast('Μη έγκυρο QR.'); promptAdd(card); }
  function parseIdentity(data) {
    try { let p = data; const i = data.indexOf('#add='); if (i >= 0) p = data.slice(i + 5); const card = decodeCard(p); if (card && card.spk && card.epk && card.id) return card; } catch {}
    return null;
  }
  function promptAdd(card) {
    if (card.id === me.id) return toast('Αυτό είναι το δικό σου QR 🙂');
    pendingAdd = card;
    setAvatar($('#addAvatar'), card.n, card.id);
    $('#addName').textContent = card.n || 'Χωρίς όνομα';
    $('#addId').textContent = 'ID: ' + card.id;
    $('#confirmAdd').textContent = contacts.has(card.id) ? 'Ενημέρωση' : 'Προσθήκη';
    $('#addModal').classList.remove('hidden');
  }
  async function confirmAdd() {
    if (!pendingAdd) return;
    const ex = contacts.get(pendingAdd.id) || {};
    const c = { id: pendingAdd.id, name: pendingAdd.n || 'Χωρίς όνομα', spk: pendingAdd.spk, epk: pendingAdd.epk, addedAt: ex.addedAt || Date.now(), last: ex.last, lastTs: ex.lastTs, unread: ex.unread };
    keyCache.delete(c.id); await DB.putContact(c); contacts.set(c.id, c);
    // Mutual add: tell the other side to add me too (so only one scan is needed).
    sendIntroduce(c.id);
    scheduleCloudBackup();
    $('#addModal').classList.add('hidden'); pendingAdd = null; renderContacts();
    toast('Η επαφή προστέθηκε.'); openConversation(c.id);
  }
  // Send an "introduce" (mutual add); if offline, retry when the socket is ready.
  const pendingIntro = new Set();
  function sendIntroduce(id) { if (!wsSend({ type: 'introduce', to: id, card: me.card })) pendingIntro.add(id); }
  function flushIntroduce() { for (const id of [...pendingIntro]) if (wsSend({ type: 'introduce', to: id, card: me.card })) pendingIntro.delete(id); }
  // Someone scanned my QR -> they introduce themselves -> I auto-add them.
  async function onIntroduce(m) {
    const card = m.card;
    if (!card || !card.id || card.id === me.id || contacts.has(card.id)) return;
    const c = { id: card.id, name: card.n || 'Χωρίς όνομα', spk: card.spk, epk: card.epk, addedAt: Date.now() };
    keyCache.delete(c.id); await DB.putContact(c); contacts.set(c.id, c);
    renderContacts(); scheduleCloudBackup();
    toast(`${c.name} σε πρόσθεσε ✓`);
  }
  // --- settings / password / backup ----------------------------------------
  async function setPassword(pw) {
    sessionPass = pw;
    await DB.kvSet('identity-pub', { id: me.id, name: me.name, card: me.card });
    await DB.kvSet('identity-enc', await C.wrapIdentity({ signPriv: me.signPriv, dhPriv: me.dhPriv }, pw));
    await DB.kvDelete('identity');   // drop any legacy plaintext copy
    scheduleCloudBackup();
  }

  // --- owner-only cloud backup ---------------------------------------------
  let cloudTimer;
  function scheduleCloudBackup() {
    if (!ownerToken || !sessionPass) return;
    clearTimeout(cloudTimer); cloudTimer = setTimeout(cloudBackupNow, 1500);
  }
  async function cloudBackupNow() {
    if (!ownerToken || !sessionPass) return;
    try {
      let encId = await DB.kvGet('identity-enc');
      let pub = await DB.kvGet('identity-pub');
      if (!encId || !pub) {   // ensure identity is password-wrapped first
        pub = { id: me.id, name: me.name, card: me.card };
        encId = await C.wrapIdentity({ signPriv: me.signPriv, dhPriv: me.dhPriv }, sessionPass);
        await DB.kvSet('identity-pub', pub); await DB.kvSet('identity-enc', encId);
      }
      const payload = JSON.stringify({ pub, enc: encId, contacts: await DB.allContacts() });
      const blob = await C.sealWithPassword(sessionPass, payload);
      const r = await fetch('/cloud-backup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: ownerToken, blob }) });
      if (!r.ok && r.status === 403) { toast('Cloud backup: λάθος master token.'); }
    } catch (e) { /* offline etc. */ }
  }
  async function enableCloud(token) {
    // verify token by doing one backup attempt
    ownerToken = token;
    if (!sessionPass) { toast('Όρισε πρώτα κωδικό (Ρυθμίσεις → Όρισε κωδικό).'); ownerToken = null; return; }
    const encId = await DB.kvGet('identity-enc') || await C.wrapIdentity({ signPriv: me.signPriv, dhPriv: me.dhPriv }, sessionPass);
    const pub = await DB.kvGet('identity-pub') || { id: me.id, name: me.name, card: me.card };
    await DB.kvSet('identity-pub', pub); await DB.kvSet('identity-enc', encId);
    const payload = JSON.stringify({ pub, enc: encId, contacts: await DB.allContacts() });
    const blob = await C.sealWithPassword(sessionPass, payload);
    const r = await fetch('/cloud-backup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, blob }) });
    if (r.ok) { await DB.kvSet('owner-token', token); toast('Cloud backup ενεργό ✓'); return true; }
    ownerToken = null;
    toast(r.status === 403 ? 'Λάθος master token.' : 'Απέτυχε (server;).');
    return false;
  }
  async function cloudRestore(token, password) {
    let r;
    try { r = await fetch('/cloud-restore', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) }); }
    catch { toast('Χωρίς σύνδεση στον server.'); return; }
    if (r.status === 403) return toast('Λάθος master token.');
    if (r.status === 404) return toast('Δεν υπάρχει cloud backup.');
    if (!r.ok) return toast('Απέτυχε η επαναφορά.');
    const { blob } = await r.json();
    let payload; try { payload = await C.openWithPassword(password, blob); } catch { return toast('Λάθος κωδικός.'); }
    const b = JSON.parse(payload);
    await DB.kvSet('identity-pub', b.pub);
    await DB.kvSet('identity-enc', b.enc);
    await DB.kvDelete('identity');
    if (Array.isArray(b.contacts)) for (const c of b.contacts) await DB.putContact(c);
    await DB.kvSet('owner-token', token);
    toast('Επαναφορά ολοκληρώθηκε!');
    setTimeout(() => location.reload(), 1000);
  }
  async function exportBackup() {
    const encId = await DB.kvGet('identity-enc');
    const pub = await DB.kvGet('identity-pub');
    if (!encId || !pub) { toast('Όρισε πρώτα κωδικό, μετά κάνε backup.'); return; }
    const backup = { v: 1, app: 'private-messenger', pub, enc: encId, contacts: await DB.allContacts() };
    const blob = new Blob([JSON.stringify(backup)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `private-messenger-backup-${(me.name || 'me').replace(/\s+/g, '_')}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast('Backup κατέβηκε — φύλαξέ το ασφαλή.');
  }
  async function importBackup(file) {
    try {
      const b = JSON.parse(await file.text());
      if (!b.pub || !b.enc) { toast('Μη έγκυρο backup.'); return; }
      await DB.kvSet('identity-pub', b.pub);
      await DB.kvSet('identity-enc', b.enc);
      await DB.kvDelete('identity');
      if (Array.isArray(b.contacts)) for (const c of b.contacts) await DB.putContact(c);
      toast('Επαναφορά έγινε. Βάλε τον κωδικό σου.');
      setTimeout(() => location.reload(), 900);
    } catch { toast('Δεν μπόρεσα να διαβάσω το backup.'); }
  }
  function updateNotifBtn() {
    const b = $('#enableNotif'); if (!b) return;
    const g = ('Notification' in window) && Notification.permission === 'granted';
    b.textContent = g ? '🔔 Ειδοποιήσεις: ενεργές' : '🔔 Ενεργοποίηση ειδοποιήσεων';
  }

  // --- events ---------------------------------------------------------------
  function wireEvents() {
    // one-tap install (Android). On iOS this button stays hidden (no event); use Share → Add to Home Screen.
    document.querySelectorAll('.install-app').forEach(b => b.onclick = async () => {
      if (!deferredPrompt) { toast('Μενού ⋮ του Chrome → «Install app».'); return; }
      deferredPrompt.prompt(); await deferredPrompt.userChoice; deferredPrompt = null;
      document.querySelectorAll('.install-app').forEach(x => x.classList.add('hidden'));
    });
    $('#createIdentity').onclick = async () => {
      const name = $('#nameInput').value.trim() || 'Anonymous';
      const pass = $('#passInput').value;
      if (pass.length < 4) { toast('Βάλε κωδικό τουλάχιστον 4 χαρακτήρων.'); return; }
      $('#createIdentity').disabled = true;
      await createIdentity(name, pass);
      await startApp();
    };
    $('#nameInput').addEventListener('keydown', e => { if (e.key === 'Enter') $('#passInput').focus(); });
    $('#passInput').addEventListener('keydown', e => { if (e.key === 'Enter') $('#createIdentity').click(); });
    // unlock (returning user)
    const doUnlock = async () => {
      const pass = $('#lockPass').value; if (!pass) return;
      $('#lockErr').classList.add('hidden');
      try { await unlock(pass); $('#lock').classList.add('hidden'); await startApp(); }
      catch { $('#lockErr').classList.remove('hidden'); $('#lockPass').value = ''; }
    };
    $('#unlockBtn').onclick = doUnlock;
    $('#lockPass').addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock(); });
    // invite / download QR
    $('#inviteBtn').onclick = () => { setInstallQr(); $('#inviteModal').classList.remove('hidden'); };
    // settings
    $('#meBtn').onclick = () => { $('#settingsId').textContent = 'ID: ' + me.id; updateNotifBtn(); $('#settingsModal').classList.remove('hidden'); };
    $('#enableNotif').onclick = async () => {
      if (!('Notification' in window)) return toast('Ο browser δεν υποστηρίζει ειδοποιήσεις.');
      const p = await Notification.requestPermission();
      if (p === 'granted') { await registerPush(); toast('Ειδοποιήσεις ενεργοποιήθηκαν.'); }
      else toast('Δεν δόθηκε άδεια για ειδοποιήσεις.');
      updateNotifBtn();
    };
    $('#setPassBtn').onclick = () => { $('#newPass').value = ''; $('#settingsModal').classList.add('hidden'); $('#setPassModal').classList.remove('hidden'); };
    $('#savePass').onclick = async () => {
      const pw = $('#newPass').value;
      if (pw.length < 4) return toast('Κωδικός τουλάχιστον 4 χαρακτήρων.');
      await setPassword(pw); $('#setPassModal').classList.add('hidden');
      toast('Ο κωδικός ορίστηκε. Θα τον ζητάει στο άνοιγμα.');
    };
    $('#backupBtn').onclick = exportBackup;
    document.querySelectorAll('.restore-btn').forEach(b => b.onclick = () => $('#restoreFile').click());
    $('#restoreFile').addEventListener('change', (e) => { const f = e.target.files[0]; e.target.value = ''; if (f) importBackup(f); });
    // cloud backup (owner only)
    $('#cloudBtn').onclick = () => { $('#settingsModal').classList.add('hidden'); $('#ownerTokenInput').value = ownerToken || ''; $('#cloudModal').classList.remove('hidden'); };
    $('#enableCloud').onclick = async () => { const t = $('#ownerTokenInput').value.trim(); if (!t) return; if (await enableCloud(t)) $('#cloudModal').classList.add('hidden'); };
    document.querySelectorAll('.cloud-restore-btn').forEach(b => b.onclick = () => { $('#crToken').value = ''; $('#crPass').value = ''; $('#cloudRestoreModal').classList.remove('hidden'); });
    $('#doCloudRestore').onclick = () => { const t = $('#crToken').value.trim(), p = $('#crPass').value; if (!t || !p) return toast('Συμπλήρωσε token και κωδικό.'); cloudRestore(t, p); };
    $('#showQrBtn').onclick = showMyQr;
    $('#scanBtn').onclick = startScan;
    $('#confirmAdd').onclick = confirmAdd;
    // share / copy my invite link (best for remote friending)
    $('#shareLink').onclick = async () => {
      const url = identityLink(me.card);
      if (navigator.share) { try { await navigator.share({ title: 'Πρόσθεσέ με στο Bigman', url }); return; } catch { } }
      try { await navigator.clipboard.writeText(url); toast('Link αντιγράφηκε — επικόλλησέ το σε μήνυμα.'); } catch { toast('Αντέγραψε το link χειροκίνητα.'); }
    };
    $('#copyLink').onclick = async () => {
      try { await navigator.clipboard.writeText(identityLink(me.card)); toast('Το link αντιγράφηκε.'); } catch { toast('Δεν μπόρεσα να αντιγράψω.'); }
    };
    // scan a QR from a saved photo (when someone sent you their QR image)
    $('#qrFromPhoto').onclick = () => $('#qrPhoto').click();
    $('#qrPhoto').addEventListener('change', async (e) => {
      const f = e.target.files[0]; e.target.value = '';
      if (!f) return;
      const data = await decodeQrFromFile(f);
      if (data) handleScanned(data); else toast('Δεν βρέθηκε QR σε αυτή τη φωτό.');
    });
    // add a contact by pasting their invite link (reliable inside the installed app)
    $('#addByLink').onclick = () => {
      const v = $('#pasteLink').value.trim(); if (!v) return;
      const card = parseIdentity(v);
      if (!card) return toast('Μη έγκυρο link. Αντέγραψε ολόκληρο το link (με το #add=).');
      $('#pasteLink').value = ''; stopScan(); $('#scanModal').classList.add('hidden');
      promptAdd(card);
    };
    $('#backBtn').onclick = () => { $('#app').classList.remove('show-chat'); currentPeer = null; renderContacts(); };
    document.querySelectorAll('.close-modal').forEach(b => b.onclick = () => { stopScan(); b.closest('.modal').classList.add('hidden'); });

    $('#sendBtn').onclick = () => {
      const i = $('#msgInput'); const v = i.value; i.value = '';
      i.blur();                          // drop the keyboard so the whole chat is visible
      if (v.trim()) sendText(v);
      setTimeout(scrollDown, 250);
    };
    $('#msgInput').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); $('#sendBtn').click(); } });
    // tap on the messages area dismisses the keyboard (classic behavior)
    $('#messages').addEventListener('click', () => { if (document.activeElement === $('#msgInput')) $('#msgInput').blur(); });
    let typingSent = 0;
    $('#msgInput').addEventListener('input', () => {
      if (!currentPeer) return; const now = Date.now();
      if (now - typingSent > 2000) { wsSend({ type: 'typing', to: currentPeer, on: true }); typingSent = now; }
    });
    // photo attach
    $('#attachBtn').onclick = () => $('#photoInput').click();
    $('#photoInput').addEventListener('change', async (e) => {
      const file = e.target.files[0]; e.target.value = '';
      if (!file || !currentPeer) return;
      try { const dataUrl = await fileToCompressedDataUrl(file); await sendImage(dataUrl); }
      catch { toast('Δεν μπόρεσα να επεξεργαστώ τη φωτογραφία.'); }
    });

    $('#peerMenuBtn').onclick = () => { if (!currentPeer) return; $('#peerMenuName').textContent = contacts.get(currentPeer).name; $('#peerMenu').classList.remove('hidden'); };
    $('#clearChat').onclick = async () => {
      if (!currentPeer) return;
      await DB.deleteConversation(currentPeer);
      const c = contacts.get(currentPeer); c.last = null; c.lastTs = null; await DB.putContact(c);
      $('#messages').innerHTML = ''; $('#peerMenu').classList.add('hidden'); renderContacts(); toast('Η συνομιλία καθαρίστηκε.');
    };
    $('#removeContact').onclick = async () => {
      if (!currentPeer) return; const id = currentPeer;
      await DB.deleteConversation(id); await DB.delContact(id);
      contacts.delete(id); keyCache.delete(id);
      currentPeer = null; $('#chat').classList.add('no-peer'); $('#app').classList.remove('show-chat');
      $('#peerMenu').classList.add('hidden'); renderContacts(); toast('Η επαφή διαγράφηκε.');
    };
    window.addEventListener('hashchange', handleHashAdd);
    // when app regains focus with a conversation open, mark visible incoming as read
    document.addEventListener('visibilitychange', async () => {
      if (!document.hidden && currentPeer) { const msgs = await DB.messagesFor(currentPeer); markRead(currentPeer, msgs.filter(m => m.dir === 'in')); }
    });
  }
  function handleHashAdd() {
    if (location.hash.startsWith('#add=')) {
      const card = parseIdentity(location.hash);
      history.replaceState(null, '', location.pathname);
      if (card) promptAdd(card);
    }
  }

  // --- boot -----------------------------------------------------------------
  async function startApp() {
    $('#onboarding').classList.add('hidden');
    $('#lock').classList.add('hidden');
    $('#app').classList.remove('hidden');
    setAvatar($('#myAvatar'), me.name, me.id);
    $('#myName').textContent = me.name;
    ownerToken = (await DB.kvGet('owner-token')) || null;
    fetch('/cloud-status').then(r => r.json()).then(s => { cloudEnabled = !!(s && s.enabled); }).catch(() => {});
    await sweepExpired();
    await loadContacts();
    updateBadge(unreadTotal());
    connect();
    handleHashAdd();
  }
  async function main() {
    wireEvents();
    setInstallQr();
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
    const b = await bootState();
    if (b.state === 'ready') { await startApp(); }
    else if (b.state === 'locked') { $('#lockHello').textContent = 'Καλωσόρισες ' + (b.pub.name || ''); $('#lock').classList.remove('hidden'); }
    else { $('#onboarding').classList.remove('hidden'); }
  }
  main();
})();
