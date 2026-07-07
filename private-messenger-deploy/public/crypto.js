/*
 * crypto.js — all cryptography runs in the browser. Keys never leave the device.
 *
 *   Identity = two P-256 keypairs:
 *     - sign (ECDSA)  -> proves who you are to the server (auth challenge)
 *     - dh   (ECDH)   -> derives a shared secret with each contact for E2E
 *
 *   Your public ID  = base64url(SHA-256(signPublicKey))[0..21]
 *   Messages are AES-256-GCM encrypted with a key derived per-contact via
 *   ECDH + HKDF. The server only ever relays ciphertext.
 */
const C = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // --- base64 helpers -------------------------------------------------------
  function bufToB64(buf) {
    const b = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }
  function b64ToBuf(b64) {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out.buffer;
  }
  const b64url = (buf) => bufToB64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const b64urlToBuf = (s) => b64ToBuf(s.replace(/-/g, '+').replace(/_/g, '/'));

  // --- identity -------------------------------------------------------------
  async function generateIdentity() {
    const sign = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const dh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    return {
      signPriv: await crypto.subtle.exportKey('pkcs8', sign.privateKey),
      signPub: await crypto.subtle.exportKey('spki', sign.publicKey),
      dhPriv: await crypto.subtle.exportKey('pkcs8', dh.privateKey),
      dhPub: await crypto.subtle.exportKey('spki', dh.publicKey),
    };
  }

  async function fingerprint(signPubSpki) {
    const hash = await crypto.subtle.digest('SHA-256', signPubSpki);
    return b64url(hash).slice(0, 22);
  }

  // Build the identity object we serialise (into QR / storage).
  async function identityCard(idBundle, name) {
    return {
      v: 1,
      n: name || 'Anonymous',
      spk: b64url(idBundle.signPub),
      epk: b64url(idBundle.dhPub),
      id: await fingerprint(idBundle.signPub),
    };
  }

  // --- auth signing ---------------------------------------------------------
  async function signNonce(signPrivPkcs8, nonceB64Std) {
    const key = await crypto.subtle.importKey('pkcs8', signPrivPkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const nonce = b64ToBuf(nonceB64Std); // server sends standard base64
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, nonce); // raw r||s (64 bytes)
    return b64url(sig);
  }

  // --- per-contact shared key (ECDH -> HKDF -> AES-GCM) ---------------------
  async function deriveKey(myDhPrivPkcs8, peerEpkB64url, myId, peerId) {
    const priv = await crypto.subtle.importKey('pkcs8', myDhPrivPkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const peerPub = await crypto.subtle.importKey('spki', b64urlToBuf(peerEpkB64url), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const secret = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPub }, priv, 256);
    const hkdfKey = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
    // salt is the two ids sorted, so both sides derive the same key
    const salt = enc.encode([myId, peerId].sort().join('|'));
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('private-messenger-v1') },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // --- password lock: encrypt the identity's private keys at rest ----------
  async function passKey(password, salt) {
    const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }
  // Encrypt the two private keys with a key derived from the password.
  async function wrapIdentity(idBundle, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await passKey(password, salt);
    const payload = JSON.stringify({ signPriv: b64url(idBundle.signPriv), dhPriv: b64url(idBundle.dhPriv) });
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(payload));
    return { salt: b64url(salt), iv: b64url(iv), data: b64url(data) };
  }
  // Decrypt them back given the correct password (throws if wrong).
  async function unwrapIdentity(box, password) {
    const key = await passKey(password, new Uint8Array(b64urlToBuf(box.salt)));
    const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(b64urlToBuf(box.iv)) }, key, b64urlToBuf(box.data));
    const obj = JSON.parse(dec.decode(data));
    return { signPriv: b64urlToBuf(obj.signPriv), dhPriv: b64urlToBuf(obj.dhPriv) };
  }

  // Seal/open an arbitrary string with a password (for the cloud backup blob).
  async function sealWithPassword(password, plaintext) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await passKey(password, salt);
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
    return JSON.stringify({ salt: b64url(salt), iv: b64url(iv), data: b64url(data) });
  }
  async function openWithPassword(password, blobStr) {
    const box = JSON.parse(blobStr);
    const key = await passKey(password, new Uint8Array(b64urlToBuf(box.salt)));
    const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(b64urlToBuf(box.iv)) }, key, b64urlToBuf(box.data));
    return dec.decode(data);
  }

  async function encrypt(aesKey, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(plaintext));
    return { iv: b64url(iv), data: b64url(data) };
  }

  async function decrypt(aesKey, ct) {
    const iv = new Uint8Array(b64urlToBuf(ct.iv));
    const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, b64urlToBuf(ct.data));
    return dec.decode(data);
  }

  return { generateIdentity, fingerprint, identityCard, signNonce, deriveKey, encrypt, decrypt, wrapIdentity, unwrapIdentity, sealWithPassword, openWithPassword, b64url, b64urlToBuf };
})();
