/*
 * db.js — local persistence via IndexedDB.
 *   kv        : identity bundle, identity card, settings
 *   contacts  : people you added by scanning their QR
 *   messages  : full chat history, indexed by peer id
 * Everything stays on the device. Nothing here is uploaded.
 */
const DB = (() => {
  let dbp = null;
  function open() {
    if (dbp) return dbp;
    dbp = new Promise((resolve, reject) => {
      const req = indexedDB.open('private-messenger', 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains('kv')) db.createObjectStore('kv');
        if (!db.objectStoreNames.contains('contacts')) db.createObjectStore('contacts', { keyPath: 'id' });
        if (!db.objectStoreNames.contains('messages')) {
          const m = db.createObjectStore('messages', { keyPath: 'mid' });
          m.createIndex('peer', 'peer', { unique: false });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return dbp;
  }
  function tx(store, mode, fn) {
    return open().then(db => new Promise((resolve, reject) => {
      const t = db.transaction(store, mode);
      const s = t.objectStore(store);
      const r = fn(s);
      t.oncomplete = () => resolve(r && r.result !== undefined ? r.result : undefined);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    }));
  }

  // kv
  const kvGet = (k) => tx('kv', 'readonly', s => s.get(k));
  const kvSet = (k, v) => tx('kv', 'readwrite', s => s.put(v, k));

  // contacts
  const putContact = (c) => tx('contacts', 'readwrite', s => s.put(c));
  const getContact = (id) => tx('contacts', 'readonly', s => s.get(id));
  const delContact = (id) => tx('contacts', 'readwrite', s => s.delete(id));
  const allContacts = () => tx('contacts', 'readonly', s => s.getAll());

  // messages
  const putMessage = (m) => tx('messages', 'readwrite', s => s.put(m));
  const getMessage = (mid) => tx('messages', 'readonly', s => s.get(mid));
  function messagesFor(peer) {
    return open().then(db => new Promise((resolve, reject) => {
      const t = db.transaction('messages', 'readonly');
      const idx = t.objectStore('messages').index('peer');
      const out = [];
      idx.openCursor(IDBKeyRange.only(peer)).onsuccess = (e) => {
        const cur = e.target.result;
        if (cur) { out.push(cur.value); cur.continue(); }
        else resolve(out.sort((a, b) => a.ts - b.ts));
      };
      t.onerror = () => reject(t.error);
    }));
  }
  const deleteConversation = (peer) => open().then(db => new Promise((resolve, reject) => {
    const t = db.transaction('messages', 'readwrite');
    const idx = t.objectStore('messages').index('peer');
    idx.openCursor(IDBKeyRange.only(peer)).onsuccess = (e) => {
      const cur = e.target.result;
      if (cur) { cur.delete(); cur.continue(); }
    };
    t.oncomplete = resolve; t.onerror = () => reject(t.error);
  }));

  return {
    kvGet, kvSet,
    putContact, getContact, delContact, allContacts,
    putMessage, getMessage, messagesFor, deleteConversation,
  };
})();
