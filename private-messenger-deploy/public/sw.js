/*
 * Service worker — caches the app shell so it opens instantly and works
 * offline (you can read old messages; sending needs a connection).
 * Bump CACHE when you change any static file.
 */
const CACHE = 'pm-v1';
const SHELL = [
  '/', '/index.html', '/style.css', '/crypto.js', '/db.js', '/app.js',
  '/vendor/jsQR.js', '/manifest.json',
  '/icons/icon-192.png', '/icons/icon-512.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  // never cache the websocket or the dynamic QR endpoint
  if (url.pathname === '/ws' || url.pathname === '/qr' || url.pathname === '/healthz') return;
  if (e.request.method !== 'GET') return;
  // cache-first for the shell, network fallback otherwise
  e.respondWith(
    caches.match(e.request).then((cached) => cached || fetch(e.request).then((res) => {
      if (res.ok && url.origin === location.origin) {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy));
      }
      return res;
    }).catch(() => cached))
  );
});
