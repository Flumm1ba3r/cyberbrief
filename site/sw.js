// Offline support. The app shell is served from cache and refreshed in the background;
// the briefing is fetched from the network first, falling back to the last copy when offline.
const SHELL_CACHE = 'cyberbrief-shell-v1';
const DATA_CACHE = 'cyberbrief-data';
const SHELL = ['./', 'index.html', 'styles.css', 'app.js', 'manifest.webmanifest', 'icons/icon.svg', 'icons/icon-192.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(SHELL_CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== SHELL_CACHE && k !== DATA_CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

async function briefing(request) {
  const cache = await caches.open(DATA_CACHE);
  try {
    const res = await fetch(request);
    if (res.ok) await cache.put('briefing', res.clone());
    return res;
  } catch {
    const cached = await cache.match('briefing');
    if (!cached) throw new Error('offline and nothing cached');
    const headers = new Headers(cached.headers);
    headers.set('x-cyberbrief-cache', 'offline');
    return new Response(cached.body, { status: 200, headers });
  }
}

async function shell(request) {
  const cache = await caches.open(SHELL_CACHE);
  const cached = await cache.match(request, { ignoreSearch: true });
  const network = fetch(request)
    .then((res) => { if (res.ok) cache.put(request, res.clone()); return res; })
    .catch(() => null);
  return cached || (await network) || (request.mode === 'navigate' ? cache.match('index.html') : Response.error());
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname.endsWith('/data/briefing.json')) event.respondWith(briefing(event.request));
  else event.respondWith(shell(event.request));
});
