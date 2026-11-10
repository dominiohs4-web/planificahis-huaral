/* PlanificaHis — Service Worker de la variante PHP/Apache (XAMPP/Render).
 * - Cachea únicamente el shell estático de la app.
 * - Nunca cachea api.php, sync_cloud_to_local.php ni respuestas clínicas.
 * - No intercepta métodos distintos de GET.
 */
const SW_VERSION = 'planificahis-v10';
const PRECACHE = [
  './index.php',
  './manifest.webmanifest',
  './public/icon.svg?v=3',
  './public/apple-touch-icon.png?v=3',
  './public/favicon.ico?v=3',
  './public/pwa-192x192.png?v=3',
  './public/pwa-512x512.png?v=3',
  './public/pwa-maskable-512x512.png?v=3',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(SW_VERSION)
      .then((cache) =>
        Promise.all(
          PRECACHE.map((url) =>
            cache.add(url).catch(() => {
              /* Un recurso opcional no debe bloquear la instalación. */
            })
          )
        )
      )
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => key !== SW_VERSION).map((key) => caches.delete(key)))
      )
      .then(() => self.clients.claim())
  );
});

function isClinicalApi(url) {
  const path = url.pathname.toLowerCase();
  return (
    path.indexOf('api.php') !== -1 ||
    path.indexOf('sync_cloud_to_local.php') !== -1 ||
    path.indexOf('/api/') !== -1 ||
    url.searchParams.has('action')
  );
}

self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  const esApiPhp = url.pathname.toLowerCase().indexOf('api.php') !== -1;
  // api.php NUNCA se cachea, ni siquiera si en el futuro se sirve como GET
  // navegable o con query string. Las API clínicas y cualquier escritura van
  // SIEMPRE a la red, sin leer ni escribir cachés.
  if (request.method !== 'GET' || esApiPhp) {
    event.respondWith(fetch(request, { cache: 'no-store' }));
    return;
  }

  if (isClinicalApi(url)) {
    event.respondWith(fetch(request, { cache: 'no-store' }));
    return;
  }
  if (url.origin !== self.location.origin) return;
  if (url.pathname.endsWith('/sw.js')) return;

  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(SW_VERSION).then((cache) => cache.put(request, copy)).catch(() => {});
          return response;
        })
        .catch(async () => {
          const cached = await caches.match(request);
          if (cached) return cached;
          return (
            (await caches.match('./index.php')) ||
            new Response('Sin conexión. Abra la aplicación desde la pantalla de inicio.', {
              status: 503,
              headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            })
          );
        })
    );
    return;
  }

  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request)
        .then((response) => {
          if (!response || response.status !== 200 || response.type === 'opaque') return response;
          const copy = response.clone();
          caches.open(SW_VERSION).then((cache) => cache.put(request, copy)).catch(() => {});
          return response;
        })
        .catch(() => cached || Response.error());
    })
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});
