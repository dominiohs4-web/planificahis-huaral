/* PlanificaHis - Service Worker de la variante PHP/Apache (XAMPP/Render).
 * - App Shell y recursos estaticos: Cache-First.
 * - Navegaciones HTML: Network-First con timeout corto y fallback al shell.
 * - api.php y escrituras clinicas: SIEMPRE red, sin cache.
 */
const SW_VERSION = 'planificahis-v2026.11.13-sec';
const NAV_TIMEOUT_MS = 3500;
const PRECACHE = [
  './index.php',
  './manifest.webmanifest',
  './public/icon.svg?v=20261113',
  './public/logo.png?v=20261113',
  './public/logo-diresa-lima.jpg?v=20261113',
  './public/apple-touch-icon.png?v=20261113',
  './public/favicon.ico?v=20261113',
  './public/pwa-192x192.png?v=20261113',
  './public/pwa-512x512.png?v=20261113',
  './public/pwa-maskable-512x512.png?v=20261113',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(SW_VERSION)
      .then((cache) =>
        Promise.all(
          PRECACHE.map((url) =>
            cache.add(url).catch(() => {
              /* Un recurso opcional no debe bloquear la instalacion. */
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

function isStaticAsset(url) {
  const path = url.pathname.toLowerCase();
  if (path.indexOf('/public/') !== -1) return true;
  return /\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|eot|webmanifest)$/i.test(path);
}

async function cachePut(request, response) {
  if (!response || !response.ok) return;
  try {
    const copy = response.clone();
    const cache = await caches.open(SW_VERSION);
    await cache.put(request, copy);
  } catch (e) {
    /* El cache es una optimizacion, nunca debe romper la respuesta. */
  }
}

async function networkFirstNavigation(request) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NAV_TIMEOUT_MS);
  try {
    const response = await fetch(request, { signal: controller.signal });
    clearTimeout(timer);
    if (!response || !response.ok) throw new Error('Navigation failed');
    await cachePut(request, response);
    return response;
  } catch (e) {
    clearTimeout(timer);
    const cached = (await caches.match(request)) || (await caches.match('./index.php'));
    if (cached) return cached;
    return new Response(
      '<!doctype html><html lang="es"><head><meta charset="utf-8">' +
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">' +
        '<meta name="theme-color" content="#0F172A"><title>PlanificaSalud HIS</title>' +
        '<style>body{margin:0;min-height:100dvh;display:flex;align-items:center;justify-content:center;' +
        'background:linear-gradient(165deg,#f8fafc,#e0f2fe);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;' +
        'color:#0f172a;padding:24px;text-align:center}.card{max-width:360px;background:#fff;border:1px solid #bae6fd;' +
        'border-radius:24px;padding:28px 22px;box-shadow:0 20px 60px rgba(15,23,42,.12)}h1{font-size:18px;margin:0 0 8px}' +
        'p{font-size:12px;line-height:1.6;color:#475569;margin:0 0 16px}a{display:inline-block;padding:12px 18px;' +
        'border-radius:12px;background:#0369a1;color:#fff;text-decoration:none;font-size:12px;font-weight:700}</style>' +
        '</head><body><div class="card"><h1>Sin conexion</h1>' +
        '<p>No se pudo contactar al servidor del hospital. Verifique su red movil e intente nuevamente.</p>' +
        '<a href="./index.php">Reintentar</a></div></body></html>',
      { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
  }
}

async function cacheFirstAsset(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    await cachePut(request, response);
    return response;
  } catch (e) {
    return cached || Response.error();
  }
}

self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);

  // api.php y cualquier escritura clinica NUNCA se cachean, ni siquiera GET.
  if (request.method !== 'GET' || url.pathname.toLowerCase().indexOf('api.php') !== -1) {
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
    event.respondWith(networkFirstNavigation(request));
    return;
  }

  if (isStaticAsset(url)) {
    event.respondWith(cacheFirstAsset(request));
    return;
  }

  // Otros GET same-origin: red primero, con respaldo en cache.
  event.respondWith(
    fetch(request)
      .then(async (response) => {
        await cachePut(request, response);
        return response;
      })
      .catch(async () => (await caches.match(request)) || Response.error())
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});
