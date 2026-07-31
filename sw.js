// sw.js — Service Worker de ClipSafe
// Stratégie : "Cache first, network fallback" pour un fonctionnement 100% hors ligne
// une fois la première visite effectuée.

const CACHE_NAME = "clipsafe-cache-v1";
const CORE_ASSETS = [
  "./",
  "./index.html",
  "./app.js",
  "./data.json",
  "./manifest.json",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/icon-512-maskable.png",
  "./icons/favicon.jpg"
];

// Installation : on met en cache le noyau applicatif
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(CORE_ASSETS))
  );
  self.skipWaiting();
});

// Activation : nettoyage des anciens caches
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

// Interception des requêtes
self.addEventListener("fetch", (event) => {
  const req = event.request;

  // On ne gère que les requêtes GET du même domaine (sécurité + simplicité)
  if (req.method !== "GET" || !req.url.startsWith(self.location.origin)) {
    return;
  }

  event.respondWith(
    caches.match(req).then((cached) => {
      const network = fetch(req)
        .then((response) => {
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, clone));
          }
          return response;
        })
        .catch(() => cached);

      // Cache-first pour une réactivité instantanée, mise à jour en tâche de fond
      return cached || network;
    })
  );
});
