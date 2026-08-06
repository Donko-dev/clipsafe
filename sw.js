// sw.js — Service Worker de ClipSafe
// Stratégie : "Cache first, network fallback" pour un fonctionnement 100% hors ligne,
// y compris lors d'une actualisation (F5) pendant que l'appareil est hors connexion.
//
// Limite technique honnête et incontournable pour TOUTE application web :
// la toute première visite d'une URL nécessite un accès réseau (ne serait-ce que pour
// télécharger ce fichier lui-même). Une fois cette première visite effectuée, tout le
// reste — y compris les actualisations et les réouvertures via le lien — fonctionne
// intégralement hors ligne grâce au cache ci-dessous.

const CACHE_NAME = "clipsafe-cache-v4";
const CORE_ASSETS = [
  "./",
  "./index.html",
  "./style.css",
  "./app.js",
  "./data.json",
  "./manifest.json",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/icon-512-maskable.png",
  "./icons/favicon.jpg",
];

// Installation : on met en cache le noyau applicatif complet
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(CORE_ASSETS))
  );
  self.skipWaiting();
});

// Activation : nettoyage des anciens caches + prise de contrôle immédiate
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
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

  // Cas particulier : navigation (chargement de page / actualisation / accès direct
  // par le lien). On sert systématiquement l'app shell en cache si le réseau échoue,
  // pour garantir que l'app s'ouvre même hors connexion après actualisation.
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req)
        .then((response) => {
          caches.open(CACHE_NAME).then((cache) => cache.put("./index.html", response.clone()));
          return response;
        })
        .catch(async () => {
          const cache = await caches.open(CACHE_NAME);
          return (
            (await cache.match(req)) ||
            (await cache.match("./index.html")) ||
            (await cache.match("./"))
          );
        })
    );
    return;
  }

  // Tous les autres assets (CSS, JS, JSON, icônes) : cache-first, mise à jour en tâche de fond
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

      return cached || network;
    })
  );
});
