/**
 * CapAuth Bunker phone-signer — service worker (SPIKE).
 *
 * Minimal app-shell cache so the PWA is installable + works offline for the
 * key-management UI. The WebSocket relay obviously needs the network. OpenPGP.js
 * is vendored locally (vendor/openpgp.min.js) and precached — no CDN dependency.
 */
const CACHE = "capauth-bunker-v6";
const SHELL = [
  "./",
  "./index.html",
  "./app.js",
  "./manifest.webmanifest",
  "./vendor/openpgp.min.js",
  "./vendor/qrcode-generator.js",
  "./lib/keyvault.js",
  "./lib/canonical.js",
  "./lib/bunker-signer.js",
  "./lib/bunker-e2e.js",
  "./lib/keyqr.js",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// --- Web Push: wake the phone for a sign-in approval when backgrounded ------
self.addEventListener("push", (e) => {
  let data = {};
  try {
    data = e.data ? e.data.json() : {};
  } catch {
    data = { body: e.data ? e.data.text() : "" };
  }
  const title = data.title || "CapAuth sign-in request";
  const options = {
    body: data.body || "Tap to review and approve a sign-in.",
    icon: "./icons/icon-192.png",
    badge: "./icons/icon-192.png",
    tag: "capauth-bunker-approval",
    requireInteraction: true,
    data: { url: data.url || "./" },
  };
  e.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const target = (e.notification.data && e.notification.data.url) || "./";
  // Open the PWA pre-filled with the pairing URI (./?uri=capauth-bunker://…).
  const open = target.startsWith("capauth-bunker:")
    ? "./?uri=" + encodeURIComponent(target)
    : target;
  e.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((cs) => {
      for (const c of cs) {
        if ("focus" in c) return c.focus();
      }
      return self.clients.openWindow(open);
    })
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  // Never intercept the relay WebSocket or cross-origin CDN requests.
  if (url.origin !== location.origin) return;
  // NETWORK-FIRST: always prefer the freshest code when online, fall back to the
  // cached shell only when offline. A previous cache-FIRST strategy meant any
  // deployed fix was masked by a stale precache until the cache name changed —
  // an active-development footgun. Cache is now an offline safety net only.
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
