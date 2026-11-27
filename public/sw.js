/* Install-only service worker for PWA installability.
   Deliberately NO fetch handler and NO caching: registrations, admin data and
   API responses are never stored offline — every request goes to the network. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
