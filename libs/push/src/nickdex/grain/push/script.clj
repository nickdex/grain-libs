(ns nickdex.grain.push.script
  "The browser half: subscribing, and recognising this device.

   Two strings, for two different files.

   `client-script` goes in a script the page loads from <head>. NOT in
   the page body: an application that streams its markup -- Datastar,
   htmx, anything applying HTML by morphing -- never executes a <script>
   element inserted that way, so the functions silently do not exist and
   every button calling them throws ReferenceError into a console nobody
   is reading. Inline event ATTRIBUTES survive morphing, which is how the
   buttons reach this.

   `service-worker-script` goes in the service worker, and the app is
   responsible for pasting it there -- a worker is registered by URL and
   cannot be composed from a library at runtime."
  (:require [cheshire.core :as json]))

(def default-paths
  "Where the application is expected to have mounted the handlers."
  {:public-key "/push/key"
   :subscribe  "/push/subscribe"})

(defn client-script
  "`window.grainPush` with enable, label and markThisDevice.

   `opts`:
     :paths       overrides for `default-paths`
     :after       where to go after subscribing, e.g. \"/account\"
     :list-id     id of the element holding the device rows
     :enable-id   id of the element holding the enable control

   Returns a string for a <script type=\"module\"> served from <head>."
  [{:keys [paths after list-id enable-id]}]
  (let [{:keys [public-key subscribe]} (merge default-paths paths)
        q #(json/generate-string %)]
    (str "
const PUBLIC_KEY_PATH = " (q public-key) ";
const SUBSCRIBE_PATH = " (q subscribe) ";
const AFTER = " (q (or after "/")) ";
const LIST_ID = " (q (or list-id "push-devices")) ";
const ENABLE_ID = " (q (or enable-id "push-enable")) ";

function urlBase64ToUint8Array(base64) {
  // applicationServerKey wants raw bytes, and the VAPID public key
  // travels as base64url. Not interchangeable: passing the string
  // straight through fails with an opaque InvalidCharacterError.
  const padded = (base64 + '='.repeat((4 - (base64.length % 4)) % 4))
    .replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(padded);
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

// A starting point, not the answer -- two Android phones both come out
// as 'Chrome on Android', which is why the label is editable after.
function deviceLabel() {
  const ua = navigator.userAgent;
  const browser = /Firefox\\//.test(ua) ? 'Firefox'
    : /Edg\\//.test(ua) ? 'Edge'
    : /Chrome\\//.test(ua) ? 'Chrome'
    : /Safari\\//.test(ua) ? 'Safari'
    : 'Browser';
  const platform = /Android/.test(ua) ? 'Android'
    : /iPhone|iPad|iPod/.test(ua) ? 'iOS'
    : /Macintosh/.test(ua) ? 'Mac'
    : /Windows/.test(ua) ? 'Windows'
    : /Linux/.test(ua) ? 'Linux'
    : 'this device';
  return browser + ' on ' + platform;
}

async function enable(statusEl) {
  const say = (m) => { if (statusEl) statusEl.textContent = m; };
  say('');

  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    // iOS is the common case, and 'cannot' is wrong there: Safari
    // exposes PushManager only once the site is installed to the Home
    // Screen, so the honest message is what to do about it.
    const iOS = /iPhone|iPad|iPod/.test(navigator.userAgent);
    const standalone = window.matchMedia('(display-mode: standalone)').matches
      || window.navigator.standalone === true;
    say(iOS && !standalone
      ? 'On iPhone, add this app to your Home Screen first (Share, then Add to Home Screen), then open it from there.'
      : 'This browser cannot receive notifications.');
    return;
  }

  // Asked here, on a tap, and nowhere else. A browser asked on arrival
  // and refused cannot easily be asked again, so an unprompted request
  // spends the only chance there is.
  if ((await Notification.requestPermission()) !== 'granted') {
    say('Notifications are blocked for this site. Your browser settings can undo that.');
    return;
  }

  const keyRes = await fetch(PUBLIC_KEY_PATH);
  if (!keyRes.ok) { say('Notifications are not configured on this server.'); return; }
  const {publicKey} = await keyRes.json();

  const reg = await navigator.serviceWorker.ready;
  let sub;
  try {
    sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(publicKey),
    });
  } catch (e) {
    say('Could not subscribe: ' + e.message);
    return;
  }

  const json = sub.toJSON();
  const res = await fetch(SUBSCRIBE_PATH, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      endpoint: json.endpoint,
      p256dh: json.keys.p256dh,
      auth: json.keys.auth,
      label: deviceLabel(),
    }),
  });
  const result = await res.json();
  if (result.ok) { window.location = AFTER; } else { say('Could not save this device.'); }
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Only the browser knows which subscription is its own. It matches on a
// hash: the endpoint is a capability -- anyone holding it can push here
// -- so it never reaches the page.
//
// Matching, rather than just asking whether a subscription exists: a
// browser can hold one the server has already retired, and hiding the
// enable control then would leave no way back.
async function markThisDevice() {
  const list = document.getElementById(LIST_ID);
  if (!list || list.dataset.checked === '1') return;
  list.dataset.checked = '1';

  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
  const reg = await navigator.serviceWorker.getRegistration();
  const sub = reg && (await reg.pushManager.getSubscription());
  if (!sub) return;

  const row = document.querySelector(
    `[data-device-fingerprint=\"${await sha256Hex(sub.endpoint)}\"]`);
  if (!row) return;

  row.querySelector('[data-this-device]')?.removeAttribute('hidden');
  // Already subscribed here, and the server agrees. Offering to enable
  // it again is offering to do nothing.
  document.getElementById(ENABLE_ID)?.setAttribute('hidden', '');
}

// A MutationObserver because a streamed page's body arrives after this
// script has run, and nothing in that markup can call us.
new MutationObserver(() => { markThisDevice(); })
  .observe(document.documentElement, {childList: true, subtree: true});
document.addEventListener('DOMContentLoaded', markThisDevice);

window.grainPush = {enable, label: deviceLabel, markThisDevice};
")))

(defn service-worker-script
  "Push and notificationclick handlers, to paste into the service worker.

   A worker is registered by URL and its code cannot be composed from a
   library at runtime, so this is a string the application concatenates
   into its own sw.js rather than something it can require.

   userVisibleOnly is true on the subscription, so every push MUST show
   a notification. A handler that decides not to costs the site its
   permission: browsers substitute a 'this site was updated in the
   background' notice, and repeat offenders get unsubscribed.

   `icon` is a path in the consuming app."
  [{:keys [icon]}]
  (let [icon (or icon "/icons/icon-180x180.png")]
    (str "
self.addEventListener('push', (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (e) {
    // A malformed or absent payload still has to surface something.
    payload = {};
  }
  event.waitUntil(self.registration.showNotification(payload.title || 'Notification', {
    body: payload.body || '',
    icon: " (json/generate-string icon) ",
    badge: " (json/generate-string icon) ",
    tag: payload.tag || 'default',
    data: {url: payload.url || '/'},
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  // Focus a tab that is already open rather than stacking another.
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({type: 'window', includeUncontrolled: true});
    for (const client of clients) {
      if (client.url.includes(url) && 'focus' in client) return client.focus();
    }
    return self.clients.openWindow(url);
  })());
});
")))
