(ns nickdex.grain.push.interface
  "Web Push for a Clojure application, backed by a SQLite table.

   Behaviour is specified in push.allium. A device is one browser install
   that agreed to be notified; this keeps that list honest and delivers
   to it.

   Subscriptions are a TABLE, not an event log. An endpoint plus its keys
   is a capability -- whoever holds them can push to that browser -- so in
   an append-only log they would outlive the unsubscribe meant to revoke
   them, and a person asking to be erased could not be. Here, delete
   deletes.

   No dependency on the auth library. `account-id` is an opaque uuid this
   library stores and never reads, so an application can have
   notifications without passkeys.

   Every function takes `now` explicitly rather than reading the clock,
   so a test can pin it.

   Wiring, once per application start:

     (require '[nickdex.grain.push.interface :as push])
     (push/migrate! datasource)

   The table is prefixed `push_`, so an existing backup script covers it
   without being told about it."
  (:require [nickdex.grain.push.devices :as devices]
            [nickdex.grain.push.script :as script]
            [nickdex.grain.push.send :as send]
            [nickdex.grain.push.store :as store]))

;; --- Schema -------------------------------------------------------

(defn migrate!
  "Create the push table if absent. Idempotent; call it on every start."
  [datasource]
  (store/migrate! datasource))

;; --- Devices ------------------------------------------------------

(def subscribe!
  "Record a browser's subscription, or update the one already held for
   that endpoint.

   Takes {:account-id :endpoint :public-key :auth-secret :label}. A
   browser re-subscribing hands back the endpoint it already has, so the
   ordinary repeat is an update rather than a second row -- and an
   endpoint returning under a different account moves to it, because
   that means the browser was signed out and signed in as somebody else."
  devices/subscribe!)

(def for-account
  "This account's devices, oldest first. Each carries a :fingerprint."
  devices/for-account)

(def by-id
  "One device by its id. The id, not the endpoint: an endpoint is a
   capability and has no business in a URL or a form field."
  devices/by-id)

(def rename!
  "Replace a device's label. Returns an anomaly when it is blank."
  devices/rename!)

(def unsubscribe!
  "A person turning this off. Scoped to their account, so a device id
   alone cannot remove somebody else's subscription."
  devices/unsubscribe!)

(def retire!
  "The push service reporting a subscription is gone. Keyed on the
   endpoint, because that is what the service knows, and unscoped by
   account, because no session is behind it. Only ever for a PERMANENT
   rejection."
  devices/retire!)

(def endpoint-fingerprint
  "A SHA-256 of an endpoint, hex.

   push.allium guarantees EndpointIsNeverShown, so a browser that needs
   to recognise its own row matches on this instead. A hash identifies
   the subscription without being usable against it."
  devices/endpoint-fingerprint)

;; --- Delivery -----------------------------------------------------

(def send!
  "Deliver one message to every device on an account. Returns outcomes
   by count, e.g. {:delivered 2} or {:delivered 1 :gone 1}.

   Takes a config:

     {:datasource        ds
      :vapid-public-key  \"...\"
      :vapid-private-key \"...\"   ; plaintext; the CALLER decides how
      :vapid-subject     \"mailto:you@example.com\"}

   Devices the service reports as gone are retired, which is the only
   thing keeping the list from filling with browsers that were
   uninstalled or had their site data cleared. A timeout or a 500 is NOT
   gone and the device is kept."
  send/send!)

;; --- The browser half ---------------------------------------------

(def client-script
  "window.grainPush with enable, label and markThisDevice. Serve it from
   <head> -- see the script namespace for why the page body is not an
   option."
  script/client-script)

(def service-worker-script
  "push and notificationclick handlers, to paste into your service
   worker. A worker is registered by URL, so a library cannot compose
   one at runtime."
  script/service-worker-script)

(def default-paths
  "Where client-script expects the handlers to be mounted."
  script/default-paths)
