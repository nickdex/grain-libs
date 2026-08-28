(ns nickdex.grain.push.devices
  "push.allium's Device: subscribing a browser to push,
   renaming it, unsubscribing, and retiring one the push service says is
   gone.

   Every function takes `now` explicitly rather than reading the clock,
   matching grain-auth and for the same reason: a test can pin it and one
   request cannot hold two notions of the current instant."
  (:require [clojure.string :as str]
            [cognitect.anomalies :as anom]
            [next.jdbc.sql :as sql]
            [nickdex.grain.push.store :as store])
  (:import [java.nio.charset StandardCharsets]
           [java.security MessageDigest]
           [java.time Instant]))

(defn- incorrect [message]
  {::anom/category ::anom/incorrect ::anom/message message})

(defn- ->label [value]
  (let [t (str/trim (or value ""))]
    (when (seq t) t)))

(defn endpoint-fingerprint
  "A SHA-256 of an endpoint, hex.

   push.allium guarantees EndpointIsNeverShown: an endpoint plus
   its keys is a capability to push to a browser, so it cannot go in the
   DOM. A hash of it is not a capability -- it identifies the
   subscription without being usable against it, which is exactly enough
   for a browser to recognise its own row.

   Derived rather than stored: it is a function of a column that never
   changes, and a second copy would be free to drift."
  [endpoint]
  (let [digest (.digest (MessageDigest/getInstance "SHA-256")
                        (.getBytes (str endpoint) StandardCharsets/UTF_8))]
    (apply str (map #(format "%02x" %) digest))))

(defn- row->device [row]
  (when row
    (-> row
        (update :device-id parse-uuid)
        (update :account-id parse-uuid)
        (update :created-at #(when % (Instant/ofEpochMilli (long %))))
        (as-> d (assoc d :fingerprint (endpoint-fingerprint (:endpoint d)))))))

;; ------------------------------------------------------------------
;; Reading
;; ------------------------------------------------------------------

(defn for-account
  "This account's devices, oldest first. What DeviceManagement lists and
   what a send iterates."
  [datasource account-id]
  (->> (sql/query datasource
                  ["SELECT * FROM push_device WHERE account_id = ?
                     ORDER BY created_at ASC" (str account-id)]
                  store/options)
       (mapv row->device)))

(defn by-id
  "One device by its id, or nil. The id, not the endpoint: an endpoint is
   a capability and has no business in a URL or a form field."
  [datasource device-id]
  (row->device
   (first (sql/find-by-keys datasource :push_device
                            {:device_id (str device-id)} store/options))))

(defn- by-endpoint [datasource endpoint]
  (row->device
   (first (sql/find-by-keys datasource :push_device
                            {:endpoint endpoint} store/options))))

;; ------------------------------------------------------------------
;; Writing
;; ------------------------------------------------------------------

(defn subscribe!
  "push.allium's SubscribeDevice and ResubscribeDevice, which
   share a trigger and are told apart by whether the endpoint is known.

   A browser re-subscribing hands back the endpoint it already has, so
   the ordinary repeat must not create a second device. The account is
   reassigned rather than defended: an endpoint returning under a
   different account means the browser was signed out and signed in as
   someone else, and leaving it on the first account would send that
   person's notifications to whoever holds the device now.

   The label is only replaced when one is supplied, so a re-subscribe
   does not undo a rename."
  [datasource {:keys [account-id endpoint public-key auth-secret label]} ^Instant now]
  (let [label (->label label)]
    (cond
      (str/blank? (str endpoint))
      (incorrect "That browser did not provide a push endpoint.")

      (some? (by-endpoint datasource endpoint))
      (do (sql/update! datasource :push_device
                       (cond-> {:account_id (str account-id)
                                :public_key public-key
                                :auth_secret auth-secret}
                         label (assoc :label label))
                       {:endpoint endpoint}
                       store/options)
          (by-endpoint datasource endpoint))

      (nil? label)
      (incorrect "Give this device a name so you can tell it apart later.")

      :else
      (let [device-id (random-uuid)]
        (sql/insert! datasource :push_device
                     {:endpoint endpoint
                      :device_id (str device-id)
                      :account_id (str account-id)
                      :public_key public-key
                      :auth_secret auth-secret
                      :label label
                      :created_at (.toEpochMilli now)}
                     store/options)
        (by-id datasource device-id)))))

(defn rename!
  "push.allium's RenameDevice. The label is the only thing that
   makes one device recognisable among several, so it may not be blanked
   -- a browser-derived name is a starting point, not the answer."
  [datasource device-id label]
  (if-let [label (->label label)]
    (do (sql/update! datasource :push_device
                     {:label label} {:device_id (str device-id)} store/options)
        nil)
    (incorrect "A device needs a name.")))

(defn unsubscribe!
  "push.allium's UnsubscribeDevice: a person turning this off.

   Scoped to the caller's account, so a device id alone cannot remove
   somebody else's subscription."
  [datasource device-id account-id]
  (sql/delete! datasource :push_device
               {:device_id (str device-id) :account_id (str account-id)}
               store/options)
  nil)

(defn retire!
  "push.allium's RetireGoneDevice: the push service reporting
   that a subscription no longer exists.

   Deliberately separate from unsubscribe! even though the row goes the
   same way. One is a person deciding and is scoped to their account;
   this is a service reporting, runs with no session behind it, and is
   keyed on the endpoint because that is what the service knows.

   Only ever called for a PERMANENT rejection. See push/send!."
  [datasource endpoint]
  (sql/delete! datasource :push_device {:endpoint endpoint} store/options)
  nil)
