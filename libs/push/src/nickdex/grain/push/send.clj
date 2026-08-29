(ns nickdex.grain.push.send
  "Delivery: push.allium's PushChannel contract, realised over
   Web Push.

   The contract's two load-bearing invariants both live in `outcome`
   below, and they are the ones worth not getting wrong:

   - PermanentRejectionIsReportedAsGone. 404 and 410 mean the
     subscription no longer exists. Not retiring on them leaves a dead
     device on the list forever, and every later send pays for it.

   - TransientFailureIsNotGone. A timeout, a 429 or a 500 is the service
     being unavailable, NOT the subscription being gone. Retiring on one
     of those unsubscribes a device that still works, silently, and the
     person finds out by never being notified again.

   Delivery is per device: a message to a person is a message to each of
   their devices, and one failing says nothing about the others."
  (:require [cheshire.core :as json]
            [com.brunobonacci.mulog :as u]
            [nickdex.grain.push.devices :as devices])
  (:import [java.security Security]
           [nl.martijndwars.webpush Notification PushService]
           [org.bouncycastle.jce.provider BouncyCastleProvider]))

(defonce ^:private bouncy-castle
  ;; web-push asks the JCA for algorithms by provider NAME -- "BC" -- and
  ;; having the jar on the classpath is not the same as having the
  ;; provider registered. Without this every send fails with
  ;; NoSuchProviderException: no such provider: BC, at the first
  ;; encryption step, long after the request looked fine.
  ;;
  ;; A namespace-load side effect, which is how BouncyCastle is normally
  ;; installed, and guarded so a reload does not stack duplicates.
  (do (when-not (Security/getProvider "BC")
        (Security/addProvider (BouncyCastleProvider.)))
      :registered))

(defn- push-service
  "The signer, built per send.

   Takes the private key as a plain string, and the CALLER decides how
   long it exists as one. An application using Biff should unwrap
   #biff/secret at the call site rather than putting the plaintext on a
   context that gets logged; this library does not know about Biff and
   should not."
  [{:keys [vapid-public-key vapid-private-key vapid-subject]}]
  (when-not (and (seq (str vapid-public-key)) (seq (str vapid-private-key)))
    (throw (ex-info "Push is not configured: a VAPID keypair is required."
                    {:public-key-present? (boolean (seq (str vapid-public-key)))
                     :private-key-present? (boolean (seq (str vapid-private-key)))})))
  (doto (PushService.)
    (.setPublicKey ^String vapid-public-key)
    (.setPrivateKey ^String vapid-private-key)
    ;; Some push services refuse a VAPID JWT with no `sub`. A mailto:
    ;; they can reach if this server starts misbehaving.
    (.setSubject ^String (or vapid-subject "mailto:admin@example.com"))))

(defn- outcome
  "What an HTTP status from the push service means for this device.

   Anything not explicitly permanent is treated as transient. That
   asymmetry is deliberate: a wrongly-retired device is silent forever
   and nobody notices, while a wrongly-kept one costs one failed request
   per send and shows up in the log."
  [status]
  (cond
    (<= 200 status 299) :delivered
    (contains? #{404 410} status) :gone
    :else :failed))

(defn send!
  "Deliver one message to every device on a user. Returns a map of
   outcome to count.

   Retires the devices the service reports as gone, which is the only
   thing that keeps the list from filling with browsers that were
   uninstalled or had their site data cleared.

   `message` is a map; it reaches the service worker as JSON."
  [{:keys [datasource] :as config} user-id message]
  (let [service (push-service config)
        payload (json/generate-string message)]
    (->> (devices/for-user datasource user-id)
         (map (fn [{:keys [endpoint public-key auth-secret label]}]
                (let [result
                      (try
                        (-> (.send service (Notification. ^String endpoint
                                                           ^String public-key
                                                           ^String auth-secret
                                                           ^bytes (.getBytes payload "UTF-8")))
                            .getStatusLine
                            .getStatusCode
                            outcome)
                        (catch Exception e
                          ;; A transport failure is not the subscription
                          ;; being gone. Log and keep the device.
                          (u/log ::push-failed :label label :error e)
                          :failed))]
                  (when (= :gone result)
                    (u/log ::device-gone :label label)
                    (devices/retire! datasource endpoint))
                  result)))
         frequencies)))
