(ns nickdex.grain.push.push-test
  "Tests propagated from push.allium.

   Every `testing` string opens with the Allium obligation it discharges
   (`allium plan src/nickdex/grain/push/push.allium`),
   so a failing run names the spec clause that broke.

   Devices are table rows, so the seam is a real SQLite database in a
   temp file -- not `:memory:`, where every connection gets its own
   private database unless shared-cache is negotiated.

   What is NOT here: delivery. PushChannel's invariants are about what a
   push service returns, and exercising them needs one. `push/outcome`
   is the part that decides, and it is tested directly."
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [cognitect.anomalies :as anom]
            [next.jdbc :as jdbc]
            [nickdex.grain.push.devices :as devices]
            [nickdex.grain.push.send :as send]
            [nickdex.grain.push.store :as store])
  (:import [java.time Instant]))

(def now (Instant/parse "2026-08-27T09:00:00Z"))

(def ^:dynamic *db* nil)

(defn with-database [f]
  (let [file (doto (java.io.File/createTempFile "grain-push" ".sqlite") .delete)
        ds (jdbc/get-datasource {:jdbcUrl (str "jdbc:sqlite:" (.getPath file))})]
    (store/migrate! ds)
    (binding [*db* ds]
      (try (f)
           (finally
             (doseq [suffix ["" "-wal" "-shm"]]
               (io/delete-file (str (.getPath file) suffix) true)))))))

(use-fixtures :each with-database)

(defn- account [] (random-uuid))

(defn- subscribe!
  ([account-id endpoint] (subscribe! account-id endpoint "Chrome on Android"))
  ([account-id endpoint label]
   (devices/subscribe! *db* {:account-id account-id
                             :endpoint endpoint
                             :public-key "public-key"
                             :auth-secret "auth-secret"
                             :label label}
                       now)))

(defn- anomaly? [x] (some? (::anom/category x)))

;; ------------------------------------------------------------------
;; SubscribeDevice
;; ------------------------------------------------------------------

(deftest subscribe-device
  (testing "SubscribeDevice ensures Device.created with the account and label"
    (let [owner (account)
          device (subscribe! owner "https://push.example/a" "Phone")]
      (is (not (anomaly? device)))
      (is (= owner (:account-id device)))
      (is (= "Phone" (:label device)))
      (is (= now (:created-at device)))))

  (testing "SubscribeDevice requires: label != \"\""
    (is (anomaly? (subscribe! (account) "https://push.example/blank" "   ")))
    (is (empty? (devices/for-account *db* (account)))))

  (testing "a browser with no endpoint is refused"
    (is (anomaly? (subscribe! (account) "" "Phone")))))

(deftest a-stored-device-carries-what-a-send-needs
  ;; The bug this pins: the columns were named after the Web Push JSON
  ;; (p256dh, auth), and next.jdbc's kebab builder turns `p256dh` into
  ;; :p-256dh -- it inserts a hyphen at the letter/digit boundary. Every
  ;; read produced a key nothing looked for, so the subscription's public
  ;; key reached the push library as nil and every send died inside
  ;; BouncyCastle.
  ;;
  ;; Nothing caught it, because the other tests hand subscribe! a literal
  ;; map and assert on :label. Only a ROUND TRIP through the column names
  ;; shows it.
  (let [owner (account)]
    (devices/subscribe! *db* {:account-id owner
                              :endpoint "https://push.example/roundtrip"
                              :public-key "a-real-looking-public-key"
                              :auth-secret "a-real-looking-auth"
                              :label "Phone"}
                        now)
    (let [device (first (devices/for-account *db* owner))]
      (testing "the keys send! destructures survive the round trip"
        (is (= "a-real-looking-public-key" (:public-key device)))
        (is (= "a-real-looking-auth" (:auth-secret device))))

      (testing "and nothing a send reads is nil"
        (doseq [k [:endpoint :public-key :auth-secret :label]]
          (is (some? (get device k)) (str k " is nil")))))))

(deftest resubscribe-device
  ;; A browser re-subscribing hands back the endpoint it already has.
  ;; The ordinary repeat must not create a second device.
  (testing "ResubscribeDevice updates rather than creating a second row"
    (let [owner (account)]
      (subscribe! owner "https://push.example/same" "Phone")
      (subscribe! owner "https://push.example/same" "Phone")
      (is (= 1 (count (devices/for-account *db* owner))))))

  (testing "and re-subscribing without a label keeps the one it was renamed to"
    (let [owner (account)
          device (subscribe! owner "https://push.example/keep" "Chrome on Android")]
      (devices/rename! *db* (:device-id device) "Work phone")
      (subscribe! owner "https://push.example/keep" nil)
      (is (= "Work phone" (:label (devices/by-id *db* (:device-id device)))))))

  (testing "an endpoint returning under another account moves to it"
    ;; The browser was signed out and signed in as somebody else. Leaving
    ;; it on the first account would send that person's notifications to
    ;; whoever holds the device now.
    (let [first-owner (account)
          second-owner (account)]
      (subscribe! first-owner "https://push.example/moved" "Phone")
      (subscribe! second-owner "https://push.example/moved" "Phone")
      (is (empty? (devices/for-account *db* first-owner)))
      (is (= 1 (count (devices/for-account *db* second-owner)))))))

;; ------------------------------------------------------------------
;; RenameDevice
;; ------------------------------------------------------------------

(deftest endpoint-fingerprint-identifies-without-exposing
  ;; push.allium's EndpointIsNeverShown. A browser has to be
  ;; able to recognise its own row, and the endpoint cannot be what it
  ;; matches on -- anyone holding one can push to that browser.
  (let [endpoint "https://push.example/secret-capability"
        fingerprint (devices/endpoint-fingerprint endpoint)]
    (testing "it is a SHA-256, so it identifies without being usable"
      (is (= 64 (count fingerprint)))
      (is (re-matches #"[0-9a-f]{64}" fingerprint))
      (is (not (clojure.string/includes? fingerprint "push.example"))))

    (testing "and it is stable, or a browser would never match its own row"
      (is (= fingerprint (devices/endpoint-fingerprint endpoint))))

    (testing "a different endpoint fingerprints differently"
      (is (not= fingerprint (devices/endpoint-fingerprint (str endpoint "x"))))))

  (testing "every stored device carries one"
    (let [owner (account)]
      (subscribe! owner "https://push.example/fp" "Phone")
      (let [device (first (devices/for-account *db* owner))]
        (is (= (devices/endpoint-fingerprint (:endpoint device))
               (:fingerprint device)))))))

(deftest rename-device
  (testing "RenameDevice ensures device.label = label"
    (let [device (subscribe! (account) "https://push.example/r" "Chrome on Android")]
      (is (nil? (devices/rename! *db* (:device-id device) "Kitchen tablet")))
      (is (= "Kitchen tablet" (:label (devices/by-id *db* (:device-id device)))))))

  (testing "RenameDevice requires: label != \"\""
    (let [device (subscribe! (account) "https://push.example/r2" "Keep me")]
      (is (anomaly? (devices/rename! *db* (:device-id device) "  ")))
      (is (= "Keep me" (:label (devices/by-id *db* (:device-id device))))))))

;; ------------------------------------------------------------------
;; UnsubscribeDevice / RetireGoneDevice
;; ------------------------------------------------------------------

(deftest unsubscribe-device
  (testing "UnsubscribeDevice ensures: not exists device"
    (let [owner (account)
          device (subscribe! owner "https://push.example/u" "Phone")]
      (devices/unsubscribe! *db* (:device-id device) owner)
      (is (nil? (devices/by-id *db* (:device-id device))))
      (is (empty? (devices/for-account *db* owner)))))

  (testing "and another account cannot unsubscribe your device"
    (let [owner (account)
          device (subscribe! owner "https://push.example/u2" "Phone")]
      (devices/unsubscribe! *db* (:device-id device) (account))
      (is (some? (devices/by-id *db* (:device-id device)))))))

(deftest retire-gone-device
  ;; The translate step: the push service saying a subscription no longer
  ;; exists. Keyed on the endpoint, because that is what the service
  ;; knows, and unscoped by account, because no session is behind it.
  (testing "RetireGoneDevice ensures: not exists device"
    (let [owner (account)]
      (subscribe! owner "https://push.example/gone" "Phone")
      (devices/retire! *db* "https://push.example/gone")
      (is (empty? (devices/for-account *db* owner))))))

;; ------------------------------------------------------------------
;; Invariants
;; ------------------------------------------------------------------

(deftest invariant-endpoint-identifies-one-device
  (testing "EndpointIdentifiesOneDevice: no endpoint appears twice"
    (let [owners (repeatedly 3 account)]
      (doseq [owner owners
              n (range 3)]
        (subscribe! owner (str "https://push.example/" n) "Phone"))
      ;; Nine subscribes across three endpoints. The last account to
      ;; claim each one holds it, and there are three rows, not nine.
      (let [endpoints (map :endpoint
                           (mapcat #(devices/for-account *db* %) owners))]
        (is (= 3 (count endpoints)))
        (is (= (count endpoints) (count (distinct endpoints))))))))

(deftest invariant-device-is-labelled
  (testing "DeviceIsLabelled: nothing reaches the table with a blank label"
    (let [owner (account)]
      (subscribe! owner "https://push.example/ok" "Phone")
      (subscribe! owner "https://push.example/blank" "")
      (subscribe! owner "https://push.example/spaces" "   ")
      (is (every? #(seq (:label %)) (devices/for-account *db* owner)))
      (is (= 1 (count (devices/for-account *db* owner)))))))

;; ------------------------------------------------------------------
;; PushChannel
;; ------------------------------------------------------------------

(deftest bouncy-castle-is-registered
  ;; web-push asks the JCA for algorithms by provider NAME. Having the
  ;; jar on the classpath satisfies compile-time resolution and nothing
  ;; else -- without the provider registered, every send failed with
  ;; "NoSuchProviderException: no such provider: BC" at the first
  ;; encryption step, which is well past the point anything looks wrong.
  ;;
  ;; Requiring the push namespace is what registers it. This asserts that
  ;; side effect, because deleting it compiles, passes every other test,
  ;; and breaks only delivery.
  (is (some? (java.security.Security/getProvider "BC"))))

(deftest contract-push-channel-outcome
  ;; The whole of PushChannel's two load-bearing invariants lives in this
  ;; one function, so it is tested directly rather than through a push
  ;; service nobody has in a test.
  (let [outcome #'send/outcome]
    (testing "PermanentRejectionIsReportedAsGone: 404 and 410 mean gone"
      (is (= :gone (outcome 404)))
      (is (= :gone (outcome 410))))

    (testing "TransientFailureIsNotGone: everything else is a failure, not a removal"
      ;; Retiring on one of these unsubscribes a device that still works,
      ;; silently, and the person finds out by never being notified again.
      (doseq [status [408 429 500 502 503 504 400 401 403]]
        (is (= :failed (outcome status))
            (str status " must not retire a device"))))

    (testing "a 2xx is delivered"
      (doseq [status [200 201 202 204]]
        (is (= :delivered (outcome status)))))))
