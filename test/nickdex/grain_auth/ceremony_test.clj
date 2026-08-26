(ns nickdex.grain-auth.ceremony-test
  "Tests for the WebAuthn ceremony seam.

   What is NOT here: a ceremony that succeeds. Producing one needs a real
   authenticator holding a real private key, and the cryptography is
   com.yubico/webauthn-server-core's, verified by its own test suite
   rather than re-verified here. Faking it would mean faking the
   signature check, which is the only part that matters.

   What IS here is everything around that: the account seam Yubico calls
   into, the options a browser receives, and every failure path -- which
   is where the mistakes this library could make actually live, and where
   a uniform rejection message has to be checked rather than assumed."
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [cognitect.anomalies :as anom]
            [next.jdbc :as jdbc]
            [nickdex.grain-auth.interface :as auth]
            [nickdex.grain-auth.webauthn :as webauthn])
  (:import [java.time Instant]))

(def now (Instant/parse "2026-08-26T09:00:00Z"))

(def ^:dynamic *db* nil)

(defn with-database [f]
  (let [file (doto (java.io.File/createTempFile "grain-auth-ceremony" ".sqlite")
               .delete)
        ds (jdbc/get-datasource {:jdbcUrl (str "jdbc:sqlite:" (.getPath file))})]
    (auth/migrate! ds)
    (binding [*db* ds]
      (try (f)
           (finally
             (doseq [suffix ["" "-wal" "-shm"]]
               (io/delete-file (str (.getPath file) suffix) true)))))))

(use-fixtures :each with-database)

;; A directory standing in for the application's account model. The
;; library never reads a field on an account -- this is the whole of what
;; it knows about people.
(def ^:private directory
  {"nik@example.com" #uuid "00000000-0000-4000-8000-00000000000a"})

(defn- config []
  {:origin "https://example.com"
   :app-name "Example"
   :datasource *db*
   :accounts {:account-id-for-handle directory
              :handle-for-account (fn [account-id]
                                    (some (fn [[h a]] (when (= a account-id) h))
                                          directory))
              :display-name-for-account (constantly "Nik")}})

(def ^:private account-id (get directory "nik@example.com"))

(defn- anomaly? [x] (some? (::anom/category x)))

(defn- register-a-key! [credential-id]
  (auth/register-credential!
   *db* {:account-id account-id
         :credential-uuid (random-uuid)
         :credential-id credential-id
         :public-key "cose"
         :sign-count 0
         :label "Phone"}
   now))

;; ------------------------------------------------------------------
;; User handles
;; ------------------------------------------------------------------

(deftest user-handle-round-trips
  (testing "an account id survives the trip through WebAuthn's 16-byte handle"
    ;; The handle IS the account id in the shape the spec wants, which is
    ;; why nothing stores one. If this stops round-tripping, every
    ;; discoverable sign-in resolves to the wrong account or to none.
    (dotimes [_ 100]
      (let [id (random-uuid)]
        (is (= id (webauthn/handle-bytes->uuid (webauthn/uuid->handle-bytes id)))))))

  (testing "the handle is exactly 16 bytes"
    (is (= 16 (count (webauthn/uuid->handle-bytes (random-uuid)))))))

;; ------------------------------------------------------------------
;; Beginning a ceremony
;; ------------------------------------------------------------------

(deftest begin-registration
  (testing "the browser receives creation options naming this relying party"
    (let [{:keys [options-json pending]} (auth/begin-registration (config) {:account-id account-id})
          options (json/parse-string options-json true)]
      (is (= "example.com" (get-in options [:rp :id]))
          "the relying-party id is the host alone -- a scheme or port here fails every ceremony")
      (is (= "Example" (get-in options [:rp :name])))
      (is (= "nik@example.com" (get-in options [:user :name])))
      (is (= "Nik" (get-in options [:user :displayName]))
          "the display name is what an authenticator shows a person choosing a key")
      (is (seq (:challenge options)))
      (is (= options-json pending)
          "registration's two halves are the same string; the assertion's are not")))

  (testing "residentKey is required, or usernameless sign-in silently finds nothing"
    (let [{:keys [options-json]} (auth/begin-registration (config) {:account-id account-id})]
      (is (= "required"
             (get-in (json/parse-string options-json true)
                     [:authenticatorSelection :residentKey]))))))

(deftest begin-sign-in
  ;; Order matters here, and the fixture will not save you: use-fixtures
  ;; :each runs once per deftest, not per testing block, so a key
  ;; registered above is still there below. The empty cases go first.
  (testing "an unknown handle is refused"
    (is (anomaly? (auth/begin-sign-in (config) {:handle "nobody@example.com"}))))

  (testing "a known handle with no registered key is refused"
    (is (anomaly? (auth/begin-sign-in (config) {:handle "nik@example.com"}))))

  (testing "a handle with a registered key gets request options"
    (register-a-key! "cred-1")
    (let [{:keys [options-json pending]} (auth/begin-sign-in (config) {:handle "nik@example.com"})]
      (is (seq (:challenge (json/parse-string options-json true))))
      (is (not= options-json pending)
          "the browser gets the inner options; finish-assertion needs the whole request"))))

(deftest begin-discoverable-sign-in
  (testing "a usernameless ceremony needs no handle and names no credentials"
    (register-a-key! "cred-1")
    (let [{:keys [options-json]} (auth/begin-discoverable-sign-in (config))
          options (json/parse-string options-json true)]
      (is (seq (:challenge options)))
      ;; allowCredentials present would tell the browser which keys to
      ;; offer -- and tell whoever asked which keys exist.
      (is (empty? (:allowCredentials options))))))

;; ------------------------------------------------------------------
;; Failure paths
;; ------------------------------------------------------------------

(deftest a-ceremony-that-does-not-verify-is-refused
  (testing "garbage in place of a registration response stores nothing"
    (let [{:keys [pending]} (auth/begin-registration (config) {:account-id account-id})]
      (is (anomaly? (auth/complete-registration!
                     (config)
                     {:pending pending :credential-json "{\"not\":\"a credential\"}"
                      :account-id account-id :label "Phone"}
                     now)))
      (is (empty? (auth/credentials-for-account *db* account-id)))))

  (testing "garbage in place of an assertion opens no session"
    (register-a-key! "cred-1")
    (let [{:keys [pending]} (auth/begin-sign-in (config) {:handle "nik@example.com"})]
      (is (anomaly? (auth/complete-sign-in!
                     (config)
                     {:pending pending :credential-json "{\"not\":\"a credential\"}"}
                     now)))
      (is (empty? (auth/sessions-for-account *db* account-id now)))))

  (testing "verify never throws, whatever it is handed"
    ;; Every failure has to arrive as an anomaly. An exception escaping
    ;; here would reach a route handler as a 500, which says more about
    ;; what went wrong than a refusal should.
    (doseq [junk ["" "null" "[]" "{" "\"\"" "{\"id\":\"nope\"}"]]
      (is (anomaly? (auth/complete-sign-in!
                     (config) {:pending "{}" :credential-json junk} now))
          (str "did not refuse: " (pr-str junk))))))

(deftest RejectionRevealsNothing
  (testing "every sign-in failure says exactly the same thing"
    ;; auth.allium's guarantee. A caller must not be able to tell a
    ;; ceremony that did not verify from a credential that is not
    ;; registered -- that difference is an oracle for whether an account
    ;; exists.
    (register-a-key! "cred-1")
    (let [{:keys [pending]} (auth/begin-sign-in (config) {:handle "nik@example.com"})
          messages (into #{}
                         (map #(::anom/message
                                (auth/complete-sign-in! (config)
                                                        {:pending pending :credential-json %}
                                                        now)))
                         ["{\"not\":\"a credential\"}" "null" "{}"])]
      (is (= 1 (count messages)) (str "distinguishable failures: " messages)))))
