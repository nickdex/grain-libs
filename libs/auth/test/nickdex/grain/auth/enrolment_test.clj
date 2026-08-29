(ns nickdex.grain.auth.enrolment-test
  "The six-digit enrolment code: issuing, verifying, and the three things
   that stop it being a password.

   Same seam as auth_test: a real SQLite database in a temp file, the
   real schema, real transactions. Not `:memory:` -- every connection in
   a pool gets its own private in-memory database unless shared-cache is
   negotiated, and `verify!` runs in a transaction."
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [cognitect.anomalies :as anom]
            [next.jdbc :as jdbc]
            [nickdex.grain.auth.interface :as auth])
  (:import [java.time Duration Instant]))

(def now (Instant/parse "2026-08-26T09:00:00Z"))

(defn- later [^Duration d] (.plus now d))

(def ^:dynamic *db* nil)

(defn with-database [f]
  (let [file (doto (java.io.File/createTempFile "grain-auth-enrol-test" ".sqlite")
               .delete)
        ds (jdbc/get-datasource {:jdbcUrl (str "jdbc:sqlite:" (.getPath file))})]
    (auth/migrate! ds)
    (binding [*db* ds]
      (try (f)
           (finally
             (doseq [suffix ["" "-wal" "-shm"]]
               (io/delete-file (str (.getPath file) suffix) true)))))))

(use-fixtures :each with-database)

;; ------------------------------------------------------------------
;; Fixtures
;; ------------------------------------------------------------------

(defn- config
  "The :users seam, standing in for an application's own lookup.
   `handles` maps a handle to a user id; the reverse direction is what
   `issue!` checks before minting a code for somebody who could never
   enter it."
  [handles]
  (let [ids->handles (into {} (map (comp vec reverse)) handles)]
    {:datasource *db*
     :users {:user-id-for-handle (fn [handle] (get handles handle))
             :handle-for-user (fn [user-id] (get ids->handles user-id))}}))

(defn- register! [user-id]
  (auth/register-credential!
   *db* {:user-id user-id
         :credential-uuid (random-uuid)
         :credential-id (str "cred-" (random-uuid))
         :public-key "cose-public-key"
         :sign-count 0
         :label "Phone"}
   now))

;; ------------------------------------------------------------------
;; Issuing
;; ------------------------------------------------------------------

(deftest a-code-is-six-digits-and-unpredictable
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}
        {:keys [code expires-at]} (auth/issue-enrolment-code! (config handles) user-id now)]
    (testing "six digits, zero-padded, so every value in the range is reachable"
      (is (re-matches #"\d{6}" code)))

    (testing "it expires an hour out by default"
      (is (= (.plus now auth/enrolment-lifetime) expires-at)))

    (testing "successive codes differ"
      ;; Not a randomness test -- SecureRandom is not on trial here. This
      ;; catches a constant, which is the failure that would otherwise
      ;; look exactly like a working system.
      (let [codes (repeatedly 20 #(:code (auth/issue-enrolment-code! (config handles) user-id now)))]
        (is (< 1 (count (distinct codes))))))))

(deftest the-plaintext-code-is-never-stored
  ;; The point of hashing. A code readable straight out of the table
  ;; would make a REPL session, a log line or a backup enough to enrol.
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}
        {:keys [code]} (auth/issue-enrolment-code! (config handles) user-id now)
        row (jdbc/execute-one! *db* ["SELECT * FROM auth_enrolment_code"])]
    (is (not (some #{code} (map str (vals row))))
        (str "the code appears verbatim in " (pr-str row)))))

(deftest issuing-again-replaces-rather-than-accumulates
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}
        first-code (:code (auth/issue-enrolment-code! (config handles) user-id now))
        second-code (:code (auth/issue-enrolment-code! (config handles) user-id now))]
    (testing "one row per user, whatever was issued before"
      (is (= 1 (:n (jdbc/execute-one!
                    *db* ["SELECT COUNT(*) AS n FROM auth_enrolment_code"])))))

    (testing "the superseded code no longer works"
      ;; Only meaningful when the two differ; a 1-in-a-million collision
      ;; would otherwise fail this for the wrong reason.
      (when (not= first-code second-code)
        (is (nil? (auth/verify-enrolment-code! (config handles)
                                               "a@example.test" first-code now)))))

    (testing "and the newest one does"
      (is (= user-id (auth/verify-enrolment-code! (config handles)
                                                     "a@example.test" second-code now))))))

(deftest an-enrolled-user-cannot-be-issued-a-code
  ;; First key only. Told to the operator at the point of issue, so they
  ;; do not read a code down the phone that was never going to work.
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}]
    (register! user-id)
    (let [result (auth/issue-enrolment-code! (config handles) user-id now)]
      (is (= ::anom/conflict (::anom/category result))))))

;; ------------------------------------------------------------------
;; Verifying
;; ------------------------------------------------------------------

(deftest a-user-with-no-handle-cannot-be-issued-a-code
  ;; Email is optional on a user now -- a contact-book human may have a
  ;; phone and nothing else. verify! names a user BY its handle, so a
  ;; code for somebody without one could never be entered against
  ;; anything. Refusing at issue is the difference between a rule and a
  ;; mystery on the other end of a phone call.
  (let [user-id (random-uuid)
        result (auth/issue-enrolment-code! (config {}) user-id now)]
    (is (= ::anom/incorrect (::anom/category result)))
    (is (re-find #"no email" (::anom/message result)))

    (testing "and nothing was written, so there is no dead code to expire"
      (is (false? (auth/enrolment-pending? *db* user-id now))))))

(deftest a-correct-code-names-its-user-once
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}
        {:keys [code]} (auth/issue-enrolment-code! (config handles) user-id now)]
    (testing "it verifies"
      (is (= user-id (auth/verify-enrolment-code! (config handles)
                                                     "a@example.test" code now))))

    (testing "and is consumed, so a captured code cannot be answered twice"
      (is (nil? (auth/verify-enrolment-code! (config handles)
                                             "a@example.test" code now))))))

(deftest every-failure-looks-the-same
  ;; RejectionRevealsNothing. Which of these it was would say whether an
  ;; user exists and whether it is already in use, to somebody holding
  ;; nothing but a guess.
  (let [enrolled (random-uuid)
        no-code (random-uuid)
        user-id (random-uuid)
        handles {"enrolled@example.test" enrolled
                 "nocode@example.test" no-code
                 "a@example.test" user-id}
        {:keys [code]} (auth/issue-enrolment-code! (config handles) user-id now)]
    (register! enrolled)
    (is (nil? (auth/verify-enrolment-code! (config handles)
                                           "nobody@example.test" code now))
        "a handle nobody holds")
    (is (nil? (auth/verify-enrolment-code! (config handles)
                                           "nocode@example.test" code now))
        "a user with no code outstanding")
    (is (nil? (auth/verify-enrolment-code! (config handles)
                                           "enrolled@example.test" code now))
        "a user that already has a passkey")
    (is (nil? (auth/verify-enrolment-code! (config handles)
                                           "a@example.test" "000000" now))
        "the wrong code")
    (is (nil? (auth/verify-enrolment-code! (config handles) "a@example.test" nil now))
        "no code at all")))

(deftest a-code-expires
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}
        {:keys [code]} (auth/issue-enrolment-code! (config handles) user-id now)]
    (testing "still good a minute before"
      (is (some? (auth/verify-enrolment-code!
                  (config handles) "a@example.test" code
                  (later (.minusMinutes auth/enrolment-lifetime 1))))))

    (let [{:keys [code]} (auth/issue-enrolment-code! (config handles) user-id now)]
      (testing "and dead a minute after"
        (is (nil? (auth/verify-enrolment-code!
                   (config handles) "a@example.test" code
                   (later (.plusMinutes auth/enrolment-lifetime 1)))))))))

(deftest guessing-burns-the-code
  ;; The defence that makes six digits enough. Without it, a million
  ;; tries against a fixed code is minutes of work.
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}
        {:keys [code]} (auth/issue-enrolment-code! (config handles) user-id now)
        wrong (if (= code "000000") "111111" "000000")]
    (dotimes [_ auth/enrolment-max-attempts]
      (is (nil? (auth/verify-enrolment-code! (config handles)
                                             "a@example.test" wrong now))))

    (testing "the correct code is refused after the cap is reached"
      (is (nil? (auth/verify-enrolment-code! (config handles)
                                             "a@example.test" code now))))

    (testing "and a fresh code clears the attempts"
      (let [{:keys [code]} (auth/issue-enrolment-code! (config handles) user-id now)]
        (is (= user-id (auth/verify-enrolment-code! (config handles)
                                                       "a@example.test" code now)))))))

(deftest a-code-issued-before-a-key-existed-stops-working-once-one-does
  ;; The first-key rule asked again at the moment of use, not only at
  ;; issue. Otherwise a code minted for a new user stays live through
  ;; the window in which somebody else enrols it.
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}
        {:keys [code]} (auth/issue-enrolment-code! (config handles) user-id now)]
    (register! user-id)
    (is (nil? (auth/verify-enrolment-code! (config handles)
                                           "a@example.test" code now)))))

;; ------------------------------------------------------------------
;; Operator paths
;; ------------------------------------------------------------------

(deftest a-code-can-be-revoked
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}
        {:keys [code]} (auth/issue-enrolment-code! (config handles) user-id now)]
    (is (true? (auth/enrolment-pending? *db* user-id now)))
    (auth/clear-enrolment-code! *db* user-id)
    (is (false? (auth/enrolment-pending? *db* user-id now)))
    (is (nil? (auth/verify-enrolment-code! (config handles)
                                           "a@example.test" code now)))))

(deftest pending-tracks-what-verify-would-accept
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}]
    (is (false? (auth/enrolment-pending? *db* user-id now))
        "nothing issued")
    (auth/issue-enrolment-code! (config handles) user-id now)
    (is (true? (auth/enrolment-pending? *db* user-id now)))
    (is (false? (auth/enrolment-pending?
                 *db* user-id (later (.plusMinutes auth/enrolment-lifetime 1))))
        "expired")))

(deftest resetting-credentials-is-the-way-back-from-losing-every-device
  (let [user-id (random-uuid)
        handles {"a@example.test" user-id}]
    (register! user-id)
    (testing "the ordinary removal refuses to take a last key, by design"
      (let [only (:credential-uuid (first (auth/credentials-for-user *db* user-id)))]
        (is (= ::anom/incorrect
               (::anom/category (auth/remove-credential! *db* only))))))

    (testing "so recovery is its own operator-only operation"
      (is (= 1 (auth/reset-credentials! *db* user-id)))
      (is (empty? (auth/credentials-for-user *db* user-id))))

    (testing "and the user can be enrolled again"
      (let [{:keys [code]} (auth/issue-enrolment-code! (config handles) user-id now)]
        (is (= user-id (auth/verify-enrolment-code! (config handles)
                                                       "a@example.test" code now)))))))
