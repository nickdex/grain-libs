(ns nickdex.grain.auth.auth-test
  "Tests propagated from auth.allium.

   Every `testing` string opens with the Allium obligation it discharges
   (`allium plan src/nickdex/grain/auth/auth.allium`), so a failing run
   names the spec clause that broke rather than just the group it sat in.

   The seam is the real thing minus the file: a real SQLite database, the
   real schema, real transactions. Only the location is swapped, for a
   temp file per test. Not `:memory:` -- every connection in a pool gets
   its own private in-memory database unless shared-cache is negotiated,
   so a two-connection test against `:memory:` passes or fails depending
   on which connection it happened to get."
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
  (let [file (doto (java.io.File/createTempFile "grain-auth-test" ".sqlite")
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

;; A fresh account per `testing` block. use-fixtures :each runs once per
;; deftest, NOT per testing block, so blocks inside one deftest share a
;; database -- and an account reused across them accumulates the
;; credentials and sessions the earlier blocks made. Three assertions
;; here failed that way before this existed.
(defn- account [] (random-uuid))

(defn- register!
  ([account-id credential-id] (register! account-id credential-id "Phone" 0))
  ([account-id credential-id label sign-count]
   (let [uuid (random-uuid)]
     (auth/register-credential!
      *db* {:account-id account-id
            :credential-uuid uuid
            :credential-id credential-id
            :public-key "cose-public-key"
            :sign-count sign-count
            :label label}
      now)
     uuid)))

(defn- sign-in!
  ([credential-uuid sign-count] (sign-in! credential-uuid sign-count now))
  ([credential-uuid sign-count at]
   (auth/sign-in! *db* {:session-id (random-uuid)
                        :credential-uuid credential-uuid
                        :sign-count sign-count}
                  at)))

(defn- anomaly? [x] (some? (::anom/category x)))

;; ------------------------------------------------------------------
;; RegisterCredential
;; ------------------------------------------------------------------

(deftest register-credential
  (testing "RegisterCredential: a registered key is found by the id an authenticator sends"
    (let [owner (account)
          uuid (register! owner "cred-1")]
      (is (= uuid (:credential-uuid (auth/credential-by-id *db* "cred-1"))))
      (is (= owner (:account-id (auth/credential-by-id *db* "cred-1"))))
      (is (= now (:created-at (auth/credential-by-id *db* "cred-1"))))))

  (testing "RegisterCredential requires: label != \"\""
    (is (anomaly? (auth/register-credential!
                   *db* {:account-id (account) :credential-uuid (random-uuid)
                         :credential-id "cred-blank" :public-key "k"
                         :sign-count 0 :label "   "}
                   now)))
    (is (nil? (auth/credential-by-id *db* "cred-blank"))))

  (testing "RegisterCredential requires: not exists Credential{credential_id}"
    (let [owner (account)]
      (register! owner "cred-dupe")
      (is (anomaly? (auth/register-credential!
                     *db* {:account-id owner :credential-uuid (random-uuid)
                           :credential-id "cred-dupe" :public-key "k"
                           :sign-count 0 :label "Second"}
                     now)))))

  (testing "and that check spans every account, not only this one"
    ;; A credential id resolving to two accounts is the failure this
    ;; prevents; scoping the check per account would allow it.
    (let [mine (account) theirs (account)]
      (register! mine "cred-shared")
      (is (anomaly? (auth/register-credential!
                     *db* {:account-id theirs :credential-uuid (random-uuid)
                           :credential-id "cred-shared" :public-key "k"
                           :sign-count 0 :label "Mine now"}
                     now)))
      (is (= mine (:account-id (auth/credential-by-id *db* "cred-shared")))))))

;; ------------------------------------------------------------------
;; SignIn
;; ------------------------------------------------------------------

(deftest sign-in
  (testing "SignIn: a counter that rose opens a session on the credential's account"
    (let [owner (account)
          uuid (register! owner "cred-1" "Phone" 5)
          session (sign-in! uuid 6)]
      (is (not (anomaly? session)))
      (is (= owner (:account-id session)))
      (is (= now (:started-at session)))))

  (testing "SignIn ensures: credential.sign_count = sign_count"
    (let [uuid (register! (account) "cred-2" "Key" 5)]
      (sign-in! uuid 9)
      (is (= 9 (:sign-count (auth/credential-by-id *db* "cred-2"))))
      (is (= now (:last-used-at (auth/credential-by-id *db* "cred-2"))))))

  (testing "SignIn requires: sign_count > credential.sign_count -- a repeat is a clone"
    (let [uuid (register! (account) "cred-3" "Key" 5)]
      (is (anomaly? (sign-in! uuid 5)))
      (is (anomaly? (sign-in! uuid 4)))))

  (testing "SignIn requires: ... or sign_count = 0 -- synced passkeys report 0 forever"
    ;; Not an exemption bolted on: a counter cannot be kept consistent
    ;; across copies that are all legitimate, so Apple's and Google's
    ;; authenticators send 0 every time. Requiring a rise rejects them.
    (let [uuid (register! (account) "cred-4" "iCloud" 0)]
      (is (not (anomaly? (sign-in! uuid 0))))
      (is (not (anomaly? (sign-in! uuid 0))))))

  (testing "SignIn on an unknown credential is refused"
    (is (anomaly? (sign-in! (random-uuid) 1))))

  (testing "RejectionRevealsNothing: unknown and counter-failed say the same thing"
    ;; Distinguishing them turns sign-in into a way to ask whether a
    ;; credential exists.
    (let [uuid (register! (account) "cred-5" "Key" 5)
          unknown (sign-in! (random-uuid) 1)
          replayed (sign-in! uuid 5)]
      (is (= (::anom/message unknown) (::anom/message replayed)))))

  (testing "a refused sign-in moves nothing: not the counter, not a session"
    ;; The counter move and the session insert share a transaction, so a
    ;; rejection must leave neither behind.
    (let [owner (account)
          uuid (register! owner "cred-6" "Key" 5)]
      (sign-in! uuid 5)
      (is (= 5 (:sign-count (auth/credential-by-id *db* "cred-6"))))
      (is (nil? (:last-used-at (auth/credential-by-id *db* "cred-6"))))
      (is (empty? (auth/sessions-for-account *db* owner now))))))

;; ------------------------------------------------------------------
;; Sessions
;; ------------------------------------------------------------------

(deftest session-lifetime
  (testing "SignIn ensures: session.expires_at = now + config.session_lifetime"
    (let [uuid (register! (account) "cred-1")
          session (sign-in! uuid 1)]
      (is (= (.plus now auth/default-session-lifetime) (:expires-at session)))))

  (testing "SessionExpires: expiry is derived, so a read past expires_at finds nothing"
    ;; No sweep has to have run for this to be correct.
    (let [owner (account)
          uuid (register! owner "cred-2")
          {:keys [session-id]} (sign-in! uuid 1)]
      (is (some? (auth/session *db* session-id (later (Duration/ofDays 29)))))
      (is (nil? (auth/session *db* session-id (later (Duration/ofDays 31)))))
      (is (empty? (auth/sessions-for-account *db* owner (later (Duration/ofDays 31)))))))

  (testing "purging expired sessions changes no answer"
    (let [uuid (register! (account) "cred-3")
          {:keys [session-id]} (sign-in! uuid 1)
          at (later (Duration/ofDays 31))]
      (is (nil? (auth/session *db* session-id at)))
      (auth/purge-expired-sessions! *db* at)
      (is (nil? (auth/session *db* session-id at)))))

  (testing "last_seen_at moves once it is stale, and not before"
    (let [uuid (register! (account) "cred-4")
          {:keys [session-id]} (sign-in! uuid 1)]
      (auth/session *db* session-id (later (Duration/ofSeconds 10)))
      (is (= now (:last-seen-at (auth/session *db* session-id now)))
          "a read seconds later must not write")
      (let [at (later (Duration/ofMinutes 5))]
        (auth/session *db* session-id at)
        (is (= at (:last-seen-at (auth/session *db* session-id at))))))))

(deftest opening-a-session-after-registration
  ;; sign-in! cannot serve this case: a freshly registered credential's
  ;; stored counter IS the one registration returned, so presenting it
  ;; again reads as a replay. That check is right for an assertion and
  ;; meaningless straight after a registration, which is itself proof of
  ;; possession.
  (testing "open! mints a session without a counter check"
    (let [owner (account)
          uuid (register! owner "cred-1" "Phone" 7)
          session (auth/open-session! *db* uuid now)]
      (is (some? session))
      (is (= owner (:account-id session)))
      (is (= (.plus now auth/default-session-lifetime) (:expires-at session)))
      (is (some? (auth/session *db* (:session-id session) now)))))

  (testing "and sign-in! at that same counter would have been refused"
    (let [uuid (register! (account) "cred-2" "Phone" 7)]
      (is (anomaly? (sign-in! uuid 7)))))

  (testing "an unknown credential opens nothing"
    (is (nil? (auth/open-session! *db* (random-uuid) now)))))

(deftest sign-out
  (testing "SignOut: an ended session stops working at once"
    (let [owner (account)
          uuid (register! owner "cred-1")
          {:keys [session-id]} (sign-in! uuid 1)]
      (is (nil? (auth/sign-out! *db* session-id owner)))
      (is (nil? (auth/session *db* session-id now)))))

  (testing "SignOut on somebody else's session is refused and leaves it running"
    ;; Without the account in the WHERE clause, a session id alone would
    ;; be enough to sign another person out.
    (let [owner (account)
          uuid (register! owner "cred-2")
          {:keys [session-id]} (sign-in! uuid 1)]
      (is (anomaly? (auth/sign-out! *db* session-id (account))))
      (is (some? (auth/session *db* session-id now)))))

  (testing "SignOut on an already-ended session is refused"
    (let [owner (account)
          uuid (register! owner "cred-3")
          {:keys [session-id]} (sign-in! uuid 1)]
      (auth/sign-out! *db* session-id owner)
      (is (anomaly? (auth/sign-out! *db* session-id owner)))))

  (testing "SessionManagement lists every active session on the account"
    (let [owner (account)
          other (account)
          a (register! owner "cred-4")
          b (register! owner "cred-5")]
      (sign-in! a 1)
      (sign-in! b 1)
      (is (= 2 (count (auth/sessions-for-account *db* owner now))))
      (is (empty? (auth/sessions-for-account *db* other now))))))

;; ------------------------------------------------------------------
;; RenameCredential / RemoveCredential
;; ------------------------------------------------------------------

(deftest rename-credential
  (testing "RenameCredential ensures: credential.label = label"
    (let [uuid (register! (account) "cred-1" "Old" 0)]
      (is (nil? (auth/rename-credential! *db* uuid "New")))
      (is (= "New" (:label (auth/credential-by-id *db* "cred-1"))))))

  (testing "RenameCredential requires: label != \"\""
    (let [uuid (register! (account) "cred-2" "Keep" 0)]
      (is (anomaly? (auth/rename-credential! *db* uuid "  ")))
      (is (= "Keep" (:label (auth/credential-by-id *db* "cred-2")))))))

(deftest remove-credential
  (testing "RemoveCredential ensures: not exists credential"
    (let [owner (account)]
      (register! owner "cred-1")
      (let [second (register! owner "cred-2")]
        (is (nil? (auth/remove-credential! *db* second)))
        (is (nil? (auth/credential-by-id *db* "cred-2")))
        (is (some? (auth/credential-by-id *db* "cred-1"))))))

  (testing "RemoveCredential requires: the account keeps at least one way in"
    ;; There is no recovery in this library, so an account with no
    ;; credentials is one nobody can reach.
    (let [only (register! (account) "cred-3")]
      (is (anomaly? (auth/remove-credential! *db* only)))
      (is (some? (auth/credential-by-id *db* "cred-3")))))

  (testing "removing a key ends EVERY session on the account, not only its own"
    ;; Blunt on purpose: a key is removed because it was lost or stolen,
    ;; and the question then is whether anyone else is still signed in.
    (let [owner (account)
          a (register! owner "cred-4")
          b (register! owner "cred-5")
          from-a (sign-in! a 1)
          from-b (sign-in! b 1)]
      (is (nil? (auth/remove-credential! *db* a)))
      (is (nil? (auth/session *db* (:session-id from-a) now)))
      (is (nil? (auth/session *db* (:session-id from-b) now)))))

  (testing "and leaves another account's sessions alone"
    (let [owner (account)
          other (account)
          a1 (register! owner "cred-6")
          _ (register! owner "cred-7")
          b1 (register! other "cred-8")
          theirs (sign-in! b1 1)]
      (sign-in! a1 1)
      (auth/remove-credential! *db* a1)
      (is (some? (auth/session *db* (:session-id theirs) now)))))

  (testing "RemoveCredential on an unknown credential is refused"
    (is (anomaly? (auth/remove-credential! *db* (random-uuid))))))
