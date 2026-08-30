(ns nickdex.grain.auth.ceremony-test
  "Tests for the WebAuthn ceremony seam.

   What is NOT here: a ceremony that succeeds. Producing one needs a real
   authenticator holding a real private key, and the cryptography is
   com.yubico/webauthn-server-core's, verified by its own test suite
   rather than re-verified here. Faking it would mean faking the
   signature check, which is the only part that matters.

   What IS here is everything around that: the user seam Yubico calls
   into, the options a browser receives, and every failure path -- which
   is where the mistakes this library could make actually live, and where
   a uniform rejection message has to be checked rather than assumed."
  (:require [cheshire.core :as json]
            [com.brunobonacci.mulog.core :as mulog.core]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [cognitect.anomalies :as anom]
            [next.jdbc :as jdbc]
            [nickdex.grain.auth.interface :as auth]
            [nickdex.grain.auth.webauthn :as webauthn])
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

;; A directory standing in for the application's user model. The
;; library never reads a field on a user -- this is the whole of what
;; it knows about people.
(def ^:private directory
  {"nik@example.com" #uuid "00000000-0000-4000-8000-00000000000a"})

(defn- config []
  {:origin "https://example.com"
   :app-name "Example"
   :datasource *db*
   :users {:user-id-for-handle directory
              :handle-for-user (fn [user-id]
                                    (some (fn [[h a]] (when (= a user-id) h))
                                          directory))
              :display-name-for-user (constantly "Nik")}})

(def ^:private user-id (get directory "nik@example.com"))

(defn- anomaly? [x] (some? (::anom/category x)))

(defn- register-a-key! [credential-id]
  (auth/register-credential!
   *db* {:user-id user-id
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
  (testing "a user id survives the trip through WebAuthn's 16-byte handle"
    ;; The handle IS the user id in the shape the spec wants, which is
    ;; why nothing stores one. If this stops round-tripping, every
    ;; discoverable sign-in resolves to the wrong user or to none.
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
    (let [{:keys [options-json pending]} (auth/begin-registration (config) {:user-id user-id})
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
    (let [{:keys [options-json]} (auth/begin-registration (config) {:user-id user-id})]
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
    (let [{:keys [pending]} (auth/begin-registration (config) {:user-id user-id})]
      (is (anomaly? (auth/complete-registration!
                     (config)
                     {:pending pending :credential-json "{\"not\":\"a credential\"}"
                      :user-id user-id :label "Phone"}
                     now)))
      (is (empty? (auth/credentials-for-user *db* user-id)))))

  (testing "garbage in place of an assertion opens no session"
    (register-a-key! "cred-1")
    (let [{:keys [pending]} (auth/begin-sign-in (config) {:handle "nik@example.com"})]
      (is (anomaly? (auth/complete-sign-in!
                     (config)
                     {:pending pending :credential-json "{\"not\":\"a credential\"}"}
                     now)))
      (is (empty? (auth/sessions-for-user *db* user-id now)))))

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
    ;; registered -- that difference is an oracle for whether a user
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

;; ------------------------------------------------------------------
;; Origins
;; ------------------------------------------------------------------

(defn- yubico-allows?
  "Yubico's own matcher, asked directly. Reflection because it is
   package-private -- worth it, because the whole point of these tests is
   that our idea of 'the same origin' matches the library's, and
   restating its rules here would only prove we can restate them."
  [browser-origin configured]
  (let [m (doto (.getDeclaredMethod (Class/forName "com.yubico.webauthn.OriginMatcher")
                                    "isAllowed"
                                    (into-array Class [String java.util.Set
                                                       Boolean/TYPE Boolean/TYPE]))
            (.setAccessible true))]
    (.invoke m nil (object-array [browser-origin #{configured} false false]))))

(deftest a-configured-base-url-is-reduced-to-a-browser-origin
  ;; A base URL is a URL, and URLs collect trailing slashes and paths
  ;; without anyone deciding to add one. A clientData origin never has
  ;; either, and Yubico compares them as strings -- so the difference is
  ;; total, and it surfaces at the FINISH step, after the person has
  ;; already touched their authenticator, with a message naming nothing.
  (testing "a trailing slash is dropped"
    (is (= "https://example.com:8080"
           (webauthn/normalise-origin "https://example.com:8080/"))))

  (testing "a path is dropped"
    (is (= "https://example.com" (webauthn/normalise-origin "https://example.com/app"))))

  (testing "a default port is not restated -- the browser does not send one"
    (is (= "https://example.com" (webauthn/normalise-origin "https://example.com")))
    (is (= "https://example.com" (webauthn/normalise-origin "https://example.com/"))))

  (testing "a non-default port is kept, because the browser sends it"
    (is (= "http://localhost:8080" (webauthn/normalise-origin "http://localhost:8080/"))))

  (testing "an already-clean origin is left alone"
    (is (= "https://example.com" (webauthn/normalise-origin "https://example.com")))))

(deftest normalising-is-what-yubico-actually-accepts
  ;; The check that matters: not that our string looks tidy, but that the
  ;; matcher says yes to it and no to the raw one.
  (doseq [[configured browser]
          [["https://example.com:8080/" "https://example.com:8080"]
           ["http://localhost:8080/"    "http://localhost:8080"]
           ["https://example.com/"      "https://example.com"]]]
    (is (false? (yubico-allows? browser configured))
        (str "expected the raw base URL " configured " to be rejected -- if this "
             "passes, normalising is no longer buying anything"))
    (is (true? (yubico-allows? browser (webauthn/normalise-origin configured)))
        (str configured " still does not match " browser " after normalising"))))

(deftest the-relying-party-uses-the-normalised-origin
  ;; The wiring, not just the helper. Normalising a string that nothing
  ;; passes to the RelyingParty buys nothing, and that regression is
  ;; invisible until a ceremony fails at the finish step -- so it is
  ;; asserted against the object Yubico will actually match with.
  (let [rp (webauthn/relying-party {:origin "https://example.com:8080/"
                                    :app-name "Example"
                                    :datasource nil})]
    (is (= #{"https://example.com:8080"} (set (.getOrigins rp))))
    (is (= "example.com" (.getId (.getIdentity rp))))))

(deftest a-failed-ceremony-tells-the-LOG-what-it-will-not-tell-the-BROWSER
  ;; The refusal is uniform on purpose: which check failed must not reach
  ;; whoever asked, or the ceremony becomes a way to probe. That reasoning
  ;; does not extend to the server's own log, and for a long time this
  ;; caught every exception as `_` -- so a misconfigured origin produced a
  ;; failure with no evidence anywhere, on either side.
  ;;
  ;; Captured at mulog's core/log*, because u/log is a macro and has
  ;; already expanded past anything with-redefs could reach.
  (let [events (atom [])]
    (with-redefs [mulog.core/log* (fn [_logger event-name pairs]
                                    (swap! events conj [event-name (apply hash-map pairs)])
                                    nil)]
      (let [result (webauthn/verify-registration
                    {:origin "https://example.com/" :app-name "Example" :datasource nil}
                    {:pending "not-json" :credential-json "not-json"})]

        (testing "the caller still learns nothing"
          (is (nil? result)))

        (let [[event-name logged] (first @events)]
          (testing "but the log names the failure"
            (is (= ::webauthn/registration-failed event-name))
            (is (seq (str (:reason logged)))))

          (testing "and the origin it was comparing against -- the whole question"
            (is (= "https://example.com" (:configured-origin logged)))))))))

(deftest registering-refuses-a-user-with-no-handle
  ;; Two ways to get here, both real:
  ;;
  ;;   - a user recorded without an email. Optional now, because a
  ;;     contact book is full of people with only a phone.
  ;;   - a session naming a user whose record is gone. A session row
  ;;     lives thirty days and outlives what the app keeps.
  ;;
  ;; Yubico's UserIdentity refuses a null name, so this used to die as a
  ;; 500 with a stack trace naming a builder field -- which says nothing
  ;; about either cause, and which is exactly how it shipped.
  (let [config {:origin "https://example.test"
                :app-name "Example"
                :datasource nil
                :users {:handle-for-user (constantly nil)
                        :display-name-for-user (constantly "Ramesh")}}
        result (webauthn/start-registration config {:user-id (random-uuid)})]
    (is (= ::anom/incorrect (::anom/category result)))
    (is (re-find #"no handle" (::anom/message result)))))
