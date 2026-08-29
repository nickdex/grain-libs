(ns nickdex.grain.auth.enrolment
  "The first passkey on a new user: a six-digit code, issued by an
   operator and handed over out of band.

   Registering a credential needs an authenticated caller, and a new
   user has nothing to authenticate with. Something has to bridge that
   gap. This library used to bridge it with a signed link, which had two
   problems: it was a bearer credential sitting in a URL -- and URLs are
   forwarded, screenshotted and kept in history -- and it needed a
   signing key, which is one more thing an application can wire up
   wrongly without noticing.

   A code has neither problem. It can be read aloud over a phone call, it
   carries no user id for anyone to lift out of it, and it needs no
   key at all: what makes it safe is that only a hash is stored, it dies
   after an hour, and five wrong guesses burn it. Six digits with five
   attempts is a 1-in-200,000 chance -- the attempt cap, not the length,
   is what does the work.

   The shape is Biff's (com.biffweb.authenticate.impl.backend), which has
   run this flow in production for years. What differs is what the code
   authorises: Biff's code IS the sign-in, and this one only ever buys
   the right to register one passkey.

   ON THE HASH. It is plain SHA-256, and it is worth being clear about
   what that buys. Against a stolen database it is close to cosmetic: a
   million candidates fall to any fast hash instantly. Salting would not
   change that arithmetic, and an HMAC would put back exactly the key
   dependency this flow exists to remove. What it does protect against is
   casual exposure -- a `SELECT *` at the REPL, a log line, a backup
   somebody glances at -- and against a live code being usable straight
   from a row. The expiry and the attempt cap are the real defences.

   FIRST KEY ONLY. A code is checked against a user with no
   credentials, both when issued and when verified. That means it is
   spent the moment enrolment succeeds, with nothing to mark or clean up,
   and it means an intercepted code cannot add a key to a user that
   is already in use. Losing every passkey is therefore an operator
   matter: `reset-credentials!`, then a fresh code."
  (:require [cognitect.anomalies :as anom]
            [next.jdbc :as jdbc]
            [next.jdbc.sql :as sql]
            [nickdex.grain.auth.credentials :as credentials]
            [nickdex.grain.auth.store :as store])
  (:import [java.security MessageDigest SecureRandom]
           [java.time Duration Instant]))

(def default-lifetime
  "An hour. Long enough to send the code through a message and let
   somebody get to it; short enough that an intercepted message is stale
   before it is useful. The old signed link lived a full day, which only
   made sense because opening a link is instant -- a code has to be typed
   at the app, so the person is present either way."
  (Duration/ofHours 1))

(def max-attempts
  "Five wrong guesses and the code is dead, even before it expires. This
   is what makes six digits enough: without it, a million tries against a
   fixed code is a matter of minutes."
  5)

(defonce ^:private rng
  ;; One instance, seeded once. SecureRandom is thread-safe, and a fresh
  ;; one per call is both slower and no more random.
  (SecureRandom.))

(defn- new-code []
  ;; Zero-padded, so every one of the million values is six characters
  ;; and "004821" is as likely as "904821". Biff's version asks for
  ;; nextInt(10^6 - 1), which quietly makes 999999 unreachable.
  (format "%06d" (.nextInt ^SecureRandom rng 1000000)))

(defn- hash-code ^String [^String code]
  (->> (.getBytes code "UTF-8")
       (.digest (MessageDigest/getInstance "SHA-256"))
       (map #(format "%02x" %))
       (apply str)))

(defn- matches? [^String submitted ^String stored-hash]
  (and (string? submitted)
       (string? stored-hash)
       ;; Constant time. A comparison that returns early leaks how much
       ;; of the hash was right, one byte at a time.
       (MessageDigest/isEqual (.getBytes (hash-code submitted) "UTF-8")
                              (.getBytes stored-hash "UTF-8"))))

(defn- enrolled?
  "Whether this user already has a way in. The whole of the first-key
   rule, asked in the two places it matters."
  [datasource user-id]
  (pos? (credentials/count-for-user datasource user-id)))

;; ------------------------------------------------------------------
;; Issuing
;; ------------------------------------------------------------------

(defn issue!
  "Mint a code for one user and return {:code :expires-at} ONCE, in the
   clear.

   Takes the same config `verify!` does, because both of its refusals
   need it.

   The plaintext is never stored and cannot be recovered afterwards, so a
   caller that loses it issues another -- which replaces the first rather
   than adding to it.

   Two refusals, both stated here rather than left for the person at the
   other end of the phone to discover:

   - The user already has a passkey. First key only; see the ns
     docstring.
   - The user has no handle. `verify!` names a user by its handle, so a
     user the :users seam cannot produce one for -- a contact-book human
     with a phone number and no email -- can never complete enrolment. A
     code for them is dead on arrival, and saying so at issue is the
     difference between a rule and a mystery."
  ([config user-id ^Instant now]
   (issue! config user-id now default-lifetime))
  ([{:keys [datasource users] :as _config} user-id ^Instant now ^Duration lifetime]
   (cond
     (enrolled? datasource user-id)
     {::anom/category ::anom/conflict
      ::anom/message "That user already has a passkey."}

     (nil? (some-> (:handle-for-user users) (apply [user-id])))
     {::anom/category ::anom/incorrect
      ::anom/message (str "That user has no email to enrol with. A code names "
                          "the user by their handle, so there is nothing to "
                          "enter it against.")}

     :else
     (let [code (new-code)
           expires-at (.plus now lifetime)]
       (jdbc/execute-one!
        datasource
        ["INSERT INTO auth_enrolment_code
            (user_id, code_hash, expires_at, failed_attempts)
          VALUES (?, ?, ?, 0)
          ON CONFLICT(user_id) DO UPDATE SET
            code_hash = excluded.code_hash,
            expires_at = excluded.expires_at,
            failed_attempts = 0"
         (str user-id) (hash-code code) (store/->millis expires-at)])
       {:code code :expires-at expires-at}))))

(defn clear!
  "Revoke whatever code this user has, if any. Idempotent."
  [datasource user-id]
  (sql/delete! datasource :auth_enrolment_code
               {:user_id (str user-id)} store/options)
  nil)

;; ------------------------------------------------------------------
;; Verifying
;; ------------------------------------------------------------------

(defn verify!
  "The user this code enrols, or nil.

   `handle` is whatever the application's :users seam looks users
   up by -- an email, in both apps using this. It names the user; the
   code proves the person was told about it.

   nil covers every failure: no such handle, no code issued, the wrong
   code, an expired one, one that has been guessed at too many times, and
   a user that has since been enrolled. Telling them apart would say
   whether a user exists and whether it is already in use, to
   somebody holding nothing but a guess.

   A wrong code costs an attempt. A right one deletes the row, so it
   cannot be answered twice -- the caller gets one grant out of this and
   has to come back for another."
  [{:keys [datasource users]} handle ^String code ^Instant now]
  (let [user-id (when-let [f (:user-id-for-handle users)]
                     (f handle))]
    (when user-id
      (jdbc/with-transaction [tx datasource]
        (let [row (sql/get-by-id tx :auth_enrolment_code (str user-id)
                                 :user_id store/options)]
          (when (and row (< (:failed-attempts row) max-attempts))
            (if (and (< (.toEpochMilli now) (long (:expires-at row)))
                     (matches? code (:code-hash row))
                     ;; Re-asked at the moment of use. A code issued
                     ;; before a key existed must not still work after
                     ;; one does.
                     (not (enrolled? tx user-id)))
              (do (sql/delete! tx :auth_enrolment_code
                               {:user_id (str user-id)} store/options)
                  user-id)
              (do (jdbc/execute-one!
                   tx
                   ["UPDATE auth_enrolment_code
                       SET failed_attempts = failed_attempts + 1
                     WHERE user_id = ?" (str user-id)])
                  nil))))))))

(defn pending?
  "Whether this user has a code outstanding that could still be used.
   For an operator listing, not for any decision on the request path --
   `verify!` is the only thing that should be judging a code."
  [datasource user-id ^Instant now]
  (boolean
   (when-let [row (sql/get-by-id datasource :auth_enrolment_code (str user-id)
                                 :user_id store/options)]
     (and (< (:failed-attempts row) max-attempts)
          (< (.toEpochMilli now) (long (:expires-at row)))))))

;; ------------------------------------------------------------------
;; Recovery
;; ------------------------------------------------------------------

(defn reset-credentials!
  "Remove every passkey and session on a user, so a fresh code can
   enrol it again.

   The way back from losing every device. Deliberately NOT reachable over
   HTTP and deliberately not something a code can trigger: it is the one
   operation that turns a user somebody holds into a user anybody
   with the next code holds, so it wants a human decision behind it.

   `credentials/remove!` refuses to remove a last key for exactly that
   reason, which is why recovery cannot be assembled out of the ordinary
   operations and lives here instead.

   Returns how many keys were removed."
  [datasource user-id]
  (jdbc/with-transaction [tx datasource]
    (let [n (credentials/count-for-user tx user-id)]
      (sql/delete! tx :auth_credential {:user_id (str user-id)} store/options)
      (sql/delete! tx :auth_session {:user_id (str user-id)} store/options)
      (sql/delete! tx :auth_enrolment_code {:user_id (str user-id)} store/options)
      n)))
