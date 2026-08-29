(ns nickdex.grain.auth.sessions
  "auth.allium's Session: opening one after a verified assertion, reading
   it back on every request, and ending it here or on another device.

   Expiry is a WHERE clause, not a job. A session is expired when its
   expires_at has passed, and every read says so -- there is no sweep
   that has to have run for the check to be correct. `purge-expired!`
   exists to reclaim rows, and deleting nothing changes no answer.

   `last_seen_at` is throttled. Writing it on every request would put
   request-rate writes on the same file the event store uses, and the
   value is only ever read to the nearest minute anyway."
  (:require [cognitect.anomalies :as anom]
            [next.jdbc :as jdbc]
            [next.jdbc.sql :as sql]
            [nickdex.grain.auth.credentials :as credentials]
            [nickdex.grain.auth.store :as store])
  (:import [java.time Duration Instant]))

(def default-lifetime
  "auth.allium's config.session_lifetime. Absolute, measured from the
   sign-in: a session in daily use still ends on schedule."
  (Duration/ofDays 30))

(def ^:private last-seen-resolution
  "How stale last_seen_at may get before a read bothers to write it."
  (Duration/ofMinutes 1))

(defn- forbidden [message]
  {::anom/category ::anom/forbidden ::anom/message message})

(defn open!
  "Open a session for a credential WITHOUT a counter check.

   Only for use immediately after a registration ceremony. That ceremony
   is itself proof of possession -- the authenticator just created this
   credential on this device -- so re-proving it by assertion adds a tap
   and nothing else.

   sign-in! cannot serve this case and should not be bent to. A freshly
   registered credential's stored counter IS the one registration
   returned, so presenting it again reads as a replay and is refused.
   That check is right for an assertion and meaningless here.

   Everything else matches sign-in!: same lifetime, same row, same
   expiry."
  ([datasource credential-uuid now] (open! datasource credential-uuid now default-lifetime))
  ([datasource credential-uuid ^Instant now ^Duration lifetime]
   (jdbc/with-transaction [tx datasource]
     (when-let [credential (credentials/by-uuid tx credential-uuid)]
       (let [session-id (random-uuid)
             expires-at (.plus now lifetime)]
         (sql/insert! tx :auth_session
                      {:session_id (str session-id)
                       :user_id (str (:user-id credential))
                       :started_at (store/->millis now)
                       :last_seen_at (store/->millis now)
                       :expires_at (store/->millis expires-at)}
                      store/options)
         {:session-id session-id
          :user-id (:user-id credential)
          :started-at now
          :last-seen-at now
          :expires-at expires-at})))))

(defn- row->session [row]
  (when row
    (-> row
        (update :session-id parse-uuid)
        (update :user-id parse-uuid)
        (update :started-at store/<-millis)
        (update :last-seen-at store/<-millis)
        (update :expires-at store/<-millis))))

;; ------------------------------------------------------------------
;; Signing in
;; ------------------------------------------------------------------

(defn sign-in!
  "auth.allium's SignIn. Opens a session for a credential whose assertion
   has ALREADY been verified -- this function does not check a signature
   and must never be reachable from a request that has not.

   The counter check is WebAuthn's clone detection: a device-bound
   authenticator's counter only rises, so one that repeats or goes
   backwards means the key was copied. Zero is not an exemption bolted on
   afterwards -- synced authenticators, which is most passkeys in use,
   report 0 on every assertion by design, and requiring a rise would
   reject them all.

   The counter move and the session insert share one transaction. Split
   apart, a failure between them leaves a counter that advanced for a
   sign-in that did not happen, and the next genuine assertion at the
   same counter reads as a clone."
  ([datasource args now] (sign-in! datasource args now default-lifetime))
  ([datasource {:keys [session-id credential-uuid sign-count]} ^Instant now
    ^Duration lifetime]
   (jdbc/with-transaction [tx datasource]
     (let [credential (credentials/by-uuid tx credential-uuid)]
       (if (or (nil? credential)
               (not (or (zero? sign-count)
                        (> sign-count (:sign-count credential)))))
         ;; One message for an unknown credential and for a failed
         ;; counter check. Telling them apart turns sign-in into a way to
         ;; ask whether a credential exists.
         (forbidden "That passkey could not be used to sign in.")
         (let [expires-at (.plus now lifetime)]
           (credentials/record-use! tx credential-uuid sign-count now)
           (sql/insert! tx :auth_session
                        {:session_id (str session-id)
                         :user_id (str (:user-id credential))
                         :started_at (store/->millis now)
                         :last_seen_at (store/->millis now)
                         :expires_at (store/->millis expires-at)}
                        store/options)
           {:session-id session-id
            :user-id (:user-id credential)
            :started-at now
            :last-seen-at now
            :expires-at expires-at}))))))

;; ------------------------------------------------------------------
;; Reading
;; ------------------------------------------------------------------

(defn active
  "The session behind a request, or nil when it has ended or run out.
   Touches last_seen_at only once it is more than a minute stale."
  [datasource session-id ^Instant now]
  (when session-id
    (when-let [session (row->session
                        (first (sql/query datasource
                                          ["SELECT * FROM auth_session
                                             WHERE session_id = ? AND expires_at > ?"
                                           (str session-id) (store/->millis now)]
                                          store/options)))]
      (when (.isAfter now (.plus ^Instant (:last-seen-at session) last-seen-resolution))
        (sql/update! datasource :auth_session
                     {:last_seen_at (store/->millis now)}
                     {:session_id (str session-id)}
                     store/options))
      session)))

(defn for-user
  "Sessions on this user that have not ended or run out, most recent
   first. What auth.allium's SessionManagement lists."
  [datasource user-id ^Instant now]
  (->> (sql/query datasource
                  ["SELECT * FROM auth_session
                     WHERE user_id = ? AND expires_at > ?
                     ORDER BY started_at DESC"
                   (str user-id) (store/->millis now)]
                  store/options)
       (mapv row->session)))

;; ------------------------------------------------------------------
;; Signing out
;; ------------------------------------------------------------------

(defn sign-out!
  "auth.allium's SignOut. Ends one session, here or on another device --
   nothing distinguishes the two, because a session is ended by whoever
   holds the user and where the request came from does not change what
   happens to it.

   `user-id` is the caller's own, and a session belonging to anyone
   else is left alone and reported the same way an absent one is. Without
   that condition in the WHERE clause, a session id is enough to end
   somebody else's session."
  [datasource session-id user-id]
  (let [deleted (-> (sql/delete! datasource :auth_session
                                 {:session_id (str session-id)
                                  :user_id (str user-id)}
                                 store/options)
                    ::jdbc/update-count)]
    (when (zero? (or deleted 0))
      {::anom/category ::anom/not-found
       ::anom/message "That session has already ended."})))

(defn sign-out-user!
  "End every session on a user. What removing a passkey does, and
   what a person asking to be signed out everywhere gets."
  [datasource user-id]
  (sql/delete! datasource :auth_session
               {:user_id (str user-id)}
               store/options)
  nil)

(defn purge-expired!
  "Delete sessions that have run out. Reclaims rows only -- every read
   already excludes them, so this changes no answer and may run whenever
   it is convenient, or never."
  [datasource ^Instant now]
  (-> (jdbc/execute-one! datasource
                         ["DELETE FROM auth_session WHERE expires_at <= ?"
                          (store/->millis now)]
                         store/options)
      ::jdbc/update-count))
