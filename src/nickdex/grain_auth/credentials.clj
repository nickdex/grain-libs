(ns nickdex.grain-auth.credentials
  "auth.allium's Credential: registering a passkey, looking one up,
   renaming it, and removing it.

   Every function takes `now` as an argument rather than reading the
   clock, so a test can pin it and a caller cannot end up with two
   different notions of the current instant inside one request.

   Rejections are cognitect.anomalies maps, not exceptions. Where the
   message would confirm something the caller should not learn, it says
   less on purpose -- see RejectionRevealsNothing in auth.allium."
  (:require [clojure.string :as str]
            [cognitect.anomalies :as anom]
            [next.jdbc :as jdbc]
            [next.jdbc.sql :as sql]
            [nickdex.grain-auth.store :as store])
  (:import [java.time Instant]))

(defn- incorrect [message]
  {::anom/category ::anom/incorrect ::anom/message message})

(defn- ->label
  "The trimmed label, or nil when there is nothing left after trimming."
  [value]
  (let [t (str/trim (or value ""))]
    (when (seq t) t)))

(defn- row->credential [row]
  (when row
    (-> row
        (update :credential-uuid parse-uuid)
        (update :account-id parse-uuid)
        (update :created-at store/<-millis)
        (update :last-used-at store/<-millis))))

;; ------------------------------------------------------------------
;; Reading
;; ------------------------------------------------------------------

(defn by-credential-id
  "One credential by the id the authenticator sent. A primary-key lookup,
   which is the point of keying the table this way: it runs on every
   assertion, before any account is known."
  [datasource credential-id]
  (row->credential
   (sql/get-by-id datasource :auth_credential credential-id
                  :credential_id store/options)))

(defn by-uuid
  "One credential by its surrogate uuid. The surrogate exists because a
   base64url credential id is an awkward thing to put in a URL or a form
   field, and because it never has to be sent to the browser."
  [datasource credential-uuid]
  (row->credential
   (first (sql/find-by-keys datasource :auth_credential
                            {:credential_uuid (str credential-uuid)}
                            store/options))))

(defn for-account
  "Every credential this account can sign in with, oldest first."
  [datasource account-id]
  (->> (sql/query datasource
                  ["SELECT * FROM auth_credential
                     WHERE account_id = ? ORDER BY created_at ASC"
                   (str account-id)]
                  store/options)
       (mapv row->credential)))

(defn count-for-account
  "How many ways in this account has. What RemoveCredential's guard is
   asking, expressed as a COUNT so removing a key does not have to load
   every other one."
  [datasource account-id]
  (-> (jdbc/execute-one! datasource
                         ["SELECT COUNT(*) AS n FROM auth_credential
                            WHERE account_id = ?" (str account-id)]
                         store/options)
      :n))

;; ------------------------------------------------------------------
;; Writing
;; ------------------------------------------------------------------

(defn register!
  "auth.allium's RegisterCredential. Registers a passkey against an
   account that already exists.

   The uniqueness check spans every account, not just this one, and it is
   enforced by the primary key as well as read here -- so two concurrent
   registrations of the same id cannot both succeed. Reading first is
   what turns the constraint violation into a message a person can read."
  [datasource {:keys [account-id credential-uuid credential-id
                      public-key sign-count label]}
   ^Instant now]
  (let [label (->label label)]
    (cond
      (nil? label)
      (incorrect "Give this passkey a name so you can tell it apart later.")

      (some? (by-credential-id datasource credential-id))
      (incorrect "That passkey is already registered.")

      :else
      (do (sql/insert! datasource :auth_credential
                       {:credential_id credential-id
                        :credential_uuid (str credential-uuid)
                        :account_id (str account-id)
                        :public_key public-key
                        :sign_count sign-count
                        :label label
                        :created_at (store/->millis now)}
                       store/options)
          (by-credential-id datasource credential-id)))))

(defn rename!
  "auth.allium's RenameCredential. The label is the only thing that makes
   one key recognisable among several, so it may not be blanked."
  [datasource credential-uuid label]
  (if-let [label (->label label)]
    (do (sql/update! datasource :auth_credential
                     {:label label}
                     {:credential_uuid (str credential-uuid)}
                     store/options)
        nil)
    (incorrect "A passkey needs a name.")))

(defn record-use!
  "Move a credential's signature counter and last-used stamp after an
   assertion. Called by sessions/sign-in! inside its transaction, never
   on its own -- a counter that moved without a sign-in would mean an
   assertion was accepted and then dropped."
  [conn credential-uuid sign-count ^Instant now]
  (sql/update! conn :auth_credential
               {:sign_count sign-count :last_used_at (store/->millis now)}
               {:credential_uuid (str credential-uuid)}
               store/options)
  nil)

(defn remove!
  "auth.allium's RemoveCredential: remove a passkey and end every session
   on the account.

   Ending every session is blunt on purpose. A key is removed because it
   was lost or stolen, and at that moment the question is not which
   sessions it opened but whether anyone else is still signed in.

   The last key cannot be removed. There is no recovery in this library,
   so an account with no credentials is one nobody can reach. Both the
   count and the delete run in one transaction, or two concurrent removals
   could each see two keys and leave zero."
  [datasource credential-uuid]
  (jdbc/with-transaction [tx datasource]
    (if-let [credential (by-uuid tx credential-uuid)]
      (let [account-id (:account-id credential)]
        (if (<= (count-for-account tx account-id) 1)
          (incorrect "This is your only passkey. Add another one before removing it.")
          (do (sql/delete! tx :auth_credential
                           {:credential_uuid (str credential-uuid)}
                           store/options)
              (sql/delete! tx :auth_session
                           {:account_id (str account-id)}
                           store/options)
              nil)))
      {::anom/category ::anom/not-found
       ::anom/message "That passkey is not registered."})))
