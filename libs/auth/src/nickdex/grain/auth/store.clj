(ns nickdex.grain.auth.store
  "The tables auth.allium's Credential and Session entities live in, the
   enrolment code that puts the first Credential on a user, and the
   migration that creates them.

   These are meant to share a consuming application's existing SQLite
   file rather than open one of their own. Grain's event store sets
   journal_mode=WAL, which persists at the database level, so a second
   pool on the same file is one writer and many readers in the same
   process -- and the application's existing backup script covers these
   tables without being told about them. Every table is prefixed `auth_`
   so it is obvious which of them are not Grain's.

   Timestamps are INTEGER epoch milliseconds, not ISO-8601 text. Text
   looks friendlier in a sqlite3 shell and is a trap: Instant/toString
   omits trailing zeros, so \"2026-08-26T09:00Z\" and
   \"2026-08-26T09:00:00.123Z\" do not compare correctly as strings, and
   `expires_at > ?` silently returns the wrong rows for any timestamp
   that lands on a whole second. Integers sort the way time does."
  (:require [next.jdbc :as jdbc]
            [next.jdbc.result-set :as rs])
  (:import [java.time Instant]))

(def options
  "Unqualified kebab-case keys, so a row reads like the rest of the
   codebase (:credential-id) rather than like the table it came from
   (:auth_credential/credential_id)."
  {:builder-fn rs/as-unqualified-kebab-maps})

(defn ->millis ^long [^Instant instant] (.toEpochMilli instant))
(defn <-millis ^Instant [millis] (when millis (Instant/ofEpochMilli (long millis))))

(def ^:private ddl
  [;; credential_id is the primary key because it is what every
   ;; assertion arrives holding: the authenticator sends its id and
   ;; nothing else, so the user follows from this lookup rather than
   ;; preceding it. It is unique across every user by construction --
   ;; a collision is the same key claimed twice, not two people picking
   ;; the same name.
   "CREATE TABLE IF NOT EXISTS auth_credential (
      credential_id    TEXT    PRIMARY KEY,
      credential_uuid  TEXT    NOT NULL UNIQUE,
      user_id          TEXT    NOT NULL,
      public_key       TEXT    NOT NULL,
      sign_count       INTEGER NOT NULL,
      label            TEXT    NOT NULL,
      created_at       INTEGER NOT NULL,
      last_used_at     INTEGER
    )"
   "CREATE INDEX IF NOT EXISTS auth_credential_user
      ON auth_credential (user_id)"

   "CREATE TABLE IF NOT EXISTS auth_session (
      session_id    TEXT    PRIMARY KEY,
      user_id       TEXT    NOT NULL,
      started_at    INTEGER NOT NULL,
      last_seen_at  INTEGER NOT NULL,
      expires_at    INTEGER NOT NULL
    )"
   "CREATE INDEX IF NOT EXISTS auth_session_user
      ON auth_session (user_id)"
   ;; Sweeping expired sessions is a range scan over this.
   "CREATE INDEX IF NOT EXISTS auth_session_expires
      ON auth_session (expires_at)"

   ;; The six-digit code that lets a brand-new user register its first
   ;; passkey. user_id is the primary key, so issuing a second code
   ;; REPLACES the first: one live code per user, and nothing left to
   ;; sweep when one goes unused.
   ;;
   ;; expires_at is stored rather than derived from a lifetime at read
   ;; time. A code already in somebody's hands must not have its life
   ;; extended -- or cut short -- by a later config change.
   ;;
   ;; Only the hash is kept. See enrolment.clj for what that is, and is
   ;; not, worth against six digits.
   "CREATE TABLE IF NOT EXISTS auth_enrolment_code (
      user_id         TEXT    PRIMARY KEY,
      code_hash       TEXT    NOT NULL,
      expires_at      INTEGER NOT NULL,
      failed_attempts INTEGER NOT NULL
    )"])

(defn- column-names [conn table]
  (set (map :name (jdbc/execute! conn [(str "PRAGMA table_info(" table ")")] options))))

(def ^:private renamed-to-user
  "The tables that carried account_id before the library settled on
   `user`. See the rename note in migrate!."
  ["auth_credential" "auth_session" "auth_enrolment_code"])

(defn migrate!
  "Create the auth tables if they are absent, and rename account_id to
   user_id on any that predate the rename. Idempotent, so a consuming
   application calls it on every start rather than tracking whether it
   has run.

   THE RENAME. This library used to call the thing holding credentials an
   account. It is a user: a human exists first and may acquire a way to
   sign in, rather than the credentials bringing the person into being.
   The word now matches, all the way down to the column.

   ALTER TABLE ... RENAME COLUMN is metadata only -- SQLite rewrites the
   schema text and fixes dependent indexes, and does not touch a row. So
   existing passkeys keep working: a credential binds to the relying
   party, the credential id and the public key, and a resident key's user
   handle is derived from the user's uuid, which is a VALUE and does not
   change here.

   Guarded both ways, so it runs on every start and can be re-run: rename
   only where the old column is present and the new one is not.

   One-way in practice. Once user_id exists, an older build looking for
   account_id fails on every auth query -- rolling back the image means
   rolling back the schema too.

   Beyond adding tables and columns this is the whole migration story:
   there is no bump-the-version-and-replay escape hatch here the way
   there is for a Grain read model, so anything that rewrites rows needs a
   migration written by hand before it ships."
  [datasource]
  (with-open [conn (jdbc/get-connection datasource)]
    (doseq [table renamed-to-user]
      (let [columns (column-names conn table)]
        (when (and (contains? columns "account_id") (not (contains? columns "user_id")))
          (jdbc/execute-one!
           conn [(str "ALTER TABLE " table " RENAME COLUMN account_id TO user_id")]))))
    ;; The old indexes by their old NAMES. SQLite rewrites an index to
    ;; follow a renamed column but keeps what it is called, so without
    ;; this the ddl below adds auth_credential_user beside a surviving
    ;; auth_credential_account -- two identical indexes on one column,
    ;; paid for on every insert. Observed on a real database, not
    ;; imagined.
    (doseq [index ["auth_credential_account" "auth_session_account"]]
      (jdbc/execute-one! conn [(str "DROP INDEX IF EXISTS " index)]))
    ;; After the rename, so CREATE TABLE IF NOT EXISTS sees a table that
    ;; already has the column it would otherwise have created it with.
    (run! #(jdbc/execute-one! conn [%]) ddl))
  nil)
