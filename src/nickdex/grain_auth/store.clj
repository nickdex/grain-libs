(ns nickdex.grain-auth.store
  "The two tables auth.allium's Credential and Session entities live in,
   and the migration that creates them.

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
   ;; nothing else, so the account follows from this lookup rather than
   ;; preceding it. It is unique across every account by construction --
   ;; a collision is the same key claimed twice, not two people picking
   ;; the same name.
   "CREATE TABLE IF NOT EXISTS auth_credential (
      credential_id    TEXT    PRIMARY KEY,
      credential_uuid  TEXT    NOT NULL UNIQUE,
      account_id       TEXT    NOT NULL,
      public_key       TEXT    NOT NULL,
      sign_count       INTEGER NOT NULL,
      label            TEXT    NOT NULL,
      created_at       INTEGER NOT NULL,
      last_used_at     INTEGER
    )"
   "CREATE INDEX IF NOT EXISTS auth_credential_account
      ON auth_credential (account_id)"

   "CREATE TABLE IF NOT EXISTS auth_session (
      session_id    TEXT    PRIMARY KEY,
      account_id    TEXT    NOT NULL,
      started_at    INTEGER NOT NULL,
      last_seen_at  INTEGER NOT NULL,
      expires_at    INTEGER NOT NULL
    )"
   "CREATE INDEX IF NOT EXISTS auth_session_account
      ON auth_session (account_id)"
   ;; Sweeping expired sessions is a range scan over this.
   "CREATE INDEX IF NOT EXISTS auth_session_expires
      ON auth_session (expires_at)"])

(defn migrate!
  "Create the auth tables if they are absent. Idempotent, so a consuming
   application calls it on every start rather than tracking whether it
   has run.

   This is the whole migration story today, and it only stretches as far
   as adding tables and columns. There is no bump-the-version-and-replay
   escape hatch here the way there is for a Grain read model: a change
   that rewrites existing rows needs a real migration, written by hand,
   before it ships."
  [datasource]
  (with-open [conn (jdbc/get-connection datasource)]
    (run! #(jdbc/execute-one! conn [%]) ddl))
  nil)
