(ns nickdex.grain.push.store
  "The table push.allium's Device entity lives in, and the
   migration that creates it.

   A table rather than the event log, for the same reason credentials
   are. An endpoint and its keys are a CAPABILITY: whoever holds them can
   push to that browser. In an append-only log they would outlive the
   unsubscribe that was supposed to revoke them, and a person who asked
   to be erased could not be. Here, delete deletes.

   Shares the SQLite file the event store already uses, prefixed
   `push_` so it is obvious which tables are not Grain's, and covered by
   the existing backup script without being told about it.

   Timestamps are INTEGER epoch milliseconds, matching grain-auth's
   tables and for the same reason: ISO-8601 text does not compare
   correctly as a string once fractional seconds vary."
  (:require [next.jdbc :as jdbc]
            [next.jdbc.result-set :as rs]))

(def options
  {:builder-fn rs/as-unqualified-kebab-maps})

(def ^:private ddl
  [;; endpoint is the primary key because it IS the subscription's
   ;; identity -- the push service issues it, two devices cannot share
   ;; one, and a browser re-subscribing hands back the one it already
   ;; has. Keying on it is what makes the resubscribe case an UPDATE
   ;; rather than a second row.
   "CREATE TABLE IF NOT EXISTS push_device (
      endpoint    TEXT    PRIMARY KEY,
      device_id   TEXT    NOT NULL UNIQUE,
      user_id  TEXT    NOT NULL,
      public_key  TEXT    NOT NULL,
      auth_secret TEXT    NOT NULL,
      label       TEXT    NOT NULL,
      created_at  INTEGER NOT NULL
    )"
   "CREATE INDEX IF NOT EXISTS push_device_user
      ON push_device (user_id)"])

(defn- column-names [conn]
  (set (map :name (jdbc/execute! conn ["PRAGMA table_info(push_device)"] options))))

(defn migrate!
  "Create the push table if absent, and rename the two columns that were
   originally named after the Web Push JSON. Idempotent.

   The rename is not cosmetic. next.jdbc's kebab builder turns `p256dh`
   into :p-256dh -- it inserts a hyphen at the letter/digit boundary --
   so every read produced a key nothing was looking for, and the
   subscription's public key arrived at the push library as nil. Names
   without digits round-trip; these ones cannot be got wrong the same
   way again.

   account_id -> user_id is the third, and a different kind: this library
   used to call the subscriber an account, and it is a user. A column
   rename is metadata -- SQLite rewrites the schema text and fixes
   dependent indexes without touching a row -- so subscriptions survive
   it. One-way in practice: an older build looking for account_id fails
   on every query once this has run."
  [datasource]
  (with-open [conn (jdbc/get-connection datasource)]
    ;; Renames FIRST, so CREATE TABLE IF NOT EXISTS sees a table that
    ;; already has the columns it would otherwise have created it with.
    (let [columns (column-names conn)]
      (when (and (contains? columns "p256dh") (not (contains? columns "public_key")))
        (jdbc/execute-one! conn ["ALTER TABLE push_device RENAME COLUMN p256dh TO public_key"]))
      (when (and (contains? columns "auth") (not (contains? columns "auth_secret")))
        (jdbc/execute-one! conn ["ALTER TABLE push_device RENAME COLUMN auth TO auth_secret"]))
      (when (and (contains? columns "account_id") (not (contains? columns "user_id")))
        (jdbc/execute-one! conn ["ALTER TABLE push_device RENAME COLUMN account_id TO user_id"])))
    ;; The old index by its old NAME. SQLite rewrites an index to follow a
    ;; renamed column but keeps what it is called, so without this the ddl
    ;; below adds push_device_user beside a surviving push_device_account
    ;; -- two identical indexes on one column.
    (jdbc/execute-one! conn ["DROP INDEX IF EXISTS push_device_account"])
    (run! #(jdbc/execute-one! conn [%]) ddl))
  nil)
