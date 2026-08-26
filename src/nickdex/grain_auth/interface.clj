(ns nickdex.grain-auth.interface
  "Passkey authentication for a Grain + Datastar application. Behaviour is
   specified in auth.allium; this is its public surface.

   Credentials and sessions are TABLES, not Grain blocks. Auth is
   infrastructure rather than a service area: nothing here is a decision
   worth replaying, the workload is point lookups by credential id, and a
   person who asks to be erased has to actually disappear -- which an
   append-only log cannot do. The consuming application's own domain
   stays event-sourced; see identity.allium in smriti for the account
   these credentials point at.

   One consequence is worth naming, because it is a security property and
   not an accident: none of these functions is a Grain command, so none
   of them is reachable through the command-request-handler, which routes
   every registered command over HTTP. `sign-in!` cannot be invoked by
   POSTing a credential id. The only caller is the ceremony handler, and
   the only way to reach that is to present an assertion that verifies.

   Every function takes `now` explicitly rather than reading the clock,
   so a test can pin it and one request cannot hold two notions of the
   current instant.

   Wiring, once per application start:

     (auth/migrate! datasource)

   where `datasource` is a pool on the same SQLite file the event store
   uses. Tables are prefixed `auth_`, so an existing backup script covers
   them without being told about them."
  (:require [nickdex.grain-auth.credentials :as credentials]
            [nickdex.grain-auth.sessions :as sessions]
            [nickdex.grain-auth.store :as store]))

;; --- Schema -------------------------------------------------------

(defn migrate!
  "Create the auth tables if absent. Idempotent; call it on every start."
  [datasource]
  (store/migrate! datasource))

;; --- Credentials --------------------------------------------------

(def register-credential!
  "Register a passkey against an account that already exists. Returns the
   credential, or an anomaly when the label is blank or the credential id
   is already known to some account."
  credentials/register!)

(def credential-by-id
  "One credential by the id an authenticator sent. The lookup every
   assertion makes, before any account is known."
  credentials/by-credential-id)

(def credential-by-uuid
  "One credential by its surrogate uuid -- the form safe to put in a URL."
  credentials/by-uuid)

(def credentials-for-account
  "Every credential this account can sign in with, oldest first."
  credentials/for-account)

(def rename-credential!
  "Replace a passkey's label. Returns an anomaly when the label is blank."
  credentials/rename!)

(def remove-credential!
  "Remove a passkey and end every session on the account. Returns an
   anomaly on the last remaining key: there is no recovery here, so an
   account with no credentials is one nobody can reach."
  credentials/remove!)

;; --- Sessions -----------------------------------------------------

(def sign-in!
  "Open a session for a credential whose assertion has ALREADY been
   verified. Does not check a signature; must never be reachable from a
   request that has not. Returns an anomaly when the credential is
   unknown or its signature counter did not rise."
  sessions/sign-in!)

(def session
  "The session behind a request, or nil when it has ended or run out."
  sessions/active)

(def sessions-for-account
  "Sessions that have not ended or run out, most recent first."
  sessions/for-account)

(def sign-out!
  "End one session, here or on another device. Scoped to the caller's own
   account, so a session id alone cannot end somebody else's."
  sessions/sign-out!)

(def sign-out-account!
  "End every session on an account."
  sessions/sign-out-account!)

(def purge-expired-sessions!
  "Reclaim rows for sessions that have run out. Changes no answer -- every
   read already excludes them -- so it may run whenever, or never."
  sessions/purge-expired!)

(def default-session-lifetime
  "auth.allium's config.session_lifetime, absolute from the sign-in."
  sessions/default-lifetime)
