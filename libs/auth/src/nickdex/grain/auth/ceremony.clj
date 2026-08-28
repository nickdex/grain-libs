(ns nickdex.grain.auth.ceremony
  "The five steps of a passkey ceremony, joined to the store.

   Deliberately framework-free: every function takes data and returns
   data, so the application mounts them on whatever routes it already
   has. Nothing here knows about ring, Pedestal, sessions or cookies.

   That includes the challenge. Each `begin-` returns a `:pending` string
   the matching `complete-` needs back, and where it lives in between is
   the application's decision -- a signed session cookie is the usual
   answer, and the only requirements are that it survives one round trip
   and that a person cannot choose their own.

   `:pending` is single-use. auth.allium's ChallengeIsSingleUse says why:
   a captured assertion replayed later is the thing standing between an
   intercepted ceremony and an account, so the application must discard
   the stash on completion whether or not the ceremony succeeded."
  (:require [cognitect.anomalies :as anom]
            [nickdex.grain.auth.credentials :as credentials]
            [nickdex.grain.auth.sessions :as sessions]
            [nickdex.grain.auth.webauthn :as webauthn])
  (:import [java.time Instant]))

(defn- forbidden [message]
  {::anom/category ::anom/forbidden ::anom/message message})

;; The one message every failed sign-in gets. auth.allium's
;; RejectionRevealsNothing: a ceremony that did not verify, a credential
;; that is not registered and a counter that did not move must be
;; indistinguishable, or this becomes a way to ask whether an account
;; exists.
(def ^:private sign-in-failed
  "That passkey could not be used to sign in.")

;; ------------------------------------------------------------------
;; Registering a key
;; ------------------------------------------------------------------

(defn begin-registration
  "Start registering a key for an account that already exists. Returns
   {:options-json :pending}.

   The account must be established BEFORE this is called, and by
   something other than this library -- an application with open signup
   creates it first, one with closed signup never offers the step. That
   is also the whole of the authorization decision: whoever may reach
   this may add a key to that account."
  [config {:keys [account-id]}]
  (webauthn/start-registration config {:account-id account-id}))

(defn complete-registration!
  "Verify a registration response and store the credential. Returns the
   credential, or an anomaly.

   The label is the person's, not the authenticator's: nothing in a
   WebAuthn response reliably says what the device is, and a list of keys
   nobody can tell apart is a list nobody will prune."
  [{:keys [datasource] :as config}
   {:keys [pending credential-json account-id label]}
   ^Instant now]
  (if-let [{:keys [credential-id public-key sign-count]}
           (webauthn/verify-registration config {:pending pending
                                                 :credential-json credential-json})]
    (credentials/register! datasource
                           {:account-id account-id
                            :credential-uuid (random-uuid)
                            :credential-id credential-id
                            :public-key public-key
                            :sign-count sign-count
                            :label label}
                           now)
    (forbidden "That passkey could not be registered.")))

(defn complete-registration-and-sign-in!
  "Verify a registration response, store the credential, and open a
   session for it. Returns the session, or an anomaly.

   For enrolment, where the person has no session yet. Making them sign
   in again immediately after proving possession of the authenticator
   that just created the key is a tap that establishes nothing new."
  ([config args now] (complete-registration-and-sign-in! config args now sessions/default-lifetime))
  ([{:keys [datasource] :as config} args ^Instant now lifetime]
   (let [credential (complete-registration! config args now)]
     (if (::anom/category credential)
       credential
       (or (sessions/open! datasource (:credential-uuid credential) now lifetime)
           (forbidden "That passkey could not be registered."))))))

;; ------------------------------------------------------------------
;; Signing in
;; ------------------------------------------------------------------

(defn begin-sign-in
  "Start signing in as a named handle. Returns {:options-json :pending},
   or an anomaly when the handle has no keys.

   This one does reveal whether an account exists, and cannot avoid it:
   the browser needs the list of credential ids to offer. Prefer
   `begin-discoverable-sign-in`, which needs no handle at all and so
   leaks nothing."
  [{:keys [datasource] :as config} {:keys [handle]}]
  (let [account-id ((get-in config [:accounts :account-id-for-handle]) handle)]
    (if (and account-id (seq (credentials/for-account datasource account-id)))
      (webauthn/start-assertion config {:handle handle})
      {::anom/category ::anom/not-found
       ::anom/message "No passkey is registered for that."})))

(defn begin-discoverable-sign-in
  "Start a usernameless sign-in, for conditional-UI autofill. Needs no
   handle, reveals nothing, and is the path to prefer.

   Emits no fact of its own: conditional UI fires on page load, so
   recording something here would count page views rather than sign-in
   attempts."
  [config]
  (webauthn/start-discoverable-assertion config))

(defn complete-sign-in!
  "Verify an assertion and open a session. Returns the session -- with
   the `:session-id` the application puts in its cookie -- or an anomaly.

   Serves both the named and the discoverable path: the assertion
   resolves the account either way, so there is one function and one
   failure message rather than two of each."
  ([config args now] (complete-sign-in! config args now sessions/default-lifetime))
  ([{:keys [datasource] :as config} {:keys [pending credential-json]} ^Instant now lifetime]
   (if-let [{:keys [credential-id sign-count]}
            (webauthn/finish-assertion config {:pending pending
                                               :credential-json credential-json})]
     (if-let [credential (credentials/by-credential-id datasource credential-id)]
       (let [result (sessions/sign-in! datasource
                                       {:session-id (random-uuid)
                                        :credential-uuid (:credential-uuid credential)
                                        :sign-count sign-count}
                                       now lifetime)]
         ;; sign-in! rejects a counter that did not move, which Yubico has
         ;; already checked. Re-message it so a caller cannot tell the two
         ;; layers apart.
         (if (::anom/category result) (forbidden sign-in-failed) result))
       ;; Verified against a credential the store does not have. Reachable
       ;; if a key is removed mid-ceremony.
       (forbidden sign-in-failed))
     (forbidden sign-in-failed))))
