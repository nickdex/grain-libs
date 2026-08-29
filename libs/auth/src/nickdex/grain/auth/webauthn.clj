(ns nickdex.grain.auth.webauthn
  "WebAuthn ceremony mechanics, via com.yubico/webauthn-server-core.

   Verification only. Every function here returns plain data and persists
   nothing -- deciding what to write is nickdex.grain.auth.ceremony's
   job. `credential-repository` is the exception that has to read, and it
   cannot move up a layer: Yubico's RelyingParty calls its methods
   synchronously from inside its own ceremony logic.

   Nothing here parses CBOR or checks a signature by hand. auth.allium's
   Authenticator contract says why: this is a solved problem with a lot
   of ways to get it subtly and silently wrong.

   The `config` every function takes:

     {:origin      \"https://example.com\"   ; scheme + host (+ port)
      :app-name    \"Example\"                ; shown by the authenticator
      :datasource  ds
      :accounts    {:account-id-for-handle    (fn [handle] ...)
                    :handle-for-account       (fn [account-id] ...)
                    :display-name-for-account (fn [account-id] ...)}}

   `handle` is WebAuthn's `user.name` -- whatever your application calls
   people by when an authenticator asks. An email works; so does a
   username. This library never interprets it.

   :display-name-for-account is optional and falls back to the handle.
   The two differ for a reason: an authenticator shows the display name
   to a person choosing between keys, so \"Nikhil Warke\" belongs there
   and an email address belongs in the handle."
  (:require [cheshire.core :as json]
            [com.brunobonacci.mulog :as u]
            [nickdex.grain.auth.credentials :as credentials])
  (:import [com.yubico.webauthn AssertionRequest CredentialRepository
            FinishAssertionOptions FinishRegistrationOptions
            RegisteredCredential RelyingParty StartAssertionOptions
            StartRegistrationOptions]
           [com.yubico.webauthn.data AuthenticatorSelectionCriteria ByteArray
            PublicKeyCredential PublicKeyCredentialCreationOptions
            PublicKeyCredentialDescriptor RelyingPartyIdentity
            ResidentKeyRequirement UserIdentity]
           [java.net URI]
           [java.nio ByteBuffer]
           [java.util Optional UUID]))

;; ------------------------------------------------------------------
;; User handles
;; ------------------------------------------------------------------

(defn uuid->handle-bytes
  "Packs an account id into the 16 bytes WebAuthn carries as a user
   handle. Deterministic, so the handle never has to be stored or looked
   up -- it IS the account id, in the shape the spec wants."
  ^bytes [^UUID uuid]
  (-> (ByteBuffer/allocate 16)
      (.putLong (.getMostSignificantBits uuid))
      (.putLong (.getLeastSignificantBits uuid))
      .array))

(defn handle-bytes->uuid ^UUID [^bytes bs]
  (let [buf (ByteBuffer/wrap bs)]
    (UUID. (.getLong buf) (.getLong buf))))

(defn- ->registered-credential [{:keys [credential-id public-key sign-count account-id]}]
  (-> (RegisteredCredential/builder)
      (.credentialId (ByteArray/fromBase64Url credential-id))
      (.userHandle (ByteArray. (uuid->handle-bytes account-id)))
      (.publicKeyCose (ByteArray/fromBase64Url public-key))
      (.signatureCount (long sign-count))
      .build))

(defn- display-name [{{:keys [handle-for-account display-name-for-account]} :accounts} account-id]
  (or (when display-name-for-account (display-name-for-account account-id))
      (handle-for-account account-id)))

;; ------------------------------------------------------------------
;; The repository Yubico calls into during every ceremony
;; ------------------------------------------------------------------

(defn- credential-repository
  [{:keys [datasource] {:keys [account-id-for-handle handle-for-account]} :accounts}]
  (reify CredentialRepository
    (getCredentialIdsForUsername [_ handle]
      (if-some [account-id (account-id-for-handle handle)]
        (into #{}
              (map (fn [{:keys [credential-id]}]
                     (-> (PublicKeyCredentialDescriptor/builder)
                         (.id (ByteArray/fromBase64Url credential-id))
                         .build)))
              (credentials/for-account datasource account-id))
        #{}))

    (getUserHandleForUsername [_ handle]
      (if-some [account-id (account-id-for-handle handle)]
        (Optional/of (ByteArray. (uuid->handle-bytes account-id)))
        (Optional/empty)))

    (getUsernameForUserHandle [_ user-handle]
      (let [account-id (handle-bytes->uuid (.getBytes ^ByteArray user-handle))]
        (if-some [handle (handle-for-account account-id)]
          (Optional/of handle)
          (Optional/empty))))

    (lookup [_ credential-id _user-handle]
      (if-some [row (credentials/by-credential-id
                     datasource (.getBase64Url ^ByteArray credential-id))]
        (Optional/of (->registered-credential row))
        (Optional/empty)))

    (lookupAll [_ credential-id]
      (if-some [row (credentials/by-credential-id
                     datasource (.getBase64Url ^ByteArray credential-id))]
        #{(->registered-credential row)}
        #{}))))

(defn normalise-origin
  "An origin in the exact shape a browser reports one: scheme://host,
   plus the port when it is not the default.

   A configured base URL is a URL, and URLs pick up trailing slashes and
   paths without anyone thinking about it. A browser's clientData origin
   never has either, and Yubico compares the two as STRINGS unless
   subdomain or port matching is switched on -- so a configured
   \"https://example.com:8080/\" matches the browser's
   \"https://example.com:8080\" not at all. Registration then fails at the
   finish step, after the person has already touched their authenticator,
   with a message that names nothing.

   Verified against com.yubico.webauthn.OriginMatcher/isAllowed: with the
   trailing slash it answers false, without it true."
  ^String [origin]
  (let [u (URI. (str origin))
        port (.getPort u)]
    (str (.getScheme u) "://" (.getHost u)
         (when (pos? port) (str ":" port)))))

(defn relying-party
  "The Yubico RelyingParty every ceremony call runs through.

   Not private, so a test can ask what origins it actually ended up
   holding. Everything public is in interface.clj; this namespace is
   internal either way."
  [{:keys [origin app-name] :as config}]
  (-> (RelyingParty/builder)
      (.identity (-> (RelyingPartyIdentity/builder)
                     ;; The RP id is the host alone. A scheme or port here
                     ;; makes every ceremony fail with an origin mismatch
                     ;; that names neither.
                     (.id (.getHost (URI. origin)))
                     (.name (or app-name "app"))
                     .build))
      (.credentialRepository (credential-repository config))
      (.origins #{(normalise-origin origin)})
      .build))

;; ------------------------------------------------------------------
;; Registration
;; ------------------------------------------------------------------

(defn start-registration
  "Begin registering a key for an account that already exists. Returns
   {:options-json :pending}: send the first to the browser, keep the
   second until the response comes back.

   Both are the same string. The browser's
   parseCreationOptionsFromJSON wants .toJson(), not the
   {\"publicKey\": ...} wrapper that .toCredentialsCreateJson() adds --
   passing the wrapper produces a browser-side parse error that reads
   like a malformed challenge.

   residentKey is REQUIRED, which makes every credential discoverable.
   Without it `start-discoverable-assertion` finds nothing and
   usernameless sign-in silently does not work. The cost is that older
   USB keys with little resident storage may refuse to register where
   PREFERRED would have succeeded."
  [config {:keys [account-id]}]
  (let [handle ((get-in config [:accounts :handle-for-account]) account-id)
        user (-> (UserIdentity/builder)
                 (.name handle)
                 (.displayName (display-name config account-id))
                 (.id (ByteArray. (uuid->handle-bytes account-id)))
                 .build)
        json (.toJson
              (.startRegistration
               (relying-party config)
               (-> (StartRegistrationOptions/builder)
                   (.user user)
                   (.authenticatorSelection
                    (-> (AuthenticatorSelectionCriteria/builder)
                        (.residentKey ResidentKeyRequirement/REQUIRED)
                        .build))
                   .build)))]
    {:options-json json :pending json}))

(defn verify-registration
  "Verify a registration response. Returns
   {:credential-id :public-key :sign-count} when the ceremony holds, and
   nil when it does not. Never throws, never writes.

   nil covers every way this can fail -- a tampered response, a challenge
   that does not match, an origin that does not match. The caller reports
   one failure for all of them, because distinguishing them tells an
   attacker which part they got wrong."
  [config {:keys [pending credential-json]}]
  (try
    (let [result (.finishRegistration
                  (relying-party config)
                  (-> (FinishRegistrationOptions/builder)
                      (.request (PublicKeyCredentialCreationOptions/fromJson pending))
                      (.response (PublicKeyCredential/parseRegistrationResponseJson
                                  credential-json))
                      .build))]
      {:credential-id (.getBase64Url (.getId (.getKeyId result)))
       :public-key    (.getBase64Url (.getPublicKeyCose result))
       :sign-count    (.getSignatureCount result)})
    (catch Exception e
      ;; Uniform to the CALLER, specific in the LOG. The browser must not
      ;; learn which check failed; the operator has to. Yubico's message
      ;; names it exactly -- "Incorrect origin", "Incorrect challenge" --
      ;; and swallowing that made a misconfigured base URL a failure with
      ;; no evidence anywhere. The configured origin is logged beside it,
      ;; because the whole question is which two strings disagree.
      (u/log ::registration-failed
             :reason (ex-message e)
             :configured-origin (normalise-origin (:origin config)))
      nil)))

;; ------------------------------------------------------------------
;; Assertion (sign-in)
;; ------------------------------------------------------------------

(defn- assertion->pair
  "Yubico's AssertionRequest JSON carries more than the browser needs.
   finish-assertion wants the whole thing; the browser wants only the
   inner publicKeyCredentialRequestOptions. Registration does not have
   this split, which is why the two ceremonies look asymmetric."
  [^AssertionRequest req]
  (let [request-json (.toJson req)]
    {:options-json (-> request-json
                       (json/parse-string true)
                       :publicKeyCredentialRequestOptions
                       json/generate-string)
     :pending request-json}))

(defn start-assertion
  "Begin signing in as a named handle."
  [config {:keys [handle]}]
  (assertion->pair
   (.startAssertion (relying-party config)
                    (-> (StartAssertionOptions/builder) (.username handle) .build))))

(defn start-discoverable-assertion
  "The usernameless counterpart, for conditional-UI autofill. Omitting
   the username leaves allowCredentials and username out of the request,
   which is what tells the browser to offer any resident credential for
   this relying party.

   `finish-assertion` handles the result unchanged -- it resolves the
   account from the response's user handle either way."
  [config]
  (assertion->pair
   (.startAssertion (relying-party config) (-> (StartAssertionOptions/builder) .build))))

(defn finish-assertion
  "Verify an assertion. Returns {:handle :credential-id :sign-count} when
   it holds, nil when it does not -- including on a signature-counter
   regression, which is a sign-in failure like any other and must not be
   reported as something more specific.

   The counter is returned, not written. sessions/sign-in! records it,
   inside the transaction that also opens the session, so a counter
   cannot advance for a sign-in that did not happen.

   Yubico checks the counter here and sessions/sign-in! checks it again.
   That is deliberate: this path is the one an authenticator reaches, and
   that one guards every other caller."
  [config {:keys [pending credential-json]}]
  (try
    (let [result (.finishAssertion
                  (relying-party config)
                  (-> (FinishAssertionOptions/builder)
                      (.request (AssertionRequest/fromJson pending))
                      (.response (PublicKeyCredential/parseAssertionResponseJson
                                  credential-json))
                      .build))]
      (when (and (.isSuccess result) (.isSignatureCounterValid result))
        {:handle        (.getUsername result)
         :credential-id (.getBase64Url (.getCredentialId result))
         :sign-count    (.getSignatureCount result)}))
    (catch Exception e
      (u/log ::assertion-failed
             :reason (ex-message e)
             :configured-origin (normalise-origin (:origin config)))
      nil)))
