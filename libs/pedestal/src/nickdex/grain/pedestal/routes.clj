(ns nickdex.grain.pedestal.routes
  "Every HTTP endpoint passkeys and push need, as Pedestal routes.

   ON CSRF. Pedestal's ::http/enable-csrf is deliberately not turned on
   alongside these. It demands a token on every POST, and a Datastar
   application's own posts -- /command and /actions, which is most of it
   -- carry none, so switching it on breaks the app rather than
   protecting it. Two things stand in:

   - The session cookie is SameSite=Lax, so a browser does not attach it
     to a cross-site POST at all. That is the defence.
   - The JSON posts here are application/json, which a cross-origin HTML
     form cannot produce; forging them needs a preflight the browser
     refuses.

   The GET endpoints do run on a Lax cookie and each stashes a challenge.
   The worst a cross-site GET achieves is overwriting a pending challenge
   in the visitor's OWN session, failing their next ceremony and nothing
   else.

   ON PATHS. The parameterised routes live under /credential, /device and
   /session -- never beside the static ceremony paths. Pedestal's
   prefix-tree router does not backtrack, so a path-param segment shadows
   every static sibling at the same depth: mounting a
   /passkey/:id/remove once made /passkey/register/options,
   /passkey/signin/options and /passkey/discover/options all 404 at the
   same moment, with no route conflict warning anywhere.

   Every handler returns one refusal for every failure. Saying which step
   went wrong tells whoever asked whether an account exists, whether it
   is enrolled, and whether a key is registered."
  (:require [cheshire.core :as json]
            [io.pedestal.http.body-params :as body-params]
            [nickdex.grain.auth.interface :as auth]
            [nickdex.grain.pedestal.enrolment :as enrolment]
            [nickdex.grain.push.interface :as push])
  (:import [java.time Instant]))

(defn- json-response
  ([status body] (json-response status body nil))
  ([status body session]
   (cond-> {:status status
            :headers {"Content-Type" "application/json"}
            :body (json/generate-string body)}
     session (assoc :session session))))

(defn- refused [] (json-response 403 {:ok false}))
(defn- redirect [to] {:status 303 :headers {"Location" to}})

(defn- account-of [request] (get-in request [:grain.pedestal/session :account-id]))
(defn- anomaly? [x] (some? (:cognitect.anomalies/category x)))

(defn- ceremony-config
  "What grain-auth's ceremony calls need, from this library's config."
  [{:keys [datasource origin app-name accounts]}]
  {:origin origin :app-name app-name :datasource datasource :accounts accounts})

;; ------------------------------------------------------------------
;; Enrolment
;; ------------------------------------------------------------------

(defn- enrol-claim-handler [{:keys [cookie-secret paths] :as config}]
  (fn [request]
    (if-let [account-id (enrolment/account config cookie-secret
                                           (get-in request [:query-params :token])
                                           (Instant/now))]
      (assoc (redirect (:enrol paths))
             :session (assoc (:session request) :grain.pedestal/enrolling account-id))
      (redirect (str (:sign-in paths) "?enrolment=expired")))))

(defn- registering-for
  "The account a registration may act on: the signed-in one, or the one
   an enrolment link named. These are the only two ways a key is ever
   added, and an account id in a request body is never one of them."
  [request]
  (or (account-of request)
      (get-in request [:session :grain.pedestal/enrolling])))

;; ------------------------------------------------------------------
;; Registering a key
;; ------------------------------------------------------------------

(defn- register-options-handler [config]
  (fn [request]
    (if-let [account-id (registering-for request)]
      (let [{:keys [options-json pending]}
            (auth/begin-registration (ceremony-config config) {:account-id account-id})]
        (-> (json-response 200 nil (assoc (:session request)
                                          :grain.pedestal/pending pending))
            (assoc :body options-json)))
      (refused))))

(defn- register-finish-handler
  "Completes a registration, and for an ENROLMENT also opens the session.

   Enrolling used to leave a person with a working passkey and no
   session, so the only way on was to sign in again -- one more tap
   straight after proving possession of the authenticator that had just
   made the key. Adding a second key while already signed in needs
   nothing of the sort, so the two paths differ here and nowhere else."
  [config]
  (fn [request]
    (let [enrolling (get-in request [:session :grain.pedestal/enrolling])
          account-id (registering-for request)
          pending (get-in request [:session :grain.pedestal/pending])
          {:keys [credential label]} (:json-params request)
          args {:pending pending
                :credential-json (json/generate-string credential)
                :account-id account-id
                :label (or label "Passkey")}
          result (when (and account-id pending)
                   (if enrolling
                     (auth/complete-registration-and-sign-in!
                      (ceremony-config config) args (Instant/now))
                     (auth/complete-registration! (ceremony-config config) args (Instant/now))))
          ok? (boolean (and result (not (anomaly? result))))
          ;; The challenge is spent either way. A pending value that
          ;; survives a failed attempt can be answered twice. The
          ;; enrolment grant is spent with it.
          session (dissoc (:session request)
                          :grain.pedestal/pending :grain.pedestal/enrolling)]
      (json-response 200 {:ok ok?}
                     (if (and ok? enrolling)
                       (assoc session :session-id (str (:session-id result)))
                       session)))))

;; ------------------------------------------------------------------
;; Signing in
;; ------------------------------------------------------------------

(defn- signin-options-handler [config]
  (fn [request]
    (let [result (auth/begin-sign-in (ceremony-config config)
                                     {:handle (get-in request [:query-params :handle])})]
      (if (anomaly? result)
        (refused)
        (-> (json-response 200 nil (assoc (:session request)
                                          :grain.pedestal/pending (:pending result)))
            (assoc :body (:options-json result)))))))

(defn- discover-options-handler
  "Usernameless sign-in, for conditional-UI autofill. Records nothing:
   this fires on page load, so a fact here would count page views rather
   than sign-in attempts."
  [config]
  (fn [request]
    (let [{:keys [options-json pending]} (auth/begin-discoverable-sign-in
                                          (ceremony-config config))]
      (-> (json-response 200 nil (assoc (:session request)
                                        :grain.pedestal/pending pending))
          (assoc :body options-json)))))

(defn- signin-finish-handler
  "Serves both the named and the discoverable path -- the assertion
   resolves the account either way, so there is one handler and one
   refusal rather than two of each."
  [config]
  (fn [request]
    (let [pending (get-in request [:session :grain.pedestal/pending])
          result (when pending
                   (auth/complete-sign-in!
                    (ceremony-config config)
                    {:pending pending
                     :credential-json (json/generate-string
                                       (get-in request [:json-params :credential]))}
                    (Instant/now)))
          spent (dissoc (:session request) :grain.pedestal/pending)]
      (if (and result (not (anomaly? result)))
        (json-response 200 {:ok true} (assoc spent :session-id (str (:session-id result))))
        (json-response 200 {:ok false} spent)))))

(defn- signout-handler [{:keys [datasource paths]}]
  (fn [request]
    (when-let [session (:grain.pedestal/session request)]
      (auth/sign-out! datasource (:session-id session) (:account-id session)))
    ;; Cleared whether or not the row was there. A cookie naming a
    ;; session that no longer exists is not a session, and leaving it
    ;; means every later request pays for the lookup that says so.
    (assoc (redirect (:sign-in paths))
           :session (dissoc (:session request) :session-id))))

;; ------------------------------------------------------------------
;; Managing keys, sessions and devices
;;
;; Plain form posts, not Grain commands: credentials, sessions and push
;; subscriptions are table rows, so there is no event for Datastar to
;; re-render from. Each redirects back and the reload is the update.
;;
;; Ownership is checked here AND inside the libraries, which scope by
;; account in the SQL itself. Neither is redundant: this turns somebody
;; else's id into a redirect rather than a 500, and that means a mistake
;; here still cannot touch another account's row.
;; ------------------------------------------------------------------

(defn- remove-credential-handler [{:keys [datasource paths]}]
  (fn [request]
    (when-let [account-id (account-of request)]
      (when-let [uuid (some-> (get-in request [:path-params :credential-uuid]) str parse-uuid)]
        (when (= account-id (:account-id (auth/credential-by-uuid datasource uuid)))
          (auth/remove-credential! datasource uuid))))
    ;; The same redirect whether it worked, was refused as the last key,
    ;; or named somebody else's. The page that reloads shows what is
    ;; actually there.
    (redirect (:account paths))))

(defn- rename-credential-handler [{:keys [datasource paths]}]
  (fn [request]
    (when-let [account-id (account-of request)]
      (when-let [uuid (some-> (get-in request [:path-params :credential-uuid]) str parse-uuid)]
        (when (= account-id (:account-id (auth/credential-by-uuid datasource uuid)))
          (auth/rename-credential! datasource uuid (get-in request [:form-params :label])))))
    (redirect (:account paths))))

(defn- end-session-handler [{:keys [datasource paths]}]
  (fn [request]
    (let [account-id (account-of request)
          target (some-> (get-in request [:path-params :session-id]) str parse-uuid)
          current? (= target (get-in request [:grain.pedestal/session :session-id]))]
      (when (and account-id target)
        (auth/sign-out! datasource target account-id))
      (if current?
        (assoc (redirect (:sign-in paths))
               :session (dissoc (:session request) :session-id))
        (redirect (:account paths))))))

;; ------------------------------------------------------------------
;; Push
;; ------------------------------------------------------------------

(defn- push-key-handler
  "The VAPID public key the browser needs as applicationServerKey.

   Public by design -- it is handed to every subscriber and identifies
   the server rather than authenticating anyone. Better a 503 than a 200
   with an empty key, which fails later in the browser with an opaque
   encoding error."
  [{:keys [vapid-public-key]}]
  (fn [_request]
    (if (seq (str vapid-public-key))
      (json-response 200 {:publicKey vapid-public-key})
      (json-response 503 {:error "push-not-configured"}))))

(defn- subscribe-handler [{:keys [datasource]}]
  (fn [request]
    (if-let [account-id (account-of request)]
      (let [{:keys [endpoint p256dh auth label]} (:json-params request)
            result (push/subscribe! datasource
                                    {:account-id account-id
                                     :endpoint endpoint
                                     ;; The browser sends the Web Push
                                     ;; names; the table uses digit-free
                                     ;; ones that survive kebab-casing.
                                     :public-key p256dh
                                     :auth-secret auth
                                     :label label}
                                    (Instant/now))]
        (json-response 200 {:ok (not (anomaly? result))}))
      (json-response 403 {:ok false}))))

(defn- rename-device-handler [{:keys [datasource paths]}]
  (fn [request]
    (when-let [account-id (account-of request)]
      (when-let [device-id (some-> (get-in request [:path-params :device-id]) str parse-uuid)]
        (when (= account-id (:account-id (push/by-id datasource device-id)))
          (push/rename! datasource device-id (get-in request [:form-params :label])))))
    (redirect (:account paths))))

(defn- unsubscribe-handler [{:keys [datasource paths]}]
  (fn [request]
    (when-let [account-id (account-of request)]
      (when-let [device-id (some-> (get-in request [:path-params :device-id]) str parse-uuid)]
        (push/unsubscribe! datasource device-id account-id)))
    (redirect (:account paths))))

;; ------------------------------------------------------------------
;; Wiring
;; ------------------------------------------------------------------

(defn routes
  "Every passkey and push endpoint, as a Pedestal route set.

   Union this with the application's own routes, then run the whole thing
   through `session/with-session`."
  [config]
  (let [json-body (body-params/body-params)]
    #{["/enrol/claim" :get [(enrol-claim-handler config)] :route-name ::enrol-claim]

      ["/passkey/register/options" :get [(register-options-handler config)]
       :route-name ::register-options]
      ["/passkey/register/finish" :post [json-body (register-finish-handler config)]
       :route-name ::register-finish]
      ["/passkey/signin/options" :get [(signin-options-handler config)]
       :route-name ::signin-options]
      ["/passkey/signin/finish" :post [json-body (signin-finish-handler config)]
       :route-name ::signin-finish]
      ["/passkey/discover/options" :get [(discover-options-handler config)]
       :route-name ::discover-options]
      ["/passkey/signout" :post [(signout-handler config)] :route-name ::signout]

      ["/credential/:credential-uuid/remove" :post [(remove-credential-handler config)]
       :route-name ::remove-credential]
      ["/credential/:credential-uuid/rename" :post [json-body (rename-credential-handler config)]
       :route-name ::rename-credential]
      ["/session/:session-id/signout" :post [(end-session-handler config)]
       :route-name ::end-session]

      ["/push/key" :get [(push-key-handler config)] :route-name ::push-key]
      ["/push/subscribe" :post [json-body (subscribe-handler config)]
       :route-name ::push-subscribe]
      ["/device/:device-id/rename" :post [json-body (rename-device-handler config)]
       :route-name ::rename-device]
      ["/device/:device-id/unsubscribe" :post [(unsubscribe-handler config)]
       :route-name ::unsubscribe-device]}))
