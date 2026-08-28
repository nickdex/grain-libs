(ns nickdex.grain.pedestal.interface
  "Passkeys and Web Push wired into a Grain + Datastar + Pedestal
   application.

   grain-auth and grain-push are framework-free by design: they take data
   and return data, so an application mounts them however it likes. This
   library is the however -- the wiring both applications on this stack
   would otherwise copy, including the parts that are only obvious after
   getting them wrong:

   - The ceremony script must load from <head>. A Datastar page's body
     arrives as an SSE patch applied by DOM morphing, and a <script>
     element inserted that way never executes.
   - Path-param routes must not sit beside the static ceremony paths.
     Pedestal's prefix-tree router does not backtrack, so one param
     segment 404s every static sibling at once, silently.
   - The session cookie needs a max-age. Without one iOS drops it
     whenever it terminates the app, and every return mints a new
     session while the old row lives on.
   - ::http/enable-csrf cannot be turned on: Datastar's own posts carry
     no token. SameSite=Lax is what stands in.

   DEPEND ON THIS LIBRARY ALONE. It brings grain-auth and grain-push with
   it. Declaring either of them separately as well gives tools.deps two
   coordinates for one lib and it refuses with \"No known ancestor
   relationship between local versions\".

   ## Config

   One map, built by the application:

     {:datasource        ds          ; a pool on your SQLite file
      :cookie-secret     \"...\"       ; also derives the enrolment key
      :origin            \"https://example.com\"   ; the relying party
      :app-name          \"Example\"
      :secure?           true        ; false only on plain-HTTP localhost
      :accounts          {:account-id-for-handle    (fn [handle] ...)
                          :handle-for-account       (fn [account-id] ...)
                          :display-name-for-account (fn [account-id] ...)}
      :paths             {:sign-in \"/signin\" :enrol \"/enrol\"
                          :account \"/account\"}
      :vapid-public-key  \"...\"}     ; omit for an app without push

   `:accounts` is the seam. This library stores an opaque account id and
   never reads a field on it, so the application owns what a person IS.

   ## Wiring

     (auth/migrate! ds)
     (push/migrate! ds)

     ::http/enable-session (glue/session-config config)
     ::http/routes (glue/with-session config
                     (set/union (glue/routes config)
                                (glue/asset-routes config)
                                your-own-routes))

   and put `(glue/head-scripts config)` in your Datastar shim's <head>.

   ## What it does not own

   Authorization. `signed-in?` answers whether somebody is signed in and
   stops there. Whether they may touch a row, or hold a role, is the
   application's question and does not generalise -- and roles in
   particular belong on the application's own account model rather than
   on a session, which would go stale the moment one changed."
  (:require [nickdex.grain.auth.interface :as auth]
            [nickdex.grain.pedestal.assets :as assets]
            [nickdex.grain.pedestal.enrolment :as enrolment]
            [nickdex.grain.pedestal.routes :as routes]
            [nickdex.grain.pedestal.session :as session]
            [nickdex.grain.push.interface :as push]))

;; --- Schema -------------------------------------------------------

(defn migrate!
  "Create every table both libraries need. Idempotent; call on start."
  [datasource]
  (auth/migrate! datasource)
  (push/migrate! datasource))

;; --- Wiring -------------------------------------------------------

(def session-config
  "What to put under Pedestal's ::http/enable-session."
  session/session-config)

(def interceptor
  "Resolves the session and puts it where commands, queries and SSE all
   read from. Usually reached via `with-session` rather than directly."
  session/interceptor)

(defn with-session
  "Prepend the session interceptor to every route in a set. It has to be
   EVERY route: an :authorized? predicate reads the session from the
   context, so a route that skips this is one where every predicate sees
   nobody signed in."
  [config routes]
  (session/with-session (session/interceptor config) routes))

(def routes
  "Every passkey and push endpoint, as a Pedestal route set."
  routes/routes)

(def asset-routes
  "The browser-side scripts: /passkey.js, /push.js and a composed
   /sw.js."
  assets/routes)

(def head-scripts
  "Hiccup <script> tags for the Datastar shim's <head>, content-stamped.
   Called on every page render, so the scripts behind it are memoised."
  assets/head-scripts)

(def asset-path
  "Stamp one of your OWN static resources so a changed file arrives under
   a changed URL -- the same invalidation the generated scripts get.
   Without it a service worker serves a stale stylesheet forever."
  assets/asset-path)

;; --- Predicates ---------------------------------------------------

(def signed-in?
  "Identity, not authorization: whether somebody is signed in. Fails
   closed, because Grain refuses anything whose :authorized? does not
   return literal true."
  session/signed-in?)

(def gate
  "What a Datastar page needs alongside :authorized?, so a signed-out
   visitor is redirected rather than served a shim that never
   populates."
  session/gate)

(defn session-of
  "The session on a Grain command or query context, or nil."
  [ctx]
  (get ctx :grain.pedestal/session))

(defn account-of
  "The signed-in account id, or nil."
  [ctx]
  (get-in ctx [:grain.pedestal/session :account-id]))

(defn enrolling-account
  "The account an in-flight enrolment names, or nil. For a page that
   wants to greet somebody by name before they have a session."
  [ctx]
  (get ctx :grain.pedestal/enrolling))

;; --- Enrolment ----------------------------------------------------

(def enrolment-token
  "A one-shot link letting a new account register its first passkey.

   A BEARER CREDENTIAL for its lifetime: whoever opens it can put their
   key on that account, with no second factor behind it. Send it over
   something you trust. It stops working the moment the account has a
   key, so the person using it closes the window themselves."
  enrolment/token)

(def enrolment-lifetime enrolment/default-lifetime)
