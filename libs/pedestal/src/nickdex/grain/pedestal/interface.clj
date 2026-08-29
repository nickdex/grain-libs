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
   - :cookie-secret must be the STRING, not Biff's #biff/secret wrapper.
     That wrapper's toString is a fixed public constant, so passing it
     through derives the cookie key from something anyone can compute --
     and everything still appears to work. This library now refuses to
     start rather than accept one.
   - ::http/enable-csrf cannot be turned on: Datastar's own posts carry
     no token. SameSite=Lax is what stands in.

   DEPEND ON THIS LIBRARY ALONE. It brings grain-auth and grain-push with
   it. Declaring either of them separately as well gives tools.deps two
   coordinates for one lib and it refuses with \"No known ancestor
   relationship between local versions\".

   ## Config

   One map, built by the application:

     {:datasource        ds          ; a pool on your SQLite file
      :cookie-secret     \"...\"       ; a non-blank string, NOT a Biff delay
      :origin            \"https://example.com\"   ; the relying party
      :app-name          \"Example\"
      :secure?           true        ; false only on plain-HTTP localhost
      :users             {:user-id-for-handle    (fn [handle] ...)
                          :handle-for-user       (fn [user-id] ...)
                          :display-name-for-user (fn [user-id] ...)}
      :paths             {:sign-in \"/signin\" :enrol \"/enrol\"
                          :account \"/account\"}
      :vapid-public-key  \"...\"}     ; omit for an app without push

   `:users` is the seam. This library stores an opaque user id and
   never reads a field on it, so the application owns what a person IS.

   `:paths :account` is the one place the old word survives, and on
   purpose: it names the PAGE where somebody manages their passkeys,
   sessions and devices, which is what every application calls an
   account page. The model underneath is a user; the page is an account
   page. Renaming it would also break bookmarks and the push script's
   :after redirect for no gain.

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
   particular belong on the application's own user model rather than
   on a session, which would go stale the moment one changed."
  (:require [nickdex.grain.auth.interface :as auth]
            [nickdex.grain.pedestal.assets :as assets]
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

;; --- Reading, for a user page ---------------------------------
;;
;; Re-exported so a consuming application needs ONE require as well as
;; one dependency. The routes that change these rows live here, so the
;; reads that render them belong at the same seam -- reaching past this
;; namespace into grain-auth would be depending on something the app
;; never declared.

(def credentials-for-user
  "Every passkey on a user, oldest first. Labels, dates and the
   surrogate uuid the rename and remove routes take -- never the
   credential id or public key."
  auth/credentials-for-user)

(def sessions-for-user
  "Every live session on a user. Pair with `session-of` to mark the
   one being used to read the list."
  auth/sessions-for-user)

(def devices-for-user
  "Every push subscription on a user. Carries a fingerprint of the
   endpoint rather than the endpoint, which is a capability."
  push/for-user)

(def unsubscribe-device!
  "Retire one push subscription, scoped to its user. The operator's
   counterpart to the route a person reaches from their user page."
  push/unsubscribe!)

(def notify!
  "Deliver one message to every device on a user. Returns outcomes
   by count, e.g. {:delivered 2} or {:delivered 1 :gone 1}.

   Takes grain-push's own config -- {:datasource :vapid-public-key
   :vapid-private-key :vapid-subject} -- rather than this library's,
   because the private key should be unwrapped at the point of use and
   not live on a config map that gets passed around and logged.

   Subscriptions the push service reports as gone are retired as a side
   effect. That is what keeps the list from filling with browsers that
   were uninstalled."
  push/send!)

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

(defn user-of
  "The signed-in user id, or nil."
  [ctx]
  (get-in ctx [:grain.pedestal/session :user-id]))

(defn enrolling-user
  "The user an in-flight enrolment names, or nil. For a page that
   wants to greet somebody by name before they have a session."
  [ctx]
  (get ctx :grain.pedestal/enrolling))

;; --- Enrolment ----------------------------------------------------

(def enrolment-code!
  "Mint the six-digit code a new user needs to register its first
   passkey. Returns {:code :expires-at} once, in the clear.

   Takes this library's config, the same map everything else here does.

   Hand it over however you like -- read down a phone, typed into a
   message. It names nothing and can be spoken, which the signed link
   this replaced could not. grain-auth stores only a hash, expires it
   after an hour and burns it after five wrong guesses.

   Refused for a user that already has a passkey, and for one with no
   handle -- a code is entered against a handle, so a user without one
   could never enter it.

   The person enters their handle and the code at your :enrol page,
   which posts them to /enrol/verify."
  auth/issue-enrolment-code!)

(def enrolment-lifetime auth/enrolment-lifetime)

(def revoke-enrolment-code!
  "Revoke an outstanding code. Idempotent."
  auth/clear-enrolment-code!)

(def enrolment-pending?
  "Whether a user has a code that could still be used. For an
   operator listing, not for a decision on the request path."
  auth/enrolment-pending?)

(def reset-credentials!
  "Remove every passkey and session on a user so a fresh code can
   enrol it again -- the way back from losing every device.

   Operator-only by construction: it is on no route, and no code can
   trigger it. It turns a user somebody holds into a user
   whoever gets the next code holds, so it wants a human behind it."
  auth/reset-credentials!)
