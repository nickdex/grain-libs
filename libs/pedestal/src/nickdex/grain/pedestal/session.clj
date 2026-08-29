(ns nickdex.grain.pedestal.session
  "Who is asking: the cookie that carries a session id, the interceptor
   that resolves it, and the predicates everything else gates on.

   The cookie holds a session ID and nothing else. The session itself is
   a row grain-auth owns, so a person cannot name somebody else's by
   editing a cookie, and ending a session ends it everywhere at once."
  (:require [nickdex.grain.auth.interface :as auth]
            [ring.middleware.session.cookie :as session-cookie])
  (:import [java.security MessageDigest]
           [java.time Instant]))

(defn secret-string
  "The secret as a string, or a refusal to start.

   `force` first, because Biff wraps a `#biff/secret` config value in a
   delay -- and that delay's toString is the FIXED string
   \"#<SecretDelay: redacted>\". An application passing the wrapped value
   straight through therefore derives every key in this library from a
   public constant, and nothing looks wrong: cookies encrypt, sessions
   resolve, sign-in works. It is only not secret. `force` on a plain
   string is identity, so both shapes arrive here correctly.

   Then insist on a non-blank String. nil is the other trap -- Biff's
   config drops keys whose env var is unset, so a missing COOKIE_SECRET
   arrives as nil and hashes to a constant just as happily.

   This is called from `session-config`, which runs once at boot, so a
   badly wired secret is a process that will not start rather than a
   silent weakening nobody sees."
  ^String [secret]
  (let [value (force secret)]
    (if (and (string? value) (not (.isBlank ^String value)))
      value
      (throw (ex-info
              (str "The session secret must be a non-blank string, but was: "
                   (if (nil? value) "nil" (.getName (class value)))
                   ". With Biff, a #biff/secret config value is a delay -- pass "
                   "(force secret), or ((:biff/secret ctx) :biff.ring/cookie-secret). "
                   "Passing the wrapped delay derives this key from a constant.")
              {:type (some-> value class .getName)})))))

(defn cookie-key
  "A 16-byte key for ring's cookie store, derived from a secret.

   Hashed rather than used directly: cookie-store needs exactly 16 bytes
   and throws on anything else, and a secret's length depends on how it
   was generated. SHA-256 makes that a non-question."
  ^bytes [secret]
  (java.util.Arrays/copyOf
   (.digest (MessageDigest/getInstance "SHA-256")
            (.getBytes (secret-string secret) "UTF-8"))
   16))

(defn session-config
  "What to put under Pedestal's ::http/enable-session.

   `secure?` should be false only where the app is genuinely served over
   plain HTTP -- localhost in development. A Secure cookie on http:// is
   dropped silently, and every sign-in appears to work and then does not
   stick.

   SameSite=Lax is load-bearing rather than hygiene. Pedestal's
   ::http/enable-csrf is deliberately NOT the companion to this: it
   demands a token on every POST, and a Datastar app's own posts carry
   none, so switching it on breaks the app instead of protecting it. Lax
   means the browser does not attach this cookie to a cross-site POST at
   all, which is the attack CSRF tokens exist to stop.

   max-age matters more than it looks. Without one this is a SESSION
   cookie, which iOS drops whenever it terminates a Home Screen app --
   so a person is signed out every time they come back, while the row
   the cookie named lives on. It is taken from the session lifetime so
   the two cannot drift."
  [{:keys [cookie-secret cookie-name secure? session-lifetime]}]
  {:store (session-cookie/cookie-store {:key (cookie-key cookie-secret)})
   :cookie-name (or cookie-name "session")
   :cookie-attrs {:same-site :lax
                  :http-only true
                  :secure (boolean secure?)
                  :path "/"
                  :max-age (.toSeconds (or session-lifetime auth/default-session-lifetime))}})

(defn signed-in?
  "The predicate every gated command and query shares.

   Identity, not authorization. It answers whether somebody is signed in
   and stops there -- whether they may touch a particular row, or hold a
   particular role, is the application's question and does not
   generalise.

   Absent means nobody, and Grain refuses anything whose :authorized?
   does not return literal true, so this fails closed."
  [ctx]
  (some? (get-in ctx [:grain.pedestal/session :user-id])))

(defn gate
  "What a Datastar page needs alongside :authorized?.

   :authorized? refuses the QUERY, and for a Datastar page that means the
   shim still renders and then never populates -- a blank screen with no
   way forward. This refuses the PAGE. Both are needed: one for the
   person, one for the stream."
  [sign-in-path]
  {:check signed-in? :redirect (or sign-in-path "/signin")})

(defn interceptor
  "Puts the session on :grain/additional-context, which is the one place
   Grain's commands, queries and Datastar's SSE loop all read from -- so
   this is the whole of 'who is signed in' for an application.

   Also puts it on the request, for plain Pedestal handlers that never
   see the Grain context.

   It has to run on EVERY route, not only the ones that look like they
   need it: an :authorized? predicate reads the session from the
   context, so a route that skips this is a route where every predicate
   sees nobody."
  [{:keys [datasource]}]
  {:name ::session
   :enter
   (fn [ctx]
     (let [session-id (get-in ctx [:request :session :session-id])
           enrolling (get-in ctx [:request :session :grain.pedestal/enrolling])
           session (when session-id
                     (auth/session datasource (parse-uuid (str session-id)) (Instant/now)))]
       (cond-> ctx
         session (-> (assoc-in [:grain/additional-context :grain.pedestal/session] session)
                     (assoc-in [:request :grain.pedestal/session] session))
         ;; A verified enrolment, so a page can greet the person by name.
         ;; Only ever set after a token checked out, and a visitor cannot
         ;; put it in their own session because the cookie is encrypted.
         enrolling (assoc-in [:grain/additional-context :grain.pedestal/enrolling] enrolling))))})

(defn with-session
  "Prepend the session interceptor to every route in a set.

   Pedestal builds its shared interceptor chain inside create-server, and
   Grain owns that call -- so a global interceptor is not the
   application's to add. Prepending per route is: a terse route vector's
   third element is its interceptor list, and Grain's route sets are all
   terse."
  [interceptor routes]
  (into #{}
        (map (fn [route]
               (let [route (vec route)]
                 (update route 2
                         (fn [handlers]
                           (into [interceptor]
                                 (if (sequential? handlers) handlers [handlers])))))))
        routes))
