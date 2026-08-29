(ns nickdex.grain.pedestal.routes-test
  "Structural tests for the route table.

   Not behavioural: exercising a ceremony needs a real authenticator, and
   the libraries these wrap are tested in their own directories. What is
   here is the shape of the routes, which is where this library has
   actually gone wrong."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [nickdex.grain.pedestal.interface :as glue]
            ;; cookie-key is internal -- not something a consuming app
            ;; calls -- but it is where the secret is turned into a key,
            ;; so it is where the secret's shape has to be pinned.
            [nickdex.grain.pedestal.session :as session]))

(def config
  {:datasource nil
   :cookie-secret "test-secret"
   :origin "https://example.test"
   :app-name "Example"
   :accounts {}
   :paths {:sign-in "/signin" :enrol "/enrol" :account "/account"}
   :vapid-public-key "public-key"
   :service-worker-shell nil})

(defn- paths [routes] (map first routes))

(defn- segments [path] (rest (str/split path #"/")))

(defn- param? [segment] (str/starts-with? segment ":"))

(deftest no-param-segment-shadows-a-static-sibling
  ;; Pedestal's prefix-tree router does not backtrack: a path-param
  ;; segment shadows every static sibling at the same depth. Mounting
  ;; /passkey/:credential-uuid/remove once made
  ;; /passkey/register/options, /passkey/signin/options and
  ;; /passkey/discover/options ALL return 404 at the same moment, with no
  ;; route conflict warning anywhere -- three endpoints that simply
  ;; stopped existing because a fourth was added.
  ;;
  ;; The rule this pins: for any prefix, the segment after it is either
  ;; always a parameter or never one.
  (let [prefixes (for [path (paths (glue/routes config))
                       :let [segs (segments path)]
                       i (range (count segs))]
                   [(str/join "/" (take i segs))
                    (if (param? (nth segs i)) :param :static)])
        shapes (reduce (fn [acc [prefix shape]]
                         (update acc prefix (fnil conj #{}) shape))
                       {}
                       prefixes)]
    (doseq [[prefix seen] shapes]
      (is (= 1 (count seen))
          (str "under /" prefix " the next segment is sometimes a parameter "
               "and sometimes static: " seen
               " -- the parameter shadows the static ones")))))

(deftest enrolment-is-a-form-post-not-a-link
  ;; The link it replaced was a bearer credential in a URL: forwardable,
  ;; screenshottable, kept in history, and impossible to read down a
  ;; phone. A code is none of those.
  (let [routes (glue/routes config)
        by-path (into {} (map (fn [r] [(first r) (second r)])) routes)]
    (is (= :post (get by-path "/enrol/verify")))
    (is (not (contains? by-path "/enrol/claim"))
        "the signed-link route must not linger beside the code one")))

(deftest every-route-is-uniquely-named
  ;; Pedestal keys routes by name; a duplicate silently wins over the
  ;; other.
  (let [names (map last (glue/routes config))]
    (is (= (count names) (count (distinct names))))))

(deftest asset-routes-are-omitted-when-not-configured
  (testing "no service worker shell means no /sw.js route to serve a broken one"
    (is (= #{"/passkey.js" "/push.js"} (set (paths (glue/asset-routes config))))))

  (testing "and it appears once a shell is named"
    (is (contains? (set (paths (glue/asset-routes
                                (assoc config :service-worker-shell "sw-shell.js"))))
                   "/sw.js"))))

(deftest head-scripts-are-content-stamped
  ;; A service worker caches shell assets by URL and serves them without
  ;; revalidating, so a changed script must arrive under a changed URL.
  (let [rendered (pr-str (glue/head-scripts config))]
    (is (re-find #"/passkey\.js\?v=[0-9a-f]+" rendered))
    (is (re-find #"/push\.js\?v=[0-9a-f]+" rendered))))

(deftest head-scripts-are-stable-across-calls
  ;; head-scripts runs on EVERY page render, via the Datastar shim.
  ;; Before this was memoised each call rebuilt several KB of JavaScript
  ;; and hashed it, to arrive at the same answer -- and a stamp that
  ;; changed per render would also defeat caching entirely.
  (is (= (glue/head-scripts config) (glue/head-scripts config))))

(deftest asset-path-stamps-a-real-file
  (testing "a resource gets a stamp derived from the file itself"
    (let [stamped (glue/asset-path "/test-asset.txt")]
      (is (re-matches #"/test-asset\.txt\?v=[0-9a-f]+" stamped))
      (is (= stamped (glue/asset-path "/test-asset.txt")))))

  (testing "a missing one returns the bare path rather than throwing"
    ;; A missing asset should surface as a 404 you can see, not a 500
    ;; during render.
    (is (= "/not-here.css" (glue/asset-path "/not-here.css")))))

(deftest the-session-secret-must-really-be-a-secret
  ;; Biff wraps a #biff/secret config value in a delay whose toString is
  ;; the FIXED string "#<SecretDelay: redacted>". Passing that wrapper
  ;; through derived every cookie key from a public constant, and nothing
  ;; looked wrong -- cookies encrypted, sessions resolved, sign-in
  ;; worked. It was only not secret.
  (testing "a delay is forced, so a Biff secret gives the key its value would"
    (is (java.util.Arrays/equals
         (session/cookie-key "s3kr1t")
         (session/cookie-key (delay "s3kr1t")))))

  (testing "two secrets give two keys"
    ;; THE property the bug broke, and the one a "is it 16 bytes?" test
    ;; sails straight past: under the bug both of these were equal.
    (is (not (java.util.Arrays/equals (session/cookie-key "one")
                                      (session/cookie-key "two")))))

  (testing "anything that is not a non-blank string is refused"
    ;; nil is the live case: Biff drops config keys whose env var is
    ;; unset, so a missing COOKIE_SECRET arrives as nil and would hash
    ;; just as happily as any other constant.
    (doseq [bad [nil "" "   " 42 (delay nil) {:not "a secret"}]]
      (is (thrown? clojure.lang.ExceptionInfo (session/cookie-key bad))
          (str "accepted " (pr-str bad)))))

  (testing "and session-config refuses at boot rather than at first request"
    (is (thrown? clojure.lang.ExceptionInfo
                 (glue/session-config (assoc config :cookie-secret nil))))))

(deftest the-session-cookie-cannot-be-a-session-cookie
  ;; Without a max-age the browser drops it when the browsing session
  ;; ends, which on an iPhone means whenever iOS terminates the app --
  ;; so every return minted a new session while the row it named lived
  ;; on. Nothing looked broken; you were simply signed out.
  (let [attrs (:cookie-attrs (glue/session-config (assoc config :secure? true)))]
    (is (pos? (:max-age attrs)))
    (is (= :lax (:same-site attrs)))
    (is (true? (:http-only attrs)))
    (is (true? (:secure attrs))))

  (testing "secure is opt-out, for plain-HTTP localhost only"
    (is (false? (:secure (:cookie-attrs (glue/session-config config)))))))
