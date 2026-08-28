(ns nickdex.grain.pedestal.routes-test
  "Structural tests for the route table.

   Not behavioural: exercising a ceremony needs a real authenticator, and
   the libraries these wrap are tested in their own directories. What is
   here is the shape of the routes, which is where this library has
   actually gone wrong."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [nickdex.grain.pedestal.interface :as glue]))

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
