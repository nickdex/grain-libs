(ns nickdex.grain.pedestal.enrolment
  "The link that lets a brand-new account register its first passkey.

   A chicken-and-egg problem: registering a credential needs an
   authenticated caller, and a new account has no credential to
   authenticate with. A signed link is the way across.

   Nothing is stored, and there is no token table to clean up. Being
   single-use falls out of what the token AUTHORISES rather than from
   marking it spent: enrolment is only valid on an account with no
   credentials, so the first key registered kills the link.

   It is a bearer credential for its lifetime, and that is the real cost.
   Whoever opens the link can put THEIR key on that account, with no
   second factor behind it -- so it wants a short life and a channel you
   trust."
  (:require [nickdex.grain.auth.interface :as auth])
  (:import [java.nio.charset StandardCharsets]
           [java.security MessageDigest]
           [java.time Duration Instant]
           [java.util Base64]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(def default-lifetime (Duration/ofHours 24))

(defn- ->key
  "A signing key derived from the application's secret rather than
   configured separately.

   Derived, not reused: the same bytes signing session cookies and
   enrolment links means a flaw in one is a flaw in the other, and the
   label is what keeps the two key streams apart. SHA-256 also makes the
   length right whatever format the secret arrives in."
  ^SecretKeySpec [secret]
  (SecretKeySpec.
   (.digest (doto (MessageDigest/getInstance "SHA-256")
              (.update (.getBytes (str secret "|enrolment") StandardCharsets/UTF_8))))
   "HmacSHA256"))

(defn- sign ^bytes [secret ^String payload]
  (.doFinal (doto (Mac/getInstance "HmacSHA256") (.init (->key secret)))
            (.getBytes payload StandardCharsets/UTF_8)))

(defn- b64 [^bytes bs] (.encodeToString (Base64/getUrlEncoder) bs))
(defn- unb64 ^bytes [^String s] (.decode (Base64/getUrlDecoder) s))

(defn token
  "A token naming one account, good until it expires or that account has
   a key -- whichever comes first."
  ([secret account-id now] (token secret account-id now default-lifetime))
  ([secret account-id ^Instant now ^Duration lifetime]
   (let [payload (str account-id "|" (.toEpochMilli (.plus now lifetime)))]
     (str (b64 (.getBytes payload StandardCharsets/UTF_8)) "."
          (b64 (sign secret payload))))))

(defn account
  "The account id a token authorises, or nil.

   nil covers a token that was tampered with, one that expired, and one
   for an account that already has a key. The caller reports one refusal
   for all of them: telling them apart says whether an account exists and
   whether it is enrolled, to somebody holding nothing but a guess."
  [{:keys [datasource]} secret ^String tok ^Instant now]
  (try
    (let [[payload-b64 sig-b64] (clojure.string/split (str tok) #"\." 2)
          payload (String. (unb64 payload-b64) StandardCharsets/UTF_8)]
      (when (MessageDigest/isEqual (sign secret payload) (unb64 sig-b64))
        (let [[account-id expires-at] (clojure.string/split payload #"\|" 2)
              account-id (parse-uuid account-id)]
          (when (and account-id
                     (< (.toEpochMilli now) (parse-long expires-at))
                     ;; The one-shot condition. Once a key exists the
                     ;; account is enrolled and the link is spent, with
                     ;; nothing to expire or delete.
                     (empty? (auth/credentials-for-account datasource account-id)))
            account-id))))
    ;; A malformed token is a refusal, not a 500. Everything here arrives
    ;; as untrusted input from a URL.
    (catch Exception _ nil)))
