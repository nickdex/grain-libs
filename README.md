# grain-auth

Passkey authentication for Clojure applications, backed by SQLite tables.

Behaviour is specified in
[`auth.allium`](src/nickdex/grain_auth/auth.allium) — read that first if you
want to know what this is supposed to do. This README covers what is built,
how to use it, and why it is shaped this way.

## Status: alpha, but complete end to end

Credentials, sessions, the rules `auth.allium` states about them, and the
WebAuthn ceremony that drives them — registration, sign-in, and usernameless
conditional-UI autofill, verified with `com.yubico/webauthn-server-core`.

**Screens are not here, on purpose.** Hiccup, shell, theme and icons differ
between applications, and a library that shipped them would be a library you
fight. What ships instead is the browser-side ceremony JS, which is not a
design decision — `navigator.credentials.create` and `.get` have an exact
shape, and every application mounting these routes needs the same code to
talk to them.

There is still no Grain dependency. The name is aspirational; this works in
any Clojure application with a SQLite file.

## Installing

```clojure
nickdex/grain-auth
{:git/url "https://github.com/nickdex/grain-auth.git"
 :git/sha "..."}
```

Use the **HTTPS** URL, not `git@github.com:`. A Docker build that prefetches
dependencies has `git` and CA certificates but no SSH keys, so an SSH
coordinate resolves fine on your laptop and fails in CI.

## Using it

One call at application start, against a pool on the SQLite file you already
have:

```clojure
(require '[nickdex.grain-auth.interface :as auth])

(auth/migrate! datasource)
```

Every table is prefixed `auth_`, so it is obvious which ones are not yours,
and an existing backup script covers them without being told about them.

Every function takes `now` explicitly rather than reading the clock, so a test
can pin it and one request cannot end up holding two notions of the current
instant.

```clojure
;; Registering a key, after the ceremony has verified the attestation
(auth/register-credential!
  ds {:account-id      account-id
      :credential-uuid (random-uuid)
      :credential-id   "base64url-from-the-authenticator"
      :public-key      "cose-key"
      :sign-count      0
      :label           "Phone"}
  now)

;; Opening a session, after the ceremony has verified the assertion
(auth/sign-in! ds {:session-id      (random-uuid)
                   :credential-uuid credential-uuid
                   :sign-count      sign-count}
               now)

;; On every request
(auth/session ds session-id now)          ; => session, or nil

;; Management
(auth/credentials-for-account ds account-id)
(auth/sessions-for-account ds account-id now)
(auth/rename-credential! ds credential-uuid "Work laptop")
(auth/remove-credential! ds credential-uuid)
(auth/sign-out! ds session-id account-id)
```

Rejections come back as `cognitect.anomalies` maps, not exceptions. Messages
are written for whoever reads them on a screen, except where saying more would
confirm something the caller should not learn.

## Wiring the ceremony

The ceremony functions take a `config` naming your relying party and the seam
to your account model:

```clojure
(def config
  {:origin     "https://example.com"   ; scheme + host (+ port), no path
   :app-name   "Example"               ; shown by the authenticator
   :datasource ds
   :accounts   {:account-id-for-handle    (fn [handle] ...)
                :handle-for-account       (fn [account-id] ...)
                :display-name-for-account (fn [account-id] ...)}})
```

`handle` is WebAuthn's `user.name` — whatever you call people by when an
authenticator asks. An email works; a username works. This library never
interprets it. `display-name-for-account` is optional and falls back to the
handle; the two differ because an authenticator shows the display name to
someone choosing between keys, so a person's name belongs there and an email
belongs in the handle.

Mount five handlers, at [`default-ceremony-paths`](src/nickdex/grain_auth/script.clj)
or wherever you prefer:

| Path | Calls |
|---|---|
| `GET /passkey/register/options` | `begin-registration` |
| `POST /passkey/register/finish` | `complete-registration!` |
| `GET /passkey/signin/options` | `begin-sign-in` |
| `POST /passkey/signin/finish` | `complete-sign-in!` |
| `GET /passkey/discover/options` | `begin-discoverable-sign-in` |

Each `begin-` returns `{:options-json :pending}`. Send `:options-json` to the
browser and stash `:pending` — a signed session cookie is the usual answer.
The matching `complete-` needs it back.

**`:pending` is single use.** Discard the stash on completion whether or not
the ceremony succeeded. A captured assertion replayed later is the thing
standing between an intercepted ceremony and an account.

### The browser half goes in `<head>`

```clojure
;; served once, from every page's <head>
[:script {:type "module" :src "/passkey.js?v=<content-hash>"}]
```

**Not in the page body.** If your pages stream their markup — Datastar, htmx,
anything that applies HTML by morphing — a `<script>` element inserted that
way **never executes**. The script silently defines nothing and every button
calling it throws `ReferenceError` into a console nobody is reading: the
button simply does nothing. Inline event *attributes* (`onclick`) do survive
morphing, which is why that is how the buttons are wired.

`ceremony-script` returns the module body; serve it from a route and stamp the
URL with a hash of the content, since a generated asset has no file to stat
and service workers cache by URL.

It exposes:

```js
window.grainAuth.register(label, statusEl, next)
window.grainAuth.signIn(handle, statusEl, next)
window.grainAuth.autofill(next)
```

`next` is where a successful ceremony lands, and it is **per call** because
one `<head>` script serves every page and cannot know which one invoked it.
`:on-success` in the opts is only the fallback when a call passes no `next`.

`autofill` is **opt-in** and does not start itself. From `<head>` a
self-starting conditional-UI request would fire on every page, including for
someone already signed in. Call it only from your sign-in page — and note
that a page whose body is streamed cannot run script on load to do so, which
is a good reason to serve that one page as plain HTML.

Prefer the discoverable path generally: `begin-sign-in` has to reveal whether
an account exists, because the browser needs the credential ids to offer, and
`begin-discoverable-sign-in` needs no handle at all.

### Mounting: keep the ceremony paths free of path params

Some routers — Pedestal's prefix-tree among them — do not backtrack, so a
path-param segment shadows every static sibling at the same depth. Mounting
your own `/passkey/:id/remove` beside these makes `/passkey/register/options`,
`/passkey/signin/options` and `/passkey/discover/options` all 404 at once,
with no route conflict warning. Put your own parameterised routes under a
different prefix.

## What this library does not own

**Accounts.** There is no name, no email, no profile here — `account-id` is an
opaque uuid this library stores and never reads. Your application owns the
person; this owns the keys they get in with. That separation is what lets an
application close signup without this library knowing signup exists: it
registers credentials against accounts that already exist, and never creates
one.

**Whether anyone may sign up.** Same reason.

**Recovery.** A credential is the only way in. An account that loses all of
them is reachable only if your application has its own path back — which is
why `remove-credential!` refuses on the last remaining key.

## Why tables, not an event log

The intended host is an event-sourced Grain application, so this deserves an
explanation.

Auth is infrastructure, not domain. Nothing here is a decision worth
replaying: a key is registered or it is not, a session is valid or it is not.
The workload is point lookups by credential id — which is what an authenticator
hands you, before any account is known — and that is a primary key, not a
projection. And a person who asks to be erased has to actually disappear,
which an append-only log cannot do.

There is a security property in it too. Grain's command-request-handler routes
every registered command over HTTP. As a `defcommand`, `sign-in!` would have
been reachable by POSTing a credential id, and the guard against that had to be
invented and remembered. A plain function has no route.

The cost is real and worth stating: **you own migrations.** There is no
bump-the-version-and-replay escape hatch here the way there is for a Grain read
model. `migrate!` is idempotent and stretches as far as adding tables and
columns; anything that rewrites existing rows needs a migration written by
hand, and this library has no machinery for that yet.

## Design notes worth knowing before you change anything

**Signature counters may be zero forever.** WebAuthn's clone detection expects
a counter that only rises. Synced authenticators — Apple's and Google's, so
most passkeys in use — report `0` on every assertion by design, because a
counter cannot be kept consistent across copies that are all legitimate.
`sign-in!` accepts a rise *or* zero. Requiring a rise rejects most passkeys in
the world.

**Timestamps are epoch milliseconds, not ISO-8601 text.** `Instant/toString`
omits trailing zeros, so `2026-08-26T09:00Z` and `2026-08-26T09:00:00.123Z` do
not compare correctly as strings — and `expires_at > ?` then silently returns
the wrong rows for any timestamp landing on a whole second.

**Removing a key ends every session on the account**, not only the ones that
key opened. A key is removed because it was lost or stolen, and at that moment
the question is not which sessions it started but whether anyone else is still
signed in.

**Expiry is a `WHERE` clause, not a job.** Every read excludes expired
sessions, so no sweep has to have run for the check to be correct.
`purge-expired-sessions!` reclaims rows and changes no answer; it may run
whenever, or never.

**`sign-out!` is scoped to the caller's account.** Without `account_id` in that
`WHERE` clause, a session id alone is enough to sign somebody else out.

## Tests

```bash
clj -M:test
```

Tests are propagated from `auth.allium`, and each `testing` string opens with
the obligation it discharges, so a failing run names the spec clause that broke.

They run against a real SQLite database in a temp file — not `:memory:`, where
every connection in a pool gets its own private database unless shared-cache is
negotiated, and a two-connection test passes or fails depending on which
connection it happened to get.

One gap worth knowing: **no test exercises a ceremony that succeeds.** That
needs a real authenticator holding a real private key, and the cryptography is
Yubico's, verified by its own suite rather than re-verified here — faking it
would mean faking the signature check, which is the only part that matters.
What is covered is everything around it: the account seam Yubico calls into,
the options a browser receives, and every failure path, including that a
refusal never throws and that all of them say the same thing.

## License

EPL-2.0. See [LICENSE](LICENSE).
