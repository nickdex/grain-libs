# grain-libs

Libraries for Clojure applications on the Grain + Datastar + Pedestal
stack. Each is independent, has its own `deps.edn`, and is depended on by
`:deps/root`.

| Library | What it is |
|---|---|
| [`libs/auth`](libs/auth) | Passkey authentication: WebAuthn credentials, sessions, and the ceremony. Specified in [`auth.allium`](libs/auth/src/nickdex/grain/auth/auth.allium). |
| [`libs/push`](libs/push) | Web Push: device subscriptions and delivery. Specified in [`push.allium`](libs/push/src/nickdex/grain/push/push.allium). |
| [`libs/pedestal`](libs/pedestal) | Both of the above, wired into a Grain + Datastar + Pedestal app: session cookie and interceptor, ceremony routes, browser scripts. |

```clojure
nickdex/grain-auth
{:git/url   "https://github.com/nickdex/grain-libs.git"
 :git/sha   "..."
 :deps/root "libs/auth"}
```

Use the **HTTPS** URL, not `git@github.com:`. A Docker build that
prefetches dependencies has `git` and CA certificates but no SSH keys, so
an SSH coordinate resolves on your laptop and fails in CI.

## Which one to depend on

`libs/pedestal` brings `auth` and `push` with it. **Depend on it alone.**
Declaring `grain-auth` or `grain-push` separately as well gives
tools.deps two coordinates for one lib -- one local, one git -- and it
refuses with `No known ancestor relationship between local versions`.

Take `auth` or `push` directly only if you are not on Pedestal, or want
one without the other and will do your own wiring.

## auth and push do not depend on each other

`push` takes an opaque account id, so an application can have
notifications without passkeys, and the two are proven independently.

## What they own, and what they do not

Both stop at **identity**. They answer *who is asking* and go no further:
`auth` stores an opaque `account-id` and never reads a field on it, and
`push` does the same.

**Authorization is the application's.** One app scopes rows by owner,
another checks roles — those are different questions and neither belongs
here. `signed-in?` is the last predicate that generalises.

Roles in particular should live on the application's own account model
rather than on a session. A session carrying roles goes stale the moment
one changes, and revoking a permission becomes revoking a session.

## Tests

```bash
bin/test
```

Each library is tested from its own directory; there is no aggregate
classpath, for the `:deps/root` reason above.
