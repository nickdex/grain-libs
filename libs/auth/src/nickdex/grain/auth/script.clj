(ns nickdex.grain.auth.script
  "The browser half of the ceremony.

   This is here rather than in the application because it is not a
   design decision -- `navigator.credentials.create` and `.get` are
   imperative calls with an exact shape, and every application that
   mounts these routes needs the same code to talk to them. The screens
   around it ARE a design decision, and stay in the application.

   Datastar cannot express this. A signal is a value the server patches;
   a ceremony is a promise the browser must await and whose result it
   must post back.

   IT MUST LOAD FROM <head>, not from the page body. A Datastar page's
   body arrives as an SSE patch and is applied by DOM morphing, and a
   <script> element inserted that way never executes -- so a ceremony
   script sitting in the patched markup silently defines nothing and
   every button calling it throws ReferenceError into a console nobody
   is reading. Inline event attributes (onclick) DO survive morphing,
   which is why the buttons are wired that way.

   One <head> serves every page, so two things are per-call rather than
   baked in: `next` says where a successful ceremony lands, and autofill
   is opt-in. A conditional-UI request that fired on load would fire on
   EVERY page, including for someone already signed in.

   Nothing here renders. The application supplies the markup and the
   element ids, and calls window.grainAuth.{register,signIn,autofill}."
  (:require [cheshire.core :as json]))

(def default-paths
  "Where the application is expected to have mounted the ceremony
   handlers. Override per path if it mounted them elsewhere -- a mismatch
   is a 404 in a fetch nobody is watching, so these are worth checking
   against the route table rather than assuming."
  {:register-options "/passkey/register/options"
   :register-finish  "/passkey/register/finish"
   :signin-options   "/passkey/signin/options"
   :signin-finish    "/passkey/signin/finish"
   :discover-options "/passkey/discover/options"})

(defn ceremony-script
  "The module body: `window.grainAuth` with register, signIn and
   autofill. Put it in <head> -- see the ns docstring for why the page
   body is not an option.

   `opts`:
     :paths       overrides for `default-paths`
     :csrf-token  sent as the X-CSRF-Token header on every POST
     :on-success  fallback JS run after success when a call passes no
                  `next`, e.g. \"window.location = '/'\"

   Returns a string to put inside [:script {:type \"module\"} ...]."
  [{:keys [paths csrf-token on-success]}]
  (let [{:keys [register-options register-finish signin-options
                signin-finish discover-options]} (merge default-paths paths)
        q #(json/generate-string %)]
    (str "
const CSRF = " (q (or csrf-token "")) ";
const fallback = () => { " (or on-success "window.location.reload()") " };

// Where a successful ceremony lands. Per call, because one <head>
// script serves every page and each has its own next step.
function go(next) { if (next) { window.location = next; } else { fallback(); } }

async function post(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
    body: JSON.stringify(body),
  });
  return res.json();
}

// Every failure surfaces the same way. The server already refuses to say
// which step failed; saying more here would give it back.
function fail(el, message) { if (el) el.textContent = message; }

// What went wrong at the authenticator, in words whoever can act on it
// would use.
//
// A dismissed prompt and a misconfigured relying party both arrive here
// as an exception, and calling both 'cancelled' is what makes a
// deployment mistake look like somebody changing their mind. The browser
// already tells them apart by name:
//
//   SecurityError    the page's origin is not the RP id the server sent.
//                    Nothing the person can do; whoever set the base URL
//                    can.
//   NotAllowedError  dismissed, or timed out. Theirs, and 'try again' is
//                    the whole of the advice.
//
// Naming the RP id gives nothing away -- the server sent it to this page
// a moment ago, and the origin it is being compared against is in the
// URL bar. It turns the one failure nobody can guess at into a one-line
// fix.
function ceremonyError(e, options, verb) {
  if (e && e.name === 'SecurityError') {
    const rp = options && options.rp && options.rp.id;
    return 'This site is ' + window.location.origin + ', but passkeys here are set up for '
      + (rp ? rp : 'another site')
      + '. Those have to match -- check the base URL the server is configured with.';
  }
  if (!window.isSecureContext) {
    return 'Passkeys need a secure connection. Open this over https, or on localhost.';
  }
  return verb + ' was cancelled or did not complete.';
}

async function register(label, statusEl, next) {
  fail(statusEl, '');
  const optsRes = await fetch(" (q register-options) ");
  if (!optsRes.ok) { fail(statusEl, 'Could not start registration.'); return; }
  const options = PublicKeyCredential.parseCreationOptionsFromJSON(await optsRes.json());
  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey: options });
  } catch (e) {
    fail(statusEl, ceremonyError(e, options, 'Registration'));
    return;
  }
  const result = await post(" (q register-finish) ",
                            { label: label, credential: credential.toJSON() });
  fail(statusEl, result.ok ? 'Passkey added.' : 'That passkey could not be registered.');
  if (result.ok) go(next);
}

async function finish(credential, statusEl, next) {
  const result = await post(" (q signin-finish) ", { credential: credential.toJSON() });
  if (result.ok) { go(next); } else { fail(statusEl, 'That passkey could not be used to sign in.'); }
}

async function signIn(handle, statusEl, next) {
  fail(statusEl, '');
  const optsRes = await fetch(" (q signin-options) " + '?handle=' + encodeURIComponent(handle));
  if (!optsRes.ok) { fail(statusEl, 'That passkey could not be used to sign in.'); return; }
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(await optsRes.json());
  let credential;
  try {
    credential = await navigator.credentials.get({ publicKey: options });
  } catch (e) {
    fail(statusEl, ceremonyError(e, options, 'Sign-in'));
    return;
  }
  await finish(credential, statusEl, next);
}

// Usernameless autofill. OPT-IN: this script loads in <head> on every
// page, and a conditional request that started itself would run on all
// of them, including for someone already signed in. The sign-in page
// calls it; nothing else does.
//
// Feature-detected rather than assumed, and a rejected promise here is
// the ordinary outcome -- the request is superseded whenever the person
// does anything else -- so it is not surfaced.
async function autofill(next) {
  if (!window.PublicKeyCredential || !PublicKeyCredential.isConditionalMediationAvailable) return;
  if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return;
  const optsRes = await fetch(" (q discover-options) ");
  if (!optsRes.ok) return;
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(await optsRes.json());
  let credential;
  try {
    credential = await navigator.credentials.get({ publicKey: options, mediation: 'conditional' });
  } catch (e) { return; }
  if (credential) await finish(credential, null, next);
}

window.grainAuth = { register, signIn, autofill };
")))
