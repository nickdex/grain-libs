(ns nickdex.grain-auth.script
  "The browser half of the ceremony.

   This is here rather than in the application because it is not a
   design decision -- `navigator.credentials.create` and `.get` are
   imperative calls with an exact shape, and every application that
   mounts these routes needs the same code to talk to them. The screens
   around it ARE a design decision, and stay in the application.

   Datastar cannot express this. A signal is a value the server patches;
   a ceremony is a promise the browser must await and whose result it
   must post back. So this ships as a plain <script type=\"module\"> and
   the surrounding page is Datastar as usual.

   Nothing here renders. The application supplies the markup and the
   element ids, and calls window.grainAuth.{register,signIn} from it."
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
  "The module body: `window.grainAuth` with register, signIn, and an
   autofill attempt that runs on load.

   `opts`:
     :paths       overrides for `default-paths`
     :csrf-token  sent as the X-CSRF-Token header on every POST
     :on-success  a JS expression run after a successful sign-in,
                  e.g. \"window.location = '/'\"

   Returns a string to put inside [:script {:type \"module\"} ...]."
  [{:keys [paths csrf-token on-success]}]
  (let [{:keys [register-options register-finish signin-options
                signin-finish discover-options]} (merge default-paths paths)
        q #(json/generate-string %)]
    (str "
const CSRF = " (q (or csrf-token "")) ";
const onSuccess = () => { " (or on-success "window.location.reload()") " };

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

async function register(label, statusEl) {
  fail(statusEl, '');
  const optsRes = await fetch(" (q register-options) ");
  if (!optsRes.ok) { fail(statusEl, 'Could not start registration.'); return; }
  const options = PublicKeyCredential.parseCreationOptionsFromJSON(await optsRes.json());
  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey: options });
  } catch (e) {
    // A cancelled prompt lands here alongside a real failure. Neither is
    // worth alarming language: the person either changed their mind or
    // their device declined, and both mean 'try again'.
    fail(statusEl, 'Registration was cancelled or did not complete.');
    return;
  }
  const result = await post(" (q register-finish) ",
                            { label: label, credential: credential.toJSON() });
  fail(statusEl, result.ok ? 'Passkey added.' : 'That passkey could not be registered.');
  if (result.ok) onSuccess();
}

async function finish(credential, statusEl) {
  const result = await post(" (q signin-finish) ", { credential: credential.toJSON() });
  if (result.ok) { onSuccess(); } else { fail(statusEl, 'That passkey could not be used to sign in.'); }
}

async function signIn(handle, statusEl) {
  fail(statusEl, '');
  const optsRes = await fetch(" (q signin-options) " + '?handle=' + encodeURIComponent(handle));
  if (!optsRes.ok) { fail(statusEl, 'That passkey could not be used to sign in.'); return; }
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(await optsRes.json());
  let credential;
  try {
    credential = await navigator.credentials.get({ publicKey: options });
  } catch (e) {
    fail(statusEl, 'Sign-in was cancelled or did not complete.');
    return;
  }
  await finish(credential, statusEl);
}

// Usernameless autofill. Feature-detected rather than assumed, and a
// rejected promise here is the ordinary outcome -- the request is
// superseded whenever the person does anything else -- so it is not
// surfaced.
async function tryConditional() {
  if (!window.PublicKeyCredential || !PublicKeyCredential.isConditionalMediationAvailable) return;
  if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return;
  const optsRes = await fetch(" (q discover-options) ");
  if (!optsRes.ok) return;
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(await optsRes.json());
  let credential;
  try {
    credential = await navigator.credentials.get({ publicKey: options, mediation: 'conditional' });
  } catch (e) { return; }
  if (credential) await finish(credential, null);
}

window.grainAuth = { register, signIn };
tryConditional();
")))
