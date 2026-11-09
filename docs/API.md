# gatekeeper-io API

## Stages (`gatekeeper_io::stage`, re-exported)

| Item | Purpose |
|---|---|
| `Inspected::new()` | the request pipeline's mark |
| `Identified` | `identity`, `subject`, `user`, `is_guest`, `set_cookie`; only authentication builds one |
| `Cleared` | the same accessors; only authorization builds one |
| `Identity` | `Guest`, or `Member { user, session, subject }` |

## The gates

| Item | Purpose |
|---|---|
| `trait Authenticator { fn authenticate(&self, Inspected, &Visit) -> Result<Identified, Refusal> }` | authentication on the core |
| `EveryoneGuest` | a starter `Authenticator`: everyone is a guest |
| `Gatekeeper::builder(Schema, GateKeys)?` | `identities`, `sessions`, `signals`, `audit`, `attributes`, `clock`, `locator`, `origin`, `password_policy`, `session_policy`, `lockout_policy`, `build` |
| `Gatekeeper::authorize(Identified, &Rule) -> Result<Cleared, Refusal>` | route check |
| `Gatekeeper::authorize_on(Identified, &Rule, &Resource)` | object check |
| `login_form(&Cleared, &Visit) -> FormToken` | the login form's CSRF token and pre-session cookie |
| `login(&Cleared, &Visit, LoginForm) -> Login` | `SignedIn`, `SecondFactor`, `Failed` |
| `second_factor(&Cleared, &Visit, CodeForm) -> Login` | the code form |
| `login_passkey(&Cleared, &Visit, &RelyingParty, PasskeyForm) -> Login` | passkey sign-in |
| `logout(Cleared, &Visit, csrf) -> Result<SignedOut, Refusal>` | sign-out |
| `csrf_token(&Cleared)`, `check_csrf(&Cleared, &Visit, token)` | CSRF for signed-in forms |
| `create_account`, `set_standing`, `set_roles`, `change_password` | audited account changes |
| `auth()`, `schema()` | the underlying gate and schema |
| `keys_from_vault(&KeyVault, KeyHandle) -> Result<GateKeys>` | keys from the master secret |

## Request facts

`Visit::new(peer)`, `method`, `cookie_header`, `authorization`, `user_agent`, `fetch_site`, `origin`, `referer`; `Locator` (`Cookie(name)`, `Bearer`, `CookieOrBearer(name)`; default `__Host-sid`).

## Results

`Refusal` (`kind`, `status`: 401, 403, or 503; `set_cookie`), `RefusalKind`, `FormToken`, `Login`, `SignedIn` (`user`, `set_cookies`, `token`), `SecondFactor`, `LoginFailed`, `LoginFailure`, `SignedOut`.

## Audit

`AuditLog` (trait), `ChainAudit<S>` (an audit-trail chain under keyed BLAKE3; `memory`, `records`, `actions`, `failures`), `AuditEvent`, `AuditAction`, `KeyedBlake3`.

The crate also re-exports the access-gate and auth-gate types a service needs (`Schema`, `Rule`, `Resource`, `Standing`, `GateKeys`, the stores, signals).

## Feature `web-net` (web-net 0.7)

`Gatekeeper` implements `web_net::Gate` (`Identity = Identified`, `Rule = access_gate::Rule`) and `Identified` implements `web_net::Identity` (`csrf_binding`: the session id, or a guest's pre-session value; `set_cookie`: the cleared session cookie, when there is one). `web::visit(&Request)` builds the gates' `Visit`; `web::denial(&Refusal)` maps a refusal to a web-net `Denial`, carrying the refusal's cookie (`gate.sign_in`, `gate.step_up`, `gate.guest_only`, `gate.banned`, `gate.csrf`, `gate.forbidden`, `gate.unavailable`).

Also: `Gatekeeper::check(&Identified, &Rule, Option<&Resource>) -> Result<(), Refusal>` decides without consuming the stage; `Identified::csrf_binding`; `Visit::duplicate_cookie_fields()` (more than one `Cookie` field: every cookie read is refused).
