<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>gatekeeper-io</b><br>
    <sub><sup>API REFERENCE</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>API</span>
        <span>&nbsp;│&nbsp;</span>
        <a href="./PERFORMANCE.md" title="Performance"><b>PERFORMANCE</b></a>
    </sup>
</div>
<br>

Every public item of the 0.7 API. The rustdoc on
[docs.rs](https://docs.rs/gatekeeper-io) has each item with an example.

- [Stages (`gatekeeper_io::stage`, re-exported)](#stages-gatekeeper_iostage-re-exported)
- [The gates](#the-gates)
  - [Authentication](#authentication)
  - [Authorization](#authorization)
  - [Sign-in and sign-out](#sign-in-and-sign-out)
  - [Account changes](#account-changes)
- [Request facts](#request-facts)
- [Results](#results)
- [Audit](#audit)
- [Feature `web-net` (web-net 0.11)](#feature-web-net-web-net-011)

## Stages (`gatekeeper_io::stage`, re-exported)

| Item | Purpose |
|---|---|
| `Inspected::new()` | the request pipeline's mark |
| `Identified` | `identity`, `subject`, `user`, `is_guest`, `set_cookie`; only authentication builds one |
| `Cleared` | the same accessors; only authorization builds one |
| `Identity` | `Guest`, or `Member { user, session, subject }` |

## The gates

### Authentication

| Item | Purpose |
|---|---|
| `trait Authenticator { fn authenticate(&self, Inspected, &Visit) -> Result<Identified, Refusal> }` | authentication on the core |
| `EveryoneGuest` | a starter `Authenticator`: everyone is a guest |
| `Gatekeeper::builder(Schema, GateKeys)?` | `identities`, `sessions`, `signals`, `audit`, `attributes`, `clock`, `locator`, `origin`, `password_policy`, `session_policy`, `lockout_policy`, `build` |
| `keys_from_vault(&KeyVault, KeyHandle) -> Result<GateKeys>` | keys from the master secret |

### Authorization

| Item | Purpose |
|---|---|
| `Gatekeeper::authorize(Identified, &Rule) -> Result<Cleared, Refusal>` | route check |
| `Gatekeeper::authorize_on(Identified, &Rule, &Resource)` | object check |
| `auth()`, `schema()` | the underlying gate and schema |

### Sign-in and sign-out

| Item | Purpose |
|---|---|
| `login_form(&Cleared, &Visit) -> FormToken` | the login form's CSRF token and pre-session cookie |
| `login(&Cleared, &Visit, LoginForm) -> Login` | `SignedIn`, `SecondFactor`, `Failed` |
| `second_factor(&Cleared, &Visit, CodeForm) -> Login` | the code form |
| `login_passkey(&Cleared, &Visit, &RelyingParty, PasskeyForm) -> Login` | passkey sign-in |
| `logout(Cleared, &Visit, csrf) -> Result<SignedOut, Refusal>` | sign-out |
| `csrf_token(&Cleared)`, `check_csrf(&Cleared, &Visit, token)` | CSRF for signed-in forms |

### Account changes

| Item | Purpose |
|---|---|
| `create_account`, `set_standing`, `set_roles`, `change_password`, `enroll_totp`, `confirm_totp`, `remove_totp`, `new_recovery_codes`, `register_passkey`, `remove_passkey`, `sign_out_everywhere` | audited account, factor, and session changes |

## Request facts

`Visit::new(peer)`, `method`, `cookie_header`, `authorization`, `user_agent`, `fetch_site`, `origin`, `referer`; `Locator` (`Cookie(name)`, `Bearer`, `CookieOrBearer(name)`; default `__Host-sid`).

## Results

`Refusal` (`kind`, `status`: 401, 403, or 503; `set_cookie`, only on authentication refusals), `RefusalKind`, `FormToken`, `Login`, `SignedIn` (`user`, `set_cookies`, `token`), `SecondFactor`, `LoginFailed`, `LoginFailure`, `SignedOut`.

## Audit

`AuditLog` (trait), `RingSink` (bounded memory sink), `MEMORY_AUDIT_RECORDS`, `ChainAudit<S>` (an audit-trail chain under keyed BLAKE3; `memory`, `records`, `actions`, `failures`), `AuditEvent`, `AuditAction`, `KeyedBlake3`.

The crate also re-exports the access-gate and auth-gate types a service needs (`Schema`, `Rule`, `Resource`, `Standing`, `GateKeys`, the stores, signals).

## Feature `web-net` (web-net 0.11)

`Gatekeeper` implements `web_net::Gate` (`Identity = Identified`, `Rule = access_gate::Rule`) and `Identified` implements `web_net::Identity` (`csrf_binding`: the session id, or a guest's pre-session value; `set_cookie`: the cleared session cookie, when there is one). `web::visit(&Request, &cookie_lines)` builds the gates' `Visit`; `web::denial(&Refusal)` maps a refusal to a web-net `Denial`, carrying the refusal's cookie (`gate.sign_in`, `gate.step_up`, `gate.guest_only`, `gate.banned`, `gate.csrf`, `gate.foreign_stage`, `gate.forbidden`; and `gate.unavailable`, a retryable 503 when the stores cannot answer).

Also: `Gatekeeper::check(&Identified, &Rule, Option<&Resource>) -> Result<(), Refusal>` decides without consuming the stage; `Identified::csrf_binding`; `Visit::cookie_lines(&lines)` (several `Cookie` field lines, HTTP/2 crumbs, read as one header; a duplicate cookie name is refused).
