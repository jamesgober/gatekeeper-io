<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>gatekeeper-io</b>
    <br>
    <sub>
        <sup>THE GATES, IN ONE PACKAGE</sup>
    </sub>
</h1>

<p align="center">
    <a href="https://crates.io/crates/gatekeeper-io"><img src="https://img.shields.io/crates/v/gatekeeper-io.svg" alt="Crates.io"></a>
    <a href="https://crates.io/crates/gatekeeper-io" alt="Download"><img alt="Crates.io Downloads" src="https://img.shields.io/crates/d/gatekeeper-io?color=%230099ff"></a>
    <a href="https://docs.rs/gatekeeper-io"><img src="https://docs.rs/gatekeeper-io/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/jamesgober/gatekeeper-io/actions"><img alt="GitHub CI" src="https://github.com/jamesgober/gatekeeper-io/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg" alt="License"></a>
</p>

<p align="center">
    <b>Authentication and authorization for Rust services, in one package.</b>
    <br>
    <i>Skipping a gate does not compile.</i>
</p>

<br>

<p>
    <strong>gatekeeper-io</strong> joins the two gates a service needs: <strong>authentication</strong> on every request (auth-gate) and <strong>authorization</strong> in the router after the route match (access-gate). Around them it adds sign-in and sign-out with CSRF on both forms (csrf-sec), the session cookie (cookie-net), standing changes such as bans and suspensions, a tamper-evident audit chain (audit-trail), and keys derived from one master secret held in key-vault.
</p>

<p>
    A request carries a stage value. <code>Inspected</code> comes from the request pipeline, <code>Identified</code> only from authentication, and <code>Cleared</code> only from authorization. Handlers take <code>Cleared</code>, so a handler cannot run before both gates have. A <code>Cleared</code> says the request passed a rule of this gatekeeper, not which one, so each handler stays next to its route's rule.
</p>

<p>
    Every request reads memory only: the session record carries the permission set, the tenant, and the attributes rules compare, and they are tied to a fingerprint of the schema, so a schema or role change can never hand an old session someone else's permissions. Accounts and sessions live behind store traits, with in-memory stores included for tests and local work.
</p>

---

## Features

### **The gates**
- **Stage types** - `Inspected`, `Identified`, and `Cleared` have no public constructor past the first, so a gate cannot be skipped.
- **One rule per route** - roles compile to permission bit sets at boot; a decision is a few word operations.
- **Object checks** - ownership, tenancy, and attribute conditions on the resource the handler loaded.

### **Sign-in**
- **Passwords, codes, passkeys** - Argon2id, TOTP and recovery codes, and WebAuthn, through auth-gate.
- **CSRF on both forms** - the login form is bound to a pre-session cookie, signed-in forms to the session.
- **Uniform failures** - the same message and the same work whether or not an account exists.

### **Operations**
- **Audit** - sign-ins, failures, bans, role and factor changes go into a keyed hash chain.
- **Signals** - every refusal and suspicious token is reported to the security bridge.
- **web-net** - with the `web-net` feature the gatekeeper is a `web_net::Gate`.

### **Reliability & Safety**
- **Zero Unsafe Code** - `#![forbid(unsafe_code)]`.
- **Fail closed** - a store that cannot answer makes the request a guest, and a sign-in fails.
- **Tested** - unit, integration, property, and doc tests, plus fuzz targets for every parser.

---

<br>

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
gatekeeper-io = "0.7"

# With web-net:
gatekeeper-io = { version = "0.7", features = ["web-net"] }
```

**Feature Recommendations**:
- **Minimal**: no features; call `authenticate` and `authorize` from your own server.
- **web-net sites**: `web-net`.
- **Windows without NASM**: `prebuilt-nasm` (crypt-io's code and signature checks use AWS-LC).

---

<br>

## Quick Start

```rust
use gatekeeper_io::*;

// Boot
let schema = Schema::builder("web")
    .permissions(&["post.read", "post.write"])
    .role("member", &["post.read"])
    .role("author", &["post.write"]).inherits("member")
    .build()?;
let write = Rule::signed_in().needs(&schema, &["post.write"])?;
let gk = Gatekeeper::builder(schema, keys_from_vault(&vault, master)?)?
    .identities(identity_store)
    .sessions(session_store)
    .signals(security_bridge)
    .origin("https://example.com")
    .build()?;

// Every request, on the core
let visit = Visit::new(peer).cookie_header(cookie).user_agent(agent);
let identified = gk.authenticate(Inspected::new(), &visit)?;   // banned: 403 here

// In the router, after the route match
let cleared = gk.authorize(identified, &write)?;               // 401 or 403 here
handler(cleared);
```

### **Sign-in and sign-out, with CSRF**

```rust
// GET /login (rule: guests only)
let form = gk.login_form(&cleared, &visit)?;     // token for the hidden field, plus a pre-session cookie
// POST /login
match gk.login(&cleared, &visit, LoginForm { identifier, password, csrf }) {
    Login::SignedIn(s) => { /* 303, with every s.set_cookies() */ }
    Login::SecondFactor(p) => { /* code form carrying p.challenge() */ }
    Login::Failed(f) => { /* the form again with f.message() */ }
}
// POST /logout (rule: signed in)
let out = gk.logout(cleared, &visit, csrf)?;      // 303, with out.set_cookie()
```

### **With web-net**

Enable the `web-net` feature (web-net 0.11) and the `Gatekeeper` is a `web_net::Gate`: routes declare `.allow(rule)` with an access-gate `Rule`, and web-net calls authentication once per request and authorization per route. A cleared session cookie rides on the reply exactly once: through `Identity::set_cookie` for a visitor whose token died, or on the denial when authentication itself refuses (a ban). Authorization denials never repeat it.

### **Where the data comes from**

| Question | Answer |
|---|---|
| what (permissions, roles, attributes) | the service's `Schema`, compiled at boot |
| where (accounts, sessions) | the adapters behind `IdentityStore` and `SessionStore` |
| keys (session MAC, CSRF, pepper, audit) | derived from one master secret in key-vault |
| profile fields rules need | the service's `AttributeSource`, read at sign-in only |

---

## **Status: pre-release**

**Current Version:** `0.7.0` - on web-net 0.11, auth-gate 0.5, and access-gate 0.5.

**What's complete**:
- **Both gates** - authentication on every request, authorization per route and per resource.
- **Sign-in and sign-out** - passwords, TOTP, recovery codes, passkeys, CSRF on both forms.
- **Schema-bound sessions** - a schema or role change ends old sessions instead of remapping them.
- **Audit and signals** - bounded in-memory audit by default, keyed hash chain, signals for every refusal.

**What's planned**:
- The schema as configuration (the same compile step as code).
- A one-call login page and submit.
- Role changes that refresh live sessions instead of ending them.

**Note on API stability**: the API may still change in 0.x minor releases, each with a migration note in the changelog.

---

## **Documentation & Resources**

### **Documentation**
- **[API Reference](docs/API.md)** - every public item
- **[Performance](docs/PERFORMANCE.md)** - measured costs
- **[Changelog](CHANGELOG.md)** - every release, with migration notes

### **External Resources**
- **[API Documentation](https://docs.rs/gatekeeper-io)** - rustdoc on docs.rs
- **[Crate Registry](https://crates.io/crates/gatekeeper-io)** - crates.io
- **[Examples](examples/)** - `sign_in.rs` walks a whole sign-in, request by request

### **Common Use Cases**
- **A site with accounts**: `Gatekeeper` with your store adapters, `web-net` feature.
- **An API with bearer tokens**: `Locator::Bearer`.
- **Several services in one process**: one gatekeeper each; a stage from one is refused by another.

---

### **Troubleshooting**

<details>
  <summary><b>Everyone was signed out after an upgrade?</b></summary>
    <p>Sessions carry a fingerprint of the schema. A change to the permission list, the attributes, or what a role grants ends old sessions once, by design. The changelog says when an upgrade does it too.</p>
</details>

<details>
  <summary><b>The build fails on Windows in aws-lc-sys?</b></summary>
    <p>Set <code>AWS_LC_SYS_PREBUILT_NASM=1</code>, or enable the <code>prebuilt-nasm</code> feature.</p>
</details>

<details>
  <summary><b>The session cookie name is refused at build?</b></summary>
    <p>It must start with <code>__Host-</code>, so a sibling subdomain cannot plant one.</p>
</details>

---

### **Version Compatibility**
- **Rust**: 1.85+ (edition 2024)
- **API Stability**: pre-1.0; breaking changes come in 0.x minor releases with migration notes
- **Feature Flags**: `web-net` and `prebuilt-nasm` are independent

### **Development Setup**
```bash
git clone https://github.com/jamesgober/gatekeeper-io.git
cd gatekeeper-io
cargo test --all-features
cargo bench
cargo clippy --all-targets --all-features -- -D warnings
```

## **Contributing**

See [`dev/DIRECTIVES.md`](dev/DIRECTIVES.md) for the engineering standards and the definition of done.

<hr>

<div id="license">
    <h2>License</h2>
    <p><b>gatekeeper-io</b> is dual-licensed under either of:</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>: see <a href="./LICENSE-APACHE" title="Apache-2.0 License">LICENSE-APACHE</a> or <a href="http://www.apache.org/licenses/LICENSE-2.0" title="Apache-2.0 License" target="_blank">apache.org/licenses/LICENSE-2.0</a></li>
        <li><b>MIT License</b>: see <a href="./LICENSE-MIT" title="MIT License">LICENSE-MIT</a> or <a href="https://opensource.org/licenses/MIT" title="MIT License" target="_blank">opensource.org/licenses/MIT</a></li>
    </ul>
    <p>at your option.</p>
    <h3>Contribution</h3>
    <p>Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in <b>gatekeeper-io</b> by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>JAMES GOBER.</strong></sup>
</div>
