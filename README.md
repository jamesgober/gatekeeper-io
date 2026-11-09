<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>gatekeeper-io</b>
    <br>
    <sub><sup>THE GATES, IN ONE PACKAGE</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/gatekeeper-io"><img alt="Crates.io" src="https://img.shields.io/crates/v/gatekeeper-io"></a>
    <a href="https://docs.rs/gatekeeper-io"><img alt="docs.rs" src="https://img.shields.io/docsrs/gatekeeper-io"></a>
    <a href="https://github.com/jamesgober/gatekeeper-io/actions"><img alt="CI" src="https://github.com/jamesgober/gatekeeper-io/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>gatekeeper-io</strong> joins the two gates: <strong>authentication</strong> for every request (auth-gate) and <strong>authorization</strong> in the router after the route match (access-gate), with sign-in and sign-out, CSRF on both (csrf-sec), cookies (cookie-net), standing changes, a tamper-evident audit chain (audit-trail), and keys derived from a master secret in key-vault.
    </p>
    <p>
        A request carries a stage value. <code>Inspected</code> comes from the request pipeline, <code>Identified</code> only from authentication, and <code>Cleared</code> only from authorization. Handlers take <code>Cleared</code>, so skipping a gate does not compile. Every request reads memory only.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>.
    </p>
    <blockquote>
        <strong>Status: <code>0.4.1</code>, pre-release.</strong> Built and tested locally; not yet published. It depends on auth-gate and access-gate, which publish first.
    </blockquote>
</div>

<hr>
<br>

## Installation

```toml
[dependencies]
gatekeeper-io = "0.4"
```

## Usage

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

Sign-in and sign-out, with CSRF:

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

## With web-net

Enable the `web-net` feature (web-net 0.7) and the `Gatekeeper` is a `web_net::Gate`: routes declare `.allow(rule)` with an access-gate `Rule`, and web-net calls authentication once per request and authorization per route. A cleared session cookie rides on the reply exactly once: through `Identity::set_cookie` for a visitor whose token died, or on the denial when authentication itself refuses (a ban). Authorization denials never repeat it.

## Where the data comes from

| Question | Answer |
|---|---|
| what (permissions, roles, attributes) | the service's `Schema`, compiled at boot |
| where (accounts, sessions) | the adapters behind `IdentityStore` and `SessionStore` |
| keys (session MAC, CSRF, pepper, audit) | derived from one master secret in key-vault |
| profile fields rules need | the service's `AttributeSource`, read at sign-in only |

## Documentation

- [`docs/API.md`](./docs/API.md): every public item.
- [`docs/PERFORMANCE.md`](./docs/PERFORMANCE.md): measured costs.
- [`dev/PLAN.md`](./dev/PLAN.md): design and decisions.
- [`CHANGELOG.md`](./CHANGELOG.md).

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, and `cargo doc --no-deps` with `RUSTDOCFLAGS="-D warnings"` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>: <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b>: <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
