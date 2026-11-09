# gatekeeper-io: Engineering Directives

> Engineering standards and the definition of done for this project. Read alongside `REPS.md` (root, authoritative), [`PLAN.md`](./PLAN.md) (design and decisions), and [`ROADMAP.md`](./ROADMAP.md) (current phase).

---

## 0. Philosophy

Built and maintained to a production standard. Plan the full path, then build one verified step at a time. A security component that cannot name the attack it stops, and prove it with a test, does not ship.

## 1. What this is

gatekeeper-io is the package that joins auth-gate and access-gate: stage types, sign-in and sign-out with CSRF, cookies, standing changes, audit, and keys from key-vault.

## 2. Engineering law

- **Ours, not rented.** No third-party runtime dependency, except audited cryptographic primitives reached through `crypt-io`. First-party crates at published versions only: no `path` dependency in `Cargo.toml` (a local, untracked `.cargo/config.toml` may patch unpublished siblings for development).
- **Protocol-free.** Adapters translate the wire format; the gates take plain values.
- **Storage-free.** Data lives behind traits; in-memory implementations ship for tests.
- **Fail closed.** When a check cannot run, the answer is no.
- **Never isolated.** Every detection is reported to the security bridge (`SignalSink`).
- **Secrets.** Compared in constant time, wiped after use, never in logs, errors, or `Debug` output.
- **Unsafe.** `#![forbid(unsafe_code)]`.
- **Errors.** Every fallible path returns `Result`; error enums are `#[non_exhaustive]`; no `unwrap`, `expect`, `panic!`, `todo!`, or `dbg!` in library code.
- **Docs.** `#![deny(missing_docs)]`; every public item documented; every claim maps to a test.

## 3. Definition of done

1. `cargo fmt --all -- --check` clean.
2. `cargo clippy --all-targets -- -D warnings` on every feature set, on stable and on MSRV 1.85.
3. `cargo test --all-features` green on stable and 1.85.
4. `cargo doc --no-deps` with `RUSTDOCFLAGS="-D warnings"` clean.
5. `cargo audit` and `cargo deny check` pass.
6. Property tests cover every invariant below; a fuzz target exists for every parser; every threat in `PLAN.md` has a test that must fail to get in.
7. Hot-path changes carry benchmarks.
8. `README.md`, `docs/API.md`, `CHANGELOG.md`, and `docs/release/vX.Y.Z.md` updated.
9. `1.0.0` only with the maintainer's explicit go, after real integration and an adversarial review.

## 4. Invariants

- `Identified` and `Cleared` cannot be built outside the gates.
- No header value yields a signed-in identity without a session this gate issued.
- Sign-in and sign-out fail without a CSRF token bound to the visitor (pre-session cookie or session).
- The payload decoder accepts only what the encoder wrote; anything else is a guest.
- A ban is refused at authentication, before the router.
- Sign-ins, sign-outs, failures, and standing and role changes are audited.

## 5. Writing style

Plain, specific prose. Banned in shipping files: "comprehensive", "robust", "seamless", "leverage", the em-dash character, and emoji.
