<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>gatekeeper-io</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.5.0] - 2026-11-11

Hardening fixes; on auth-gate 0.4 and
access-gate 0.4.

### Fixed

- Session payloads carry the schema fingerprint (payload version 2). A
  session written under another permission list is never read: it ends and
  its cookie is cleared, instead of holding whatever sits at its old bit
  positions (high).
- A stage carries the gatekeeper that issued it; another gatekeeper in the
  same process refuses it (`RefusalKind::ForeignStage`, 403, with a signal).
- The default audit log is a bounded ring (`RingSink`,
  `MEMORY_AUDIT_RECORDS` = 10,000) that counts what it drops.
- Factor and session changes are audited when made through the gatekeeper
  (`enroll_totp`, `confirm_totp`, `remove_totp`, `new_recovery_codes`,
  `register_passkey`, `remove_passkey`, `sign_out_everywhere`); failed
  sign-ins record the source network.
- The audit key is derived from the master secret under its own label, and
  keys are held in `Zeroizing`.
- The bearer scheme name is matched case-insensitively.

### Changed

- `check` reads the clock only when the rule or the subject's standing
  needs it, and the guest pre-session value is held inline.
- `__encode_payload` and `__decode_payload` (fuzzing hooks) take the
  fingerprint.

Existing sessions end once after this upgrade (payload version 2).

See [`docs/release/v0.5.0.md`](./docs/release/v0.5.0.md).

---

## [0.4.1] - 2026-11-09

### Fixed

- A request with a dead session cookie on a route that refused it got the
  clearing `Set-Cookie` twice: once from the identity and again on the
  authorization refusal. Authorization refusals (`check`, `authorize`,
  `authorize_on`) no longer carry a cookie; only authentication refusals
  (a ban) do. Found in end-to-end testing.

See [`docs/release/v0.4.1.md`](./docs/release/v0.4.1.md).

---

## [0.4.0] - 2026-11-09

The `web-net` feature moves to web-net 0.7.

### Changed

- `web-net` now depends on web-net 0.7 (was 0.3). Breaking for users of the
  feature: web-net's `Denial` is `Clone` only.
- `web::denial` attaches the refusal's `Set-Cookie` (a cleared session
  cookie) to the denial with `Denial::with_cookie`.

### Added

- `web_net::Identity::set_cookie` for `Identified`: web-net writes the
  cleared session cookie on the reply.

See [`docs/release/v0.4.0.md`](./docs/release/v0.4.0.md).

---

## [0.3.0] - 2026-11-08

Hardening: property tests for every invariant, fuzz targets for every parser, and benchmarks with measured numbers.

See [`docs/release/v0.3.0.md`](./docs/release/v0.3.0.md).

---

## [0.2.0] - 2026-11-08

Design lock: the public API settled with the neighbouring server and router crates, documented item by item, with examples.

See [`docs/release/v0.2.0.md`](./docs/release/v0.2.0.md).

---

## [0.1.0] - 2026-11-08

First working core: the types, the main path, and the in-memory stores, with unit and integration tests. For gatekeeper-io this includes the end-to-end sign-in scenario: sign in and out, forged and expired tokens refused, CSRF on login and logout.

See [`docs/release/v0.1.0.md`](./docs/release/v0.1.0.md).

