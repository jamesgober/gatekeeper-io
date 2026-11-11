# gatekeeper-io: Plan

> Design and decision record. Read order: [`../REPS.md`](../REPS.md), [`DIRECTIVES.md`](./DIRECTIVES.md), this file, [`ROADMAP.md`](./ROADMAP.md).

## 1. Purpose

gatekeeper-io is the package that joins auth-gate and access-gate: stage types, sign-in and sign-out with CSRF, cookies, standing changes, audit, and keys from key-vault.

## 2. Decisions

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-11-08 | The umbrella joins auth-gate and access-gate; each stays usable alone | single-purpose crates, one package for the server |
| D-002 | 2026-11-08 | The gate owns the stage values; the request type is generic over them; `Identified` and `Cleared` have no public constructor | skipping a gate fails to compile, without the gate knowing the request type |
| D-003 | 2026-11-08 | The permission set, tenant, and attributes are packed into the session payload at sign-in (172 bytes at most) | authorization reads memory only |
| D-004 | 2026-11-08 | The login form's CSRF token is bound to a `__Host-pre` cookie of 32 random bytes, with nothing stored on the server | login CSRF stopped without letting visitors fill the session store |
| D-005 | 2026-11-08 | Signed-in CSRF tokens are bound to the session's public id | a token from another session never works |
| D-006 | 2026-11-08 | A role change ends the account's sessions | the next sign-in carries the new permissions; no stale grant survives |
| D-007 | 2026-11-08 | Audit is an audit-trail chain under keyed BLAKE3, behind the `AuditLog` trait; failed appends are counted | tamper-evident without the key; a health check can alert |
| D-008 | 2026-11-08 | Access denials and CSRF refusals are signals too | a burst of denials across object ids is how enumeration looks |
| D-009 | 2026-11-08 | The session cookie name must carry the `__Host-` prefix, checked at build | a sibling subdomain cannot plant a session |
| D-010 | 2026-11-08 | web-net's `Gate` and `Identity` are implemented here behind the `web-net` feature, through a non-consuming `check` | web-net keeps its own proof (its handler context) and takes the identity by reference; the router needs no clone |
| D-011 | 2026-11-08 | Stage values are `Send + Sync + Clone + 'static` and borrow nothing from the request | the request slot carries them from the core to the router, across threads |
| D-012 | 2026-11-09 | Follow web-net 0.7: the cleared session cookie travels through `Identity::set_cookie` and `Denial::with_cookie`; a gateway in front writes it itself for the services it fronts | one writer per path, exactly once per reply |
| D-013 | 2026-11-09 | Only authentication refusals carry a `Set-Cookie`; authorization refusals never repeat the identity's | one source per reply: the identity's cookie was written twice on a refused route (found in end-to-end testing) |
| D-014 | 2026-11-11 | Payload v2 carries the schema fingerprint; a mismatch ends the session (re-deriving from roles is the 0.6 refresh item) | positional bits remapped live sessions after a schema edit |
| D-015 | 2026-11-11 | Each gatekeeper has a random id stamped into its stages; foreign members are refused, foreign guests stay guests | hardening |
| D-016 | 2026-11-11 | Default audit is a bounded ring; factor changes audited through the gatekeeper; audit key under its own label | hardening |
