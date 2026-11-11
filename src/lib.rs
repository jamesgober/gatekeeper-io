//! # gatekeeper_io
//!
//! The gates, in one package: **authentication** on the core for every
//! request (auth-gate), **authorization** in the router after the route
//! match (access-gate), and around them sign-in and sign-out, CSRF on both
//! (csrf-sec), cookies (cookie-net), standing changes, audit (audit-trail),
//! keys from key-vault, and security signals to the bridge.
//!
//! ## The stages
//!
//! A request carries one stage value. [`Inspected`] comes from the
//! request pipeline; [`Identified`] only from [`Authenticator::authenticate`];
//! [`Cleared`] only from [`Gatekeeper::authorize`]. Handlers take
//! `Cleared`, so a handler cannot run without both gates.
//!
//! ## Tier 1
//!
//! ```
//! use std::sync::Arc;
//! use gatekeeper_io::*;
//!
//! // Boot: the service's schema, its rules, and the gatekeeper.
//! let schema = Schema::builder("web")
//!     .permissions(&["post.read", "post.write"])
//!     .role("member", &["post.read"])
//!     .role("author", &["post.write"]).inherits("member")
//!     .build()?;
//! let write = Rule::signed_in().needs(&schema, &["post.write"])?;
//! let login_page = Rule::guest_only();
//! let gk = Gatekeeper::builder(schema, GateKeys::derive(&[7u8; 32])?)?
//!     .password_policy(PasswordPolicy::insecure_for_tests())  // fast, for this example only
//!     .build()?;
//! gk.create_account("alice@example.com", "correct horse battery", Standing::Active, &["author"])?;
//!
//! // GET /login: the core identifies a guest, the router clears it for the form.
//! let peer = "192.0.2.10".parse().unwrap();
//! let get = Visit::new(peer);
//! let guest = gk.authorize(gk.authenticate(Inspected::new(), &get)?, &login_page)?;
//! let form = gk.login_form(&guest, &get)?;
//!
//! // POST /login with the form's token and the pre-session cookie it set.
//! let cookie = form.set_cookie().unwrap().split(';').next().unwrap().to_owned();
//! let post = Visit::new(peer).method(b"POST").cookie_header(Some(cookie.as_bytes()));
//! let guest = gk.authorize(gk.authenticate(Inspected::new(), &post)?, &login_page)?;
//! let fields = LoginForm { identifier: "alice@example.com", password: "correct horse battery", csrf: form.token().as_bytes() };
//! let Login::SignedIn(signed_in) = gk.login(&guest, &post, fields) else { unreachable!() };
//!
//! // The next request: signed in, and allowed to write.
//! let session = signed_in.set_cookies().next().unwrap().split(';').next().unwrap().to_owned();
//! let next = Visit::new(peer).cookie_header(Some(session.as_bytes()));
//! let cleared = gk.authorize(gk.authenticate(Inspected::new(), &next)?, &write)?;
//! assert_eq!(cleared.user(), Some(signed_in.user()));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Where the data comes from
//!
//! The gatekeeper has no database and no hard-coded schema. The service
//! declares a [`Schema`] (what), configuration picks the store adapters
//! behind [`IdentityStore`] and [`SessionStore`] (where), and key-vault
//! holds the master secret every gate key is derived from
//! ([`keys_from_vault`]). Every request reads memory only.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod audit;
mod gatekeeper;
mod keys;
mod refusal;
pub mod stage;
mod subject;
mod visit;
#[cfg(feature = "web-net")]
#[cfg_attr(docsrs, doc(cfg(feature = "web-net")))]
pub mod web;

pub use access_gate::{
    self, Attrs, Audience, Condition, DenialKind, Perm, PermSet, Resource, Rule, Schema,
    SchemaError, Status, Subject,
};
pub use auth_gate::{
    self, Actor, AuthError, ClientChange, Clock, Decision, GateKeys, IdentityStore, LockoutPolicy,
    ManualClock, MemoryIdentities, MemorySessions, MemorySignals, PasswordPolicy, RelyingParty,
    SessionPolicy, SessionStore, Signal, SignalKind, SignalSink, Standing, StoreError, UnixTime,
    UserId,
};

pub use crate::{
    audit::{
        AuditAction, AuditEvent, AuditLog, ChainAudit, KeyedBlake3, MEMORY_AUDIT_RECORDS, RingSink,
    },
    gatekeeper::{
        AttributeSource, Authenticator, CodeForm, EveryoneGuest, FormToken, Gatekeeper,
        GatekeeperBuilder, Login, LoginFailed, LoginFailure, LoginForm, PRE_SESSION_COOKIE,
        PasskeyForm, SecondFactor, SignedIn, SignedOut,
    },
    keys::keys_from_vault,
    refusal::{Refusal, RefusalKind},
    stage::{Cleared, Identified, Identity, Inspected},
    visit::{DEFAULT_COOKIE, Locator, Visit},
};

#[doc(hidden)]
pub use crate::subject::{__decode_payload, __encode_payload};

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
