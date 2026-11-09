//! Refusals: what stops a request at a gate.

use core::fmt;

use access_gate::{Denial, DenialKind};
use auth_gate::UnixTime;

/// Why a gate refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum RefusalKind {
    /// Authentication: the account is banned (until a time, or for good).
    Banned {
        /// When it lifts.
        until: Option<UnixTime>,
    },
    /// Authorization: the rule needs a signed-in subject.
    NeedsSignIn,
    /// Authorization: the rule is for guests only (already signed in).
    GuestOnly,
    /// Authorization: refused for this reason.
    Forbidden(DenialKind),
    /// A state-changing request failed its CSRF check.
    Csrf,
    /// The gate could not reach its stores; failing closed.
    Unavailable,
}

/// A request stopped at a gate. Send the client only [`status`](Self::status)
/// (and [`set_cookie`](Self::set_cookie) if present); the kind is for logs
/// and audit.
#[derive(Clone, PartialEq, Eq)]
pub struct Refusal {
    kind: RefusalKind,
    set_cookie: Option<String>,
}

impl Refusal {
    pub(crate) const fn new(kind: RefusalKind) -> Self {
        Self {
            kind,
            set_cookie: None,
        }
    }

    pub(crate) fn with_cookie(mut self, cookie: Option<String>) -> Self {
        self.set_cookie = cookie;
        self
    }

    pub(crate) fn from_denial(d: Denial) -> Self {
        Self::new(match d.kind() {
            DenialKind::NeedsSignIn => RefusalKind::NeedsSignIn,
            DenialKind::GuestOnly => RefusalKind::GuestOnly,
            other => RefusalKind::Forbidden(other),
        })
    }

    /// Why.
    #[must_use]
    pub const fn kind(&self) -> RefusalKind {
        self.kind
    }

    /// The HTTP status: 401 when signing in (again) would help, 503 when the
    /// gate could not decide, 403 otherwise.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self.kind {
            RefusalKind::NeedsSignIn | RefusalKind::Forbidden(DenialKind::StaleFactor) => 401,
            RefusalKind::Unavailable => 503,
            _ => 403,
        }
    }

    /// A `Set-Cookie` value the refusal must carry (a cleared session
    /// cookie), if any.
    #[must_use]
    pub fn set_cookie(&self) -> Option<&str> {
        self.set_cookie.as_deref()
    }
}

impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refusal")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self.kind {
            RefusalKind::Banned { .. } => "account banned",
            RefusalKind::NeedsSignIn => "sign-in required",
            RefusalKind::GuestOnly => "for guests only",
            RefusalKind::Forbidden(_) => "forbidden",
            RefusalKind::Csrf => "request forgery check failed",
            RefusalKind::Unavailable => "gate unavailable",
        };
        f.write_str(text)
    }
}

impl std::error::Error for Refusal {}
