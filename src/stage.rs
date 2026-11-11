//! The stage values a request carries through the gates.
//!
//! A request carries one stage value, and its type says how far it got. The two later stages
//! have no public constructor: only authentication makes an
//! [`Identified`], and only authorization makes a [`Cleared`]. A handler
//! that takes `Cleared` therefore cannot be reached without both gates;
//! skipping one does not compile.
//!
//! ```compile_fail
//! // There is no way to build a Cleared stage outside the gate.
//! let forged = gatekeeper_io::stage::Cleared { };
//! ```

use core::fmt;

use access_gate::Subject;
use auth_gate::{SessionId, UserId};

/// The first stage: the request pipeline in front of the gates marks a
/// request it has parsed and inspected. Anyone can build one, so it asserts
/// nothing by itself; it only fixes the order (authentication takes it).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Inspected {
    _private: (),
}

impl Inspected {
    /// The request has passed inspection.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

/// Who the request is, as authentication decided.
// Kept inline: boxing the subject would allocate on every request.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Identity {
    /// A guest: no session, or one that was no good.
    Guest,
    /// A signed-in session, with the subject authorization will judge.
    Member {
        /// The account.
        user: UserId,
        /// The session's public id.
        session: SessionId,
        /// The subject snapshot from the session record.
        subject: Subject,
    },
}

impl Identity {
    /// Whether it is a guest.
    #[must_use]
    pub const fn is_guest(&self) -> bool {
        matches!(self, Self::Guest)
    }

    /// The subject, for a signed-in session.
    #[must_use]
    pub const fn subject(&self) -> Option<&Subject> {
        match self {
            Self::Guest => None,
            Self::Member { subject, .. } => Some(subject),
        }
    }

    /// The account, for a signed-in session.
    #[must_use]
    pub const fn user(&self) -> Option<UserId> {
        match self {
            Self::Guest => None,
            Self::Member { user, .. } => Some(*user),
        }
    }

    /// The session id, for a signed-in session.
    #[must_use]
    pub const fn session(&self) -> Option<SessionId> {
        match self {
            Self::Guest => None,
            Self::Member { session, .. } => Some(*session),
        }
    }
}

/// Authenticated: the request is a guest or a signed-in session. Only the
/// gate builds one.
#[derive(Clone, PartialEq, Eq)]
pub struct Identified {
    pub(crate) identity: Identity,
    pub(crate) digest: Option<auth_gate::TokenDigest>,
    pub(crate) set_cookie: Option<String>,
    pub(crate) pre: Option<[u8; PRE_LEN]>,
    /// The gatekeeper that issued it (0: no gatekeeper, a starter stub).
    pub(crate) issuer: u64,
}

/// The length of a pre-session cookie's value.
pub(crate) const PRE_LEN: usize = 43;

impl Identified {
    pub(crate) fn guest(set_cookie: Option<String>) -> Self {
        Self {
            identity: Identity::Guest,
            digest: None,
            set_cookie,
            pre: None,
            issuer: 0,
        }
    }

    /// Who.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The subject, for a signed-in session.
    #[must_use]
    pub const fn subject(&self) -> Option<&Subject> {
        self.identity.subject()
    }

    /// Whether it is a guest.
    #[must_use]
    pub const fn is_guest(&self) -> bool {
        self.identity.is_guest()
    }

    /// The account, for a signed-in session.
    #[must_use]
    pub const fn user(&self) -> Option<UserId> {
        self.identity.user()
    }

    /// A `Set-Cookie` value the response must carry: the gate clears a
    /// cookie whose token can never work again. Write it once per reply,
    /// whatever authorization decides: authorization refusals do not repeat
    /// it. Read it before passing the stage to a consuming
    /// [`Gatekeeper::authorize`](crate::Gatekeeper::authorize).
    #[must_use]
    pub fn set_cookie(&self) -> Option<&str> {
        self.set_cookie.as_deref()
    }

    /// The value CSRF tokens are bound to: the session's public id when
    /// signed in, the pre-session cookie's value for a guest who has one.
    #[must_use]
    pub fn csrf_binding(&self) -> Option<&[u8]> {
        match &self.identity {
            Identity::Member { session, .. } => Some(session.as_bytes()),
            Identity::Guest => self.pre.as_ref().map(<[u8; PRE_LEN]>::as_slice),
        }
    }
}

impl fmt::Debug for Identified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identified")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// Authorized for the matched route (and resource). Only the gate builds
/// one; handlers take it.
///
/// It proves that this gatekeeper cleared the request for *a* rule, not
/// which one: a `Cleared` from a public rule satisfies any handler's
/// signature. Keep each handler next to the rule its route declares (the
/// router does), or check the rule inside the handler with
/// [`Gatekeeper::check`](crate::Gatekeeper::check).
#[derive(Clone, PartialEq, Eq)]
pub struct Cleared {
    pub(crate) inner: Identified,
}

impl Cleared {
    /// Who.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.inner.identity
    }

    /// The subject, for a signed-in session.
    #[must_use]
    pub const fn subject(&self) -> Option<&Subject> {
        self.inner.subject()
    }

    /// Whether it is a guest.
    #[must_use]
    pub const fn is_guest(&self) -> bool {
        self.inner.is_guest()
    }

    /// The account, for a signed-in session.
    #[must_use]
    pub const fn user(&self) -> Option<UserId> {
        self.inner.user()
    }

    /// A `Set-Cookie` value the response must carry, if any.
    #[must_use]
    pub fn set_cookie(&self) -> Option<&str> {
        self.inner.set_cookie()
    }
}

impl fmt::Debug for Cleared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cleared")
            .field("identity", &self.inner.identity)
            .finish_non_exhaustive()
    }
}
