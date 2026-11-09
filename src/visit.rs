//! What the gates read from a request, and where the credential is.

use core::net::IpAddr;

/// The request facts the gates read. The caller copies header values in;
/// the gates never parse a protocol beyond the `Cookie` and
/// `Authorization` values.
///
/// ```
/// use gatekeeper_io::Visit;
///
/// let visit = Visit::new("192.0.2.10".parse().unwrap())
///     .method(b"POST")
///     .cookie_header(Some(b"__Host-sid=abc; theme=dark"))
///     .user_agent(Some(b"Mozilla/5.0"))
///     .fetch_site(Some(b"same-origin"))
///     .origin(Some(b"https://example.com"));
/// # let _ = visit;
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Visit<'a> {
    pub(crate) peer: IpAddr,
    pub(crate) method: &'a [u8],
    pub(crate) cookie: Option<&'a [u8]>,
    pub(crate) authorization: Option<&'a [u8]>,
    pub(crate) user_agent: Option<&'a [u8]>,
    pub(crate) fetch_site: Option<&'a [u8]>,
    pub(crate) origin: Option<&'a [u8]>,
    pub(crate) referer: Option<&'a [u8]>,
    pub(crate) duplicate_cookies: bool,
}

impl<'a> Visit<'a> {
    /// A request from `peer`, method `GET`, no headers yet.
    #[must_use]
    pub const fn new(peer: IpAddr) -> Self {
        Self {
            peer,
            method: b"GET",
            cookie: None,
            authorization: None,
            user_agent: None,
            fetch_site: None,
            origin: None,
            referer: None,
            duplicate_cookies: false,
        }
    }

    /// The request method.
    #[must_use]
    pub const fn method(mut self, method: &'a [u8]) -> Self {
        self.method = method;
        self
    }

    /// The raw `Cookie` header value.
    #[must_use]
    pub const fn cookie_header(mut self, value: Option<&'a [u8]>) -> Self {
        self.cookie = value;
        self
    }

    /// The raw `Authorization` header value.
    #[must_use]
    pub const fn authorization(mut self, value: Option<&'a [u8]>) -> Self {
        self.authorization = value;
        self
    }

    /// The `User-Agent` header value.
    #[must_use]
    pub const fn user_agent(mut self, value: Option<&'a [u8]>) -> Self {
        self.user_agent = value;
        self
    }

    /// The `Sec-Fetch-Site` header value.
    #[must_use]
    pub const fn fetch_site(mut self, value: Option<&'a [u8]>) -> Self {
        self.fetch_site = value;
        self
    }

    /// The `Origin` header value.
    #[must_use]
    pub const fn origin(mut self, value: Option<&'a [u8]>) -> Self {
        self.origin = value;
        self
    }

    /// The `Referer` header value.
    #[must_use]
    pub const fn referer(mut self, value: Option<&'a [u8]>) -> Self {
        self.referer = value;
        self
    }

    /// The request carried more than one `Cookie` field (cookie tossing):
    /// every cookie read is refused, never resolved by picking one.
    #[must_use]
    pub const fn duplicate_cookie_fields(mut self) -> Self {
        self.duplicate_cookies = true;
        self
    }

    /// The client address.
    #[must_use]
    pub const fn peer(&self) -> IpAddr {
        self.peer
    }

    pub(crate) fn cookie(&self, name: &str) -> Located<'a> {
        let Some(header) = self.cookie else {
            return Located::Absent;
        };
        if self.duplicate_cookies {
            return Located::Ambiguous;
        }
        match cookie_net::get_unique(header, name) {
            Ok(Some(v)) => Located::Found(v.as_bytes()),
            Ok(None) => Located::Absent,
            // Planted twice: never pick one.
            Err(_) => Located::Ambiguous,
        }
    }
}

pub(crate) enum Located<'a> {
    Absent,
    Found(&'a [u8]),
    Ambiguous,
}

/// Where the session credential is. Taken from the profile at boot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Locator {
    /// A cookie with this name (`__Host-sid` by default).
    Cookie(String),
    /// `Authorization: Bearer <token>`, for API clients.
    Bearer,
    /// The cookie, or else the bearer header.
    CookieOrBearer(String),
}

impl Default for Locator {
    fn default() -> Self {
        Self::Cookie(DEFAULT_COOKIE.into())
    }
}

/// The default session cookie name. The `__Host-` prefix stops a sibling
/// subdomain from planting one.
pub const DEFAULT_COOKIE: &str = "__Host-sid";

/// A planted duplicate cookie is presented as this, which never verifies,
/// so it becomes a guest with a malformed-token signal.
const AMBIGUOUS: &[u8] = b"ambiguous";

impl Locator {
    pub(crate) fn locate<'a>(&self, visit: &Visit<'a>) -> Option<&'a [u8]> {
        let bearer = || {
            visit.authorization.and_then(|h| {
                let rest = h.strip_prefix(b"Bearer ")?;
                Some(rest.trim_ascii())
            })
        };
        let cookie = |name: &str| match visit.cookie(name) {
            Located::Found(v) => Some(v),
            Located::Ambiguous => Some(AMBIGUOUS),
            Located::Absent => None,
        };
        match self {
            Self::Cookie(name) => cookie(name),
            Self::Bearer => bearer(),
            Self::CookieOrBearer(name) => cookie(name).or_else(bearer),
        }
    }

    pub(crate) fn cookie_name(&self) -> Option<&str> {
        match self {
            Self::Cookie(n) | Self::CookieOrBearer(n) => Some(n),
            Self::Bearer => None,
        }
    }
}
