//! web-net's gate checkpoints, implemented by the [`Gatekeeper`] (feature
//! `web-net`).
//!
//! web-net authenticates once per request and authorizes each route with
//! the route's [`Rule`]; its handlers receive a context it builds only after
//! authorization passed, so the stage guarantee holds there too.

use core::net::{IpAddr, Ipv4Addr};

use access_gate::{DenialKind as AccessDenial, Rule};
use web_net::{Denial, Request};

use crate::{
    gatekeeper::{Authenticator, Gatekeeper},
    refusal::{Refusal, RefusalKind},
    stage::{Identified, Inspected},
    visit::Visit,
};

impl web_net::Identity for Identified {
    fn is_guest(&self) -> bool {
        Identified::is_guest(self)
    }

    /// The session's public id for a signed-in visitor; the pre-session
    /// cookie's value for a guest who has one.
    fn csrf_binding(&self) -> Option<&[u8]> {
        Identified::csrf_binding(self)
    }
}

/// The web-net denial for a gate refusal. The code is for logs and events.
#[must_use]
pub fn denial(refusal: &Refusal) -> Denial {
    match refusal.kind() {
        RefusalKind::NeedsSignIn => Denial::sign_in("gate.sign_in"),
        RefusalKind::Forbidden(AccessDenial::StaleFactor) => Denial::sign_in("gate.step_up"),
        RefusalKind::GuestOnly => Denial::forbidden("gate.guest_only"),
        RefusalKind::Banned { .. } => Denial::forbidden("gate.banned"),
        RefusalKind::Csrf => Denial::forbidden("gate.csrf"),
        RefusalKind::Unavailable => Denial::forbidden("gate.unavailable"),
        _ => Denial::forbidden("gate.forbidden"),
    }
}

/// The gates' view of a web-net request.
#[must_use]
pub fn visit<'a>(req: &Request<'a>) -> Visit<'a> {
    let peer = req
        .client()
        .addr()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let method: &'static str = req.method().as_str().unwrap_or("EXTENSION");
    let mut v = Visit::new(peer)
        .method(method.as_bytes())
        .cookie_header(req.header("cookie"))
        .authorization(req.header("authorization"))
        .user_agent(req.header("user-agent"))
        .fetch_site(req.header("sec-fetch-site"))
        .origin(req.header("origin"))
        .referer(req.header("referer"));
    if req.raw().head().header_all("cookie").nth(1).is_some() {
        v = v.duplicate_cookie_fields();
    }
    v
}

impl web_net::Gate for Gatekeeper {
    type Identity = Identified;
    type Rule = Rule;

    fn authenticate(&self, req: &Request<'_>) -> Result<Identified, Denial> {
        Authenticator::authenticate(self, Inspected::new(), &visit(req)).map_err(|r| denial(&r))
    }

    fn authorize(&self, who: &Identified, rule: &Rule, _req: &Request<'_>) -> Result<(), Denial> {
        self.check(who, rule, None).map_err(|r| denial(&r))
    }
}
