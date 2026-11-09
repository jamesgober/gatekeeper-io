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

    /// The `Set-Cookie` that clears a dead session cookie, when the gate
    /// produced one. web-net writes it on the reply.
    fn set_cookie(&self) -> Option<&str> {
        Identified::set_cookie(self)
    }
}

/// The web-net denial for a gate refusal, carrying the refusal's
/// `Set-Cookie` (a cleared session cookie) when it has one. The code is for
/// logs and events.
#[must_use]
pub fn denial(refusal: &Refusal) -> Denial {
    let d = denial_kind(refusal);
    match refusal.set_cookie() {
        Some(c) => d.with_cookie(c),
        None => d,
    }
}

fn denial_kind(refusal: &Refusal) -> Denial {
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

#[cfg(test)]
mod tests {
    use web_net::DenialKind;

    use super::*;

    #[test]
    fn refusals_map_and_keep_their_cookie() {
        let banned = Refusal::new(RefusalKind::Banned { until: None })
            .with_cookie(Some("__Host-sid=; Max-Age=0".into()));
        let d = denial(&banned);
        assert_eq!(d.kind(), DenialKind::Forbidden);
        assert_eq!(d.code(), "gate.banned");
        assert_eq!(d.cookie(), Some("__Host-sid=; Max-Age=0"));

        let sign_in = denial(&Refusal::new(RefusalKind::NeedsSignIn));
        assert_eq!(sign_in.kind(), DenialKind::SignIn);
        assert_eq!(sign_in.cookie(), None);
        let step_up = denial(&Refusal::new(RefusalKind::Forbidden(
            AccessDenial::StaleFactor,
        )));
        assert_eq!(step_up.code(), "gate.step_up");
    }

    #[test]
    fn authorization_denials_carry_no_cookie() {
        let schema = access_gate::Schema::builder("web").build().unwrap();
        let gk = Gatekeeper::builder(schema, auth_gate::GateKeys::derive(&[4; 32]).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let dead = Identified::guest(Some("__Host-sid=; Max-Age=0".into()));
        let refusal = gk.check(&dead, &Rule::signed_in(), None).unwrap_err();
        let d = denial(&refusal);
        assert_eq!(d.kind(), DenialKind::SignIn);
        assert_eq!(d.cookie(), None, "web-net writes Identity::set_cookie once");
    }

    #[test]
    fn identity_hands_web_net_the_cookie() {
        let dead = Identified::guest(Some("__Host-sid=; Max-Age=0".into()));
        assert!(web_net::Identity::is_guest(&dead));
        assert_eq!(dead.set_cookie(), Some("__Host-sid=; Max-Age=0"));
        assert_eq!(
            web_net::Identity::set_cookie(&dead),
            Some("__Host-sid=; Max-Age=0")
        );
        assert_eq!(Identified::guest(None).csrf_binding(), None);
    }
}
