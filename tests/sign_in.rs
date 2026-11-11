//! The sign-in scenario end to end with in-memory stores: sign in
//! and out, forged and expired tokens refused, CSRF on login and logout,
//! bans at the core, 401 and 403 at the router, and audit.

use std::{net::IpAddr, sync::Arc, time::Duration};

use gatekeeper_io::*;

const PW: &str = "correct horse battery staple";
const ORIGIN: &str = "https://example.com";

struct Site {
    gk: Gatekeeper,
    clock: Arc<ManualClock>,
    signals: Arc<MemorySignals>,
    audit: Arc<ChainAudit<RingSink>>,
    read: Rule,
    write: Rule,
    edit: Rule,
    login: Rule,
    logout: Rule,
}

fn site() -> Site {
    let schema = Schema::builder("web")
        .permissions(&[
            "post.read",
            "post.write",
            "post.edit.any",
            "user.manage",
            "page.read",
        ])
        .guest_grants(&["page.read"])
        .attribute("org_id")
        .role("member", &["post.read"])
        .role("author", &["post.write"])
        .inherits("member")
        .role("editor", &["post.edit.any"])
        .inherits("author")
        .build()
        .unwrap();
    let read = Rule::guest().needs(&schema, &["post.read"]).unwrap();
    let write = Rule::signed_in().needs(&schema, &["post.write"]).unwrap();
    let edit = write.owner_or(&schema, &["post.edit.any"]).unwrap();
    let clock = Arc::new(ManualClock::new(UnixTime::from_secs(1_800_000_000)));
    let signals = Arc::new(MemorySignals::default());
    let audit = Arc::new(ChainAudit::memory([3; 32], clock.clone()));
    let gk = Gatekeeper::builder(schema, GateKeys::derive(&[11; 32]).unwrap())
        .unwrap()
        .password_policy(PasswordPolicy::insecure_for_tests())
        .clock(clock.clone())
        .signals(signals.clone())
        .audit(audit.clone())
        .origin(ORIGIN)
        .build()
        .unwrap();
    Site {
        gk,
        clock,
        signals,
        audit,
        read,
        write,
        edit,
        login: Rule::guest_only(),
        logout: Rule::signed_in().allow_pending().allow_suspended(),
    }
}

fn peer() -> IpAddr {
    "198.51.100.20".parse().unwrap()
}

/// The `name=value` part of a `Set-Cookie`.
fn pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_owned()
}

/// A browser: remembers cookies, sends same-origin fetch metadata.
#[derive(Default, Clone)]
struct Browser {
    jar: Vec<String>,
}

impl Browser {
    fn take(&mut self, set_cookie: &str) {
        let p = pair(set_cookie);
        let name = p.split('=').next().unwrap().to_owned();
        self.jar.retain(|c| !c.starts_with(&format!("{name}=")));
        if !set_cookie.contains("Expires=Thu, 01 Jan 1970") {
            self.jar.push(p);
        }
    }

    fn header(&self) -> String {
        self.jar.join("; ")
    }
}

fn get(cookies: &str) -> Visit<'_> {
    Visit::new(peer())
        .cookie_header((!cookies.is_empty()).then_some(cookies.as_bytes()))
        .user_agent(Some(b"Mozilla/5.0 (step7)"))
}

fn post(cookies: &str) -> Visit<'_> {
    get(cookies)
        .method(b"POST")
        .fetch_site(Some(b"same-origin"))
        .origin(Some(ORIGIN.as_bytes()))
}

fn sign_in(s: &Site, b: &mut Browser, who: &str, pw: &str) -> Login {
    let h = b.header();
    let page =
        s.gk.authorize(
            s.gk.authenticate(Inspected::new(), &get(&h)).unwrap(),
            &s.login,
        )
        .unwrap();
    let form = s.gk.login_form(&page, &get(&h)).unwrap();
    if let Some(c) = form.set_cookie() {
        b.take(c);
    }
    let h = b.header();
    let v = post(&h);
    let page =
        s.gk.authorize(s.gk.authenticate(Inspected::new(), &v).unwrap(), &s.login)
            .unwrap();
    let out = s.gk.login(
        &page,
        &v,
        LoginForm {
            identifier: who,
            password: pw,
            csrf: form.token().as_bytes(),
        },
    );
    if let Login::SignedIn(si) = &out {
        for c in si.set_cookies() {
            b.take(c);
        }
    }
    out
}

fn identify(s: &Site, b: &Browser) -> Result<Identified, Refusal> {
    let h = b.header();
    s.gk.authenticate(Inspected::new(), &get(&h))
}

#[test]
fn sign_in_then_sign_out() {
    let s = site();
    let alice =
        s.gk.create_account("alice@example.com", PW, Standing::Active, &["author"])
            .unwrap();
    let mut b = Browser::default();
    let Login::SignedIn(si) = sign_in(&s, &mut b, "alice@example.com", PW) else {
        panic!()
    };
    assert_eq!(si.user(), alice);
    assert!(b.jar.iter().any(|c| c.starts_with("__Host-sid=")));
    assert!(
        !b.jar.iter().any(|c| c.starts_with("__Host-pre=")),
        "pre-session cookie cleared"
    );

    // Signed in: the subject carries the compiled permissions.
    let id = identify(&s, &b).unwrap();
    assert_eq!(id.user(), Some(alice));
    let cleared = s.gk.authorize(id, &s.write).unwrap();
    assert!(cleared.subject().unwrap().perms().covers(s.write.need()));

    // Sign out, with the session's CSRF token.
    let token = s.gk.csrf_token(&cleared).unwrap();
    let h = b.header();
    let v = post(&h);
    let page =
        s.gk.authorize(s.gk.authenticate(Inspected::new(), &v).unwrap(), &s.logout)
            .unwrap();
    let out = s.gk.logout(page, &v, token.as_bytes()).unwrap();
    b.take(out.set_cookie().unwrap());
    assert!(b.jar.is_empty());

    // The old cookie, replayed, is a guest now.
    let mut replay = Browser::default();
    replay.jar.push(pair(si.set_cookies().next().unwrap()));
    let id = identify(&s, &replay).unwrap();
    assert!(id.is_guest());
    assert!(id.set_cookie().is_some(), "dead cookie is cleared");
    assert_eq!(s.gk.authorize(id, &s.write).unwrap_err().status(), 401);

    let actions = s.audit.actions();
    assert_eq!(
        actions,
        ["auth.account.created", "auth.sign_in", "auth.sign_out"]
    );
}

#[test]
fn forged_and_expired_tokens_are_refused() {
    let s = site();
    s.gk.create_account("a@x.io", PW, Standing::Active, &["member"])
        .unwrap();
    let mut b = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut b, "a@x.io", PW) else {
        panic!()
    };

    let real = b.jar[0].clone();
    let mut forged = real.clone().into_bytes();
    let i = forged.len() - 30;
    forged[i] = if forged[i] == b'A' { b'B' } else { b'A' };
    let forged = Browser {
        jar: vec![String::from_utf8(forged).unwrap()],
    };
    let id = identify(&s, &forged).unwrap();
    assert!(id.is_guest());
    assert_eq!(*s.signals.kinds().last().unwrap(), SignalKind::ForgedToken);

    let garbage = Browser {
        jar: vec!["__Host-sid=not-a-token".into()],
    };
    assert!(identify(&s, &garbage).unwrap().is_guest());
    assert_eq!(
        *s.signals.kinds().last().unwrap(),
        SignalKind::MalformedToken
    );

    // A planted duplicate cookie never picks one.
    let planted = Browser {
        jar: vec![real.clone(), real.clone()],
    };
    assert!(identify(&s, &planted).unwrap().is_guest());

    // Expired: 30 idle minutes.
    s.clock.advance(Duration::from_secs(31 * 60));
    let id = identify(&s, &b).unwrap();
    assert!(id.is_guest());
    assert_eq!(
        *s.signals.kinds().last().unwrap(),
        SignalKind::ExpiredSession
    );
}

#[test]
fn csrf_on_login() {
    let s = site();
    s.gk.create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let mut b = Browser::default();
    let h = b.header();
    let page =
        s.gk.authorize(
            s.gk.authenticate(Inspected::new(), &get(&h)).unwrap(),
            &s.login,
        )
        .unwrap();
    let form = s.gk.login_form(&page, &get(&h)).unwrap();
    b.take(form.set_cookie().unwrap());
    let h = b.header();
    let fields = |csrf: &'static [u8]| LoginForm {
        identifier: "a@x.io",
        password: PW,
        csrf,
    };
    let cleared = |v: &Visit<'_>| {
        s.gk.authorize(s.gk.authenticate(Inspected::new(), v).unwrap(), &s.login)
            .unwrap()
    };

    // No token, a forged token.
    let v = post(&h);
    let Login::Failed(f) = s.gk.login(&cleared(&v), &v, fields(b"")) else {
        panic!()
    };
    assert_eq!(f.reason(), LoginFailure::Csrf);
    let Login::Failed(f) = s.gk.login(
        &cleared(&v),
        &v,
        fields(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ) else {
        panic!()
    };
    assert_eq!(f.reason(), LoginFailure::Csrf);

    // A real token without the cookie it is bound to (login CSRF: the
    // attacker's own token posted from the victim's browser).
    let token: &'static str = Box::leak(form.token().to_owned().into_boxed_str());
    let bare = post("");
    let Login::Failed(f) = s.gk.login(&cleared(&bare), &bare, fields(token.as_bytes())) else {
        panic!()
    };
    assert_eq!(f.reason(), LoginFailure::Csrf);

    // A cross-site post with a real token and cookie.
    let cross = get(&h)
        .method(b"POST")
        .fetch_site(Some(b"cross-site"))
        .origin(Some(b"https://evil.example"));
    let Login::Failed(f) =
        s.gk.login(&cleared(&cross), &cross, fields(token.as_bytes()))
    else {
        panic!()
    };
    assert_eq!(f.reason(), LoginFailure::Csrf);
    assert!(s.signals.kinds().contains(&SignalKind::CsrfRejected));

    // Same page, same origin: signs in.
    assert!(matches!(
        s.gk.login(&cleared(&v), &v, fields(token.as_bytes())),
        Login::SignedIn(_)
    ));
}

#[test]
fn csrf_on_logout() {
    let s = site();
    s.gk.create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let mut b = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut b, "a@x.io", PW) else {
        panic!()
    };
    let h = b.header();
    let v = post(&h);
    let page = || {
        s.gk.authorize(s.gk.authenticate(Inspected::new(), &v).unwrap(), &s.logout)
            .unwrap()
    };

    // Forced logout from another site, or with no token: refused, still signed in.
    let err = s.gk.logout(page(), &v, b"").unwrap_err();
    assert_eq!((err.kind(), err.status()), (RefusalKind::Csrf, 403));
    let cross = get(&h).method(b"POST").fetch_site(Some(b"cross-site"));
    let token = s.gk.csrf_token(&page()).unwrap();
    let cross_page =
        s.gk.authorize(
            s.gk.authenticate(Inspected::new(), &cross).unwrap(),
            &s.logout,
        )
        .unwrap();
    assert!(s.gk.logout(cross_page, &cross, token.as_bytes()).is_err());
    assert!(!identify(&s, &b).unwrap().is_guest());

    // A token from another session does not work either.
    let mut other = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut other, "a@x.io", PW) else {
        panic!()
    };
    let oh = other.header();
    let other_page =
        s.gk.authorize(
            s.gk.authenticate(Inspected::new(), &get(&oh)).unwrap(),
            &s.logout,
        )
        .unwrap();
    let other_token = s.gk.csrf_token(&other_page).unwrap();
    assert!(s.gk.logout(page(), &v, other_token.as_bytes()).is_err());

    assert!(s.gk.logout(page(), &v, token.as_bytes()).is_ok());
    assert!(identify(&s, &b).unwrap().is_guest());
    // Guests cannot log out (the rule refuses them first).
    let err =
        s.gk.authorize(identify(&s, &b).unwrap(), &s.logout)
            .unwrap_err();
    assert_eq!(err.status(), 401);
}

#[test]
fn wrong_password_and_unknown_account_look_the_same() {
    let s = site();
    s.gk.create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let mut b = Browser::default();
    let Login::Failed(wrong) = sign_in(&s, &mut b, "a@x.io", "not the password") else {
        panic!()
    };
    let mut b = Browser::default();
    let Login::Failed(nobody) = sign_in(&s, &mut b, "nobody@x.io", PW) else {
        panic!()
    };
    assert_eq!(wrong.message(), nobody.message());
    assert_ne!(
        wrong.reason(),
        nobody.reason(),
        "the reason is kept for audit"
    );
    assert_eq!(
        s.audit
            .actions()
            .iter()
            .filter(|a| *a == "auth.sign_in.failed")
            .count(),
        2
    );
}

#[test]
fn bans_are_refused_at_the_core() {
    let s = site();
    let a =
        s.gk.create_account("a@x.io", PW, Standing::Active, &[])
            .unwrap();
    let mut b = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut b, "a@x.io", PW) else {
        panic!()
    };
    let admin = UserId::from_u128(99);
    let until = s.clock.now() + Duration::from_secs(3600);
    s.gk.set_standing(
        a,
        Standing::Banned {
            until,
            decision: Decision::new("abuse", Actor::Admin(admin), s.clock.now()),
        },
        Actor::Admin(admin),
    )
    .unwrap();
    // The ban ended the session; the old cookie is a guest.
    assert!(identify(&s, &b).unwrap().is_guest());
    // And signing in again is refused with the uniform message.
    let mut b = Browser::default();
    assert!(matches!(
        sign_in(&s, &mut b, "a@x.io", PW),
        Login::Failed(_)
    ));
    assert!(
        s.audit
            .actions()
            .contains(&"auth.standing.changed".to_owned())
    );
}

#[test]
fn ban_written_by_another_node_refuses_at_recheck() {
    let s = site();
    let a =
        s.gk.create_account("a@x.io", PW, Standing::Active, &[])
            .unwrap();
    let mut b = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut b, "a@x.io", PW) else {
        panic!()
    };
    s.gk.auth()
        .identities()
        .set_standing(
            a,
            Standing::BannedPermanent {
                decision: Decision::new("x", Actor::System, s.clock.now()),
            },
        )
        .unwrap();
    s.clock.advance(Duration::from_secs(5 * 60));
    let err = identify(&s, &b).unwrap_err();
    assert_eq!(err.kind(), RefusalKind::Banned { until: None });
    assert_eq!(err.status(), 403);
    assert!(err.set_cookie().is_some());
}

#[test]
fn router_statuses_and_object_checks() {
    let s = site();
    let author =
        s.gk.create_account("author@x.io", PW, Standing::Active, &["author"])
            .unwrap();
    s.gk.create_account("member@x.io", PW, Standing::Active, &["member"])
        .unwrap();
    s.gk.create_account("editor@x.io", PW, Standing::Active, &["editor"])
        .unwrap();

    // Guests: public read needs post.read, which guests lack: 401.
    let guest = Browser::default();
    assert_eq!(
        s.gk.authorize(identify(&s, &guest).unwrap(), &s.read)
            .unwrap_err()
            .status(),
        401
    );
    assert!(
        s.gk.authorize(identify(&s, &guest).unwrap(), &Rule::guest())
            .is_ok()
    );
    let page = Rule::guest().needs(s.gk.schema(), &["page.read"]).unwrap();
    assert!(
        s.gk.authorize(identify(&s, &guest).unwrap(), &page).is_ok(),
        "guest grants"
    );

    let mut m = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut m, "member@x.io", PW) else {
        panic!()
    };
    assert!(s.gk.authorize(identify(&s, &m).unwrap(), &s.read).is_ok());
    let err =
        s.gk.authorize(identify(&s, &m).unwrap(), &s.write)
            .unwrap_err();
    assert_eq!(err.status(), 403);
    assert_eq!(
        err.kind(),
        RefusalKind::Forbidden(DenialKind::MissingPermission)
    );
    let err =
        s.gk.authorize(identify(&s, &m).unwrap(), &s.login)
            .unwrap_err();
    assert_eq!(err.kind(), RefusalKind::GuestOnly);
    assert!(s.signals.kinds().contains(&SignalKind::AccessDenied));

    let mine = Resource::new().owner(author.as_u128());
    let mut a = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut a, "author@x.io", PW) else {
        panic!()
    };
    let mut e = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut e, "editor@x.io", PW) else {
        panic!()
    };
    assert!(
        s.gk.authorize_on(identify(&s, &a).unwrap(), &s.edit, &mine)
            .is_ok()
    );
    let theirs = Resource::new().owner(12345);
    assert!(
        s.gk.authorize_on(identify(&s, &a).unwrap(), &s.edit, &theirs)
            .is_err()
    );
    assert!(
        s.gk.authorize_on(identify(&s, &e).unwrap(), &s.edit, &theirs)
            .is_ok()
    );
}

#[test]
fn role_change_ends_sessions() {
    let s = site();
    let a =
        s.gk.create_account("a@x.io", PW, Standing::Active, &["member"])
            .unwrap();
    let mut b = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut b, "a@x.io", PW) else {
        panic!()
    };
    assert!(s.gk.authorize(identify(&s, &b).unwrap(), &s.write).is_err());
    s.gk.set_roles(a, &["author"], Actor::System).unwrap();
    assert!(identify(&s, &b).unwrap().is_guest());
    let mut b = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut b, "a@x.io", PW) else {
        panic!()
    };
    assert!(s.gk.authorize(identify(&s, &b).unwrap(), &s.write).is_ok());
}

#[test]
fn second_factor_through_the_gatekeeper() {
    let s = site();
    let a =
        s.gk.create_account("a@x.io", PW, Standing::Active, &["member"])
            .unwrap();
    let secret = s.gk.auth().enroll_totp(a).unwrap();
    assert!(
        s.gk.auth()
            .confirm_totp(a, &auth_gate::totp_now(&secret, s.clock.now()).unwrap())
            .unwrap()
    );
    s.clock.advance(Duration::from_secs(30));
    let mut b = Browser::default();
    let Login::SecondFactor(pending) = sign_in(&s, &mut b, "a@x.io", PW) else {
        panic!()
    };
    assert!(
        b.jar.iter().any(|c| c.starts_with("__Host-pre=")),
        "pre-session kept for the code form"
    );

    let h = b.header();
    let page =
        s.gk.authorize(
            s.gk.authenticate(Inspected::new(), &get(&h)).unwrap(),
            &s.login,
        )
        .unwrap();
    let form = s.gk.login_form(&page, &get(&h)).unwrap();
    let v = post(&h);
    let page =
        s.gk.authorize(s.gk.authenticate(Inspected::new(), &v).unwrap(), &s.login)
            .unwrap();
    let code = auth_gate::totp_now(&secret, s.clock.now()).unwrap();
    let out = s.gk.second_factor(
        &page,
        &v,
        CodeForm {
            challenge: pending.challenge(),
            code: &code,
            csrf: form.token().as_bytes(),
        },
    );
    let Login::SignedIn(si) = out else {
        panic!("{out:?}")
    };
    for c in si.set_cookies() {
        b.take(c);
    }
    let id = identify(&s, &b).unwrap();
    assert!(id.subject().unwrap().factor_at().is_some());
}

#[test]
fn cookie_crumbs_are_read_and_duplicates_refused() {
    let s = site();
    s.gk.create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let mut b = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut b, "a@x.io", PW) else {
        panic!()
    };
    let h = b.header();
    assert!(
        !s.gk
            .authenticate(Inspected::new(), &get(&h))
            .unwrap()
            .is_guest()
    );
    // HTTP/2 crumbs: the session cookie in one line, others in another.
    let crumbs: [&[u8]; 3] = [b"theme=dark", h.as_bytes(), b"lang=en"];
    let split = get("").cookie_lines(&crumbs);
    assert!(
        !s.gk
            .authenticate(Inspected::new(), &split)
            .unwrap()
            .is_guest(),
        "crumbs are one header"
    );
    // The session cookie planted again in another line: never pick one.
    let planted = format!("{h}; x=1");
    let tossed: [&[u8]; 2] = [h.as_bytes(), planted.as_bytes()];
    let tossed = get("").cookie_lines(&tossed);
    assert!(
        s.gk.authenticate(Inspected::new(), &tossed)
            .unwrap()
            .is_guest()
    );
}

#[test]
fn csrf_binding_follows_the_visitor() {
    let s = site();
    s.gk.create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    assert_eq!(
        identify(&s, &Browser::default()).unwrap().csrf_binding(),
        None
    );
    let mut b = Browser::default();
    let h = b.header();
    let page =
        s.gk.authorize(
            s.gk.authenticate(Inspected::new(), &get(&h)).unwrap(),
            &s.login,
        )
        .unwrap();
    b.take(
        s.gk.login_form(&page, &get(&h))
            .unwrap()
            .set_cookie()
            .unwrap(),
    );
    let guest = identify(&s, &b).unwrap();
    assert_eq!(
        guest.csrf_binding().map(<[u8]>::len),
        Some(43),
        "the pre-session value"
    );
    let mut m = Browser::default();
    let Login::SignedIn(_) = sign_in(&s, &mut m, "a@x.io", PW) else {
        panic!()
    };
    let member = identify(&s, &m).unwrap();
    assert_eq!(
        member.csrf_binding().map(<[u8]>::len),
        Some(16),
        "the session id"
    );
    // The check does not consume the stage.
    assert!(s.gk.check(&member, &Rule::signed_in(), None).is_ok());
    assert_eq!(
        s.gk.check(&guest, &Rule::signed_in(), None)
            .unwrap_err()
            .status(),
        401
    );
}

/// A forged cookie on a signed-in route: the clearing cookie comes from the
/// identity once, never again on the authorization refusal.
#[test]
fn the_clearing_cookie_is_written_once() {
    let s = site();
    let forged = Browser {
        jar: vec![format!("__Host-sid={}", "A".repeat(67))],
    };
    let id = identify(&s, &forged).unwrap();
    assert!(
        id.set_cookie().is_some(),
        "authentication clears the dead cookie"
    );
    let err = s.gk.check(&id, &s.write, None).unwrap_err();
    assert_eq!(err.status(), 401);
    assert_eq!(err.set_cookie(), None, "not repeated by the check");
    let err = s.gk.authorize(id, &s.write).unwrap_err();
    assert_eq!(err.set_cookie(), None, "not repeated by authorize");
}

#[test]
fn everyone_guest_stub() {
    let id = EveryoneGuest
        .authenticate(
            Inspected::new(),
            &Visit::new(peer()).cookie_header(Some(b"__Host-sid=x")),
        )
        .unwrap();
    assert!(id.is_guest());
}

#[test]
fn audit_chain_verifies() {
    let s = site();
    s.gk.create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let mut b = Browser::default();
    let _ = sign_in(&s, &mut b, "a@x.io", PW);
    let _ = sign_in(&s, &mut Browser::default(), "a@x.io", "nope nope nope");
    let records = s.audit.records();
    assert_eq!(records.len(), 3);
    assert_eq!(s.audit.failures(), 0);
    let mut v = audit_trail::Verifier::new(KeyedBlake3::new([3; 32]));
    for r in &records {
        v.verify(&r.as_record()).unwrap();
    }
    // A different key cannot verify the chain.
    let mut wrong = audit_trail::Verifier::new(KeyedBlake3::new([4; 32]));
    assert!(wrong.verify(&records[0].as_record()).is_err());
}

#[test]
fn keys_come_from_the_vault() {
    // Two nodes, each with its own vault holding the same master secret,
    // derive the same keys: a CSRF token from one verifies on the other.
    let node = |secret: Vec<u8>| {
        let vault = key_vault::KeyVaultBuilder::new().build();
        let h = vault
            .register("gate/master", key_vault::RawKey::new(secret))
            .unwrap();
        keys_from_vault(&vault, h).unwrap()
    };
    assert_eq!(node(vec![11; 32]).csrf_key(), node(vec![11; 32]).csrf_key());
    assert_ne!(node(vec![11; 32]).csrf_key(), node(vec![12; 32]).csrf_key());
    let vault = key_vault::KeyVaultBuilder::new().build();
    let h = vault
        .register("gone", key_vault::RawKey::new(vec![1; 32]))
        .unwrap();
    vault.unregister(h).unwrap();
    assert!(
        keys_from_vault(&vault, h).is_err(),
        "an unknown handle is refused"
    );
}

#[test]
fn session_cookie_needs_host_prefix() {
    let schema = Schema::builder("web").build().unwrap();
    let err = Gatekeeper::builder(schema, GateKeys::derive(&[1; 32]).unwrap())
        .unwrap()
        .locator(Locator::Cookie("sid".into()))
        .build()
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidInput(_)));
}

/// The stages travel in a request slot across threads: owned, shareable,
/// cloneable, no borrow of the request.
#[test]
fn stages_are_send_sync_static_clone() {
    fn check<T: Send + Sync + Clone + 'static>() {}
    check::<Identified>();
    check::<Cleared>();
    check::<Inspected>();
    check::<Refusal>();
}
