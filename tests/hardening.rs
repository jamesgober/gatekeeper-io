//! Regression tests for the 2026-11-11 hardening pass. Each failed
//! before its fix.

use std::{net::IpAddr, sync::Arc};

use gatekeeper_io::*;

const PW: &str = "correct horse battery staple";
const ORIGIN: &str = "https://example.com";

fn peer() -> IpAddr {
    "198.51.100.20".parse().unwrap()
}

fn pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_owned()
}

fn get(cookies: &str) -> Visit<'_> {
    Visit::new(peer())
        .cookie_header((!cookies.is_empty()).then_some(cookies.as_bytes()))
        .user_agent(Some(b"Mozilla/5.0"))
}

fn post(cookies: &str) -> Visit<'_> {
    get(cookies)
        .method(b"POST")
        .fetch_site(Some(b"same-origin"))
        .origin(Some(ORIGIN.as_bytes()))
}

struct Shared {
    ids: Arc<MemoryIdentities>,
    sessions: Arc<MemorySessions>,
    clock: Arc<ManualClock>,
}

fn shared() -> Shared {
    Shared {
        ids: Arc::new(MemoryIdentities::new()),
        sessions: Arc::new(MemorySessions::new()),
        clock: Arc::new(ManualClock::new(UnixTime::from_secs(1_800_000_000))),
    }
}

fn gatekeeper(schema: Schema, s: &Shared) -> Gatekeeper {
    Gatekeeper::builder(schema, GateKeys::derive(&[11; 32]).unwrap())
        .unwrap()
        .password_policy(PasswordPolicy::insecure_for_tests())
        .identities(s.ids.clone())
        .sessions(s.sessions.clone())
        .clock(s.clock.clone())
        .origin(ORIGIN)
        .build()
        .unwrap()
}

fn sign_in(gk: &Gatekeeper, who: &str) -> String {
    let login = Rule::guest_only();
    let page = gk
        .authorize(gk.authenticate(Inspected::new(), &get("")).unwrap(), &login)
        .unwrap();
    let form = gk.login_form(&page, &get("")).unwrap();
    let pre = pair(form.set_cookie().unwrap());
    let v = post(&pre);
    let page = gk
        .authorize(gk.authenticate(Inspected::new(), &v).unwrap(), &login)
        .unwrap();
    let Login::SignedIn(si) = gk.login(
        &page,
        &v,
        LoginForm {
            identifier: who,
            password: PW,
            csrf: form.token().as_bytes(),
        },
    ) else {
        panic!("sign-in failed")
    };
    pair(si.set_cookies().next().unwrap())
}

/// a schema edit (here, alphabetizing the permissions) never remaps a
/// live session: the old session ends and its cookie is cleared.
#[test]
fn test_schema_change_ends_old_sessions() {
    let s = shared();
    let v1 = Schema::builder("web")
        .permissions(&["post.read", "admin.delete"])
        .role("member", &["post.read"])
        .build()
        .unwrap();
    let gk1 = gatekeeper(v1, &s);
    gk1.create_account("eve@x.io", PW, Standing::Active, &["member"])
        .unwrap();
    let cookie = sign_in(&gk1, "eve@x.io");

    let v2 = Schema::builder("web")
        .permissions(&["admin.delete", "post.read"])
        .role("member", &["post.read"])
        .build()
        .unwrap();
    let admin_rule = Rule::signed_in().needs(&v2, &["admin.delete"]).unwrap();
    let gk2 = gatekeeper(v2, &s);
    let who = gk2.authenticate(Inspected::new(), &get(&cookie)).unwrap();
    assert!(
        who.is_guest(),
        "a session from another schema is never read"
    );
    assert!(who.set_cookie().is_some(), "and its cookie is cleared");
    assert_eq!(
        gk2.check(&who, &admin_rule, None).unwrap_err().status(),
        401
    );
    // A fresh sign-in under the new schema works and has the right bits.
    let fresh = sign_in(&gk2, "eve@x.io");
    let who = gk2.authenticate(Inspected::new(), &get(&fresh)).unwrap();
    assert!(gk2.check(&who, &admin_rule, None).is_err());
    let read = Rule::signed_in()
        .needs(gk2.schema(), &["post.read"])
        .unwrap();
    assert!(gk2.check(&who, &read, None).is_ok());
}

/// a stage issued by one gatekeeper is refused by another in the same
/// process, before any bit is read in the wrong schema.
#[test]
fn test_foreign_stage_is_refused() {
    let a = shared();
    let web = Schema::builder("web")
        .permissions(&["post.read"])
        .role("member", &["post.read"])
        .build()
        .unwrap();
    let gk_web = gatekeeper(web, &a);
    gk_web
        .create_account("eve@x.io", PW, Standing::Active, &["member"])
        .unwrap();
    let cookie = sign_in(&gk_web, "eve@x.io");
    let identified = gk_web
        .authenticate(Inspected::new(), &get(&cookie))
        .unwrap();

    let b = shared();
    let admin = Schema::builder("admin")
        .permissions(&["tenant.delete"])
        .build()
        .unwrap();
    let delete_tenant = Rule::signed_in().needs(&admin, &["tenant.delete"]).unwrap();
    let gk_admin = gatekeeper(admin, &b);
    let err = gk_admin
        .authorize(identified.clone(), &delete_tenant)
        .unwrap_err();
    assert_eq!(err.kind(), RefusalKind::ForeignStage);
    assert_eq!(err.status(), 403);
    assert!(
        gk_admin.check(&identified, &Rule::guest(), None).is_err(),
        "even a public rule"
    );
    // Its own gatekeeper still accepts it.
    let read = Rule::signed_in()
        .needs(gk_web.schema(), &["post.read"])
        .unwrap();
    assert!(gk_web.check(&identified, &read, None).is_ok());
}

/// the default audit log is bounded; failed sign-ins cannot grow it
/// without end, and what was dropped is counted.
#[test]
fn test_default_audit_is_bounded() {
    let s = shared();
    let audit = Arc::new(ChainAudit::memory_with_capacity(
        [3; 32],
        s.clock.clone(),
        100,
    ));
    let gk = Gatekeeper::builder(
        Schema::builder("web").build().unwrap(),
        GateKeys::derive(&[11; 32]).unwrap(),
    )
    .unwrap()
    .password_policy(PasswordPolicy::insecure_for_tests())
    .clock(s.clock.clone())
    .audit(audit.clone())
    .origin(ORIGIN)
    .build()
    .unwrap();
    let login = Rule::guest_only();
    let page = gk
        .authorize(gk.authenticate(Inspected::new(), &get("")).unwrap(), &login)
        .unwrap();
    let form = gk.login_form(&page, &get("")).unwrap();
    let pre = pair(form.set_cookie().unwrap());
    let v = post(&pre);
    for i in 0..500 {
        let id = format!("nobody{i}@x.io");
        let page = gk
            .authorize(gk.authenticate(Inspected::new(), &v).unwrap(), &login)
            .unwrap();
        let _ = gk.login(
            &page,
            &v,
            LoginForm {
                identifier: &id,
                password: "whatever1",
                csrf: form.token().as_bytes(),
            },
        );
    }
    assert_eq!(audit.records().len(), 100);
    assert_eq!(audit.dropped(), 400);
    assert_eq!(MEMORY_AUDIT_RECORDS, 10_000, "the default bound");
}

/// factor changes and sign-out everywhere are audited, and a failed
/// sign-in records its source network.
#[test]
fn test_factor_changes_are_audited() {
    let s = shared();
    let audit = Arc::new(ChainAudit::memory([3; 32], s.clock.clone()));
    let gk = Gatekeeper::builder(
        Schema::builder("web").build().unwrap(),
        GateKeys::derive(&[11; 32]).unwrap(),
    )
    .unwrap()
    .password_policy(PasswordPolicy::insecure_for_tests())
    .identities(s.ids.clone())
    .clock(s.clock.clone())
    .audit(audit.clone())
    .origin(ORIGIN)
    .build()
    .unwrap();
    let user = gk
        .create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let secret = gk.enroll_totp(user, Actor::System).unwrap();
    let code = auth_gate::totp_now(&secret, s.clock.now()).unwrap();
    assert!(gk.confirm_totp(user, &code, Actor::System).unwrap());
    let _ = gk.new_recovery_codes(user, Actor::System).unwrap();
    gk.remove_totp(user, Actor::Admin(UserId::from_u128(9)))
        .unwrap();
    assert!(!gk.remove_passkey(user, b"none", Actor::System).unwrap());
    assert_eq!(gk.sign_out_everywhere(user, Actor::System).unwrap(), 0);
    let actions = audit.actions();
    for want in [
        "auth.factor.totp.enrolled",
        "auth.factor.totp.confirmed",
        "auth.factor.recovery.issued",
        "auth.factor.totp.removed",
        "auth.factor.passkey.removed",
        "auth.sign_out.everywhere",
    ] {
        assert!(
            actions.iter().any(|a| a == want),
            "{want} missing from {actions:?}"
        );
    }
    // A failed sign-in names its source network.
    let login = Rule::guest_only();
    let page = gk
        .authorize(gk.authenticate(Inspected::new(), &get("")).unwrap(), &login)
        .unwrap();
    let form = gk.login_form(&page, &get("")).unwrap();
    let pre = pair(form.set_cookie().unwrap());
    let v = post(&pre);
    let page = gk
        .authorize(gk.authenticate(Inspected::new(), &v).unwrap(), &login)
        .unwrap();
    let _ = gk.login(
        &page,
        &v,
        LoginForm {
            identifier: "a@x.io",
            password: "wrong one!",
            csrf: form.token().as_bytes(),
        },
    );
    let last = audit.records().pop().unwrap();
    assert!(
        last.as_record()
            .target()
            .as_str()
            .contains("source=198.51.100.0/24")
    );
}

/// the bearer scheme name is case-insensitive.
#[test]
fn test_bearer_scheme_is_case_insensitive() {
    let s = shared();
    let gk = Gatekeeper::builder(
        Schema::builder("web").build().unwrap(),
        GateKeys::derive(&[11; 32]).unwrap(),
    )
    .unwrap()
    .password_policy(PasswordPolicy::insecure_for_tests())
    .identities(s.ids.clone())
    .sessions(s.sessions.clone())
    .locator(Locator::CookieOrBearer(DEFAULT_COOKIE.into()))
    .origin(ORIGIN)
    .build()
    .unwrap();
    gk.create_account("a@x.io", PW, Standing::Active, &[])
        .unwrap();
    let cookie = sign_in(&gk, "a@x.io");
    let token = cookie.split_once('=').unwrap().1.to_owned();
    for scheme in ["Bearer", "bearer", "BEARER"] {
        let header = format!("{scheme} {token}");
        let v = Visit::new(peer())
            .user_agent(Some(b"Mozilla/5.0"))
            .authorization(Some(header.as_bytes()));
        assert!(
            !gk.authenticate(Inspected::new(), &v).unwrap().is_guest(),
            "{scheme}"
        );
    }
}
