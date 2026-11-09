//! The login step with any CSRF token, pre-session cookie, and origin
//! facts: never a panic, never a sign-in (there is no account).
#![no_main]

use std::sync::OnceLock;

use gatekeeper_io::{
    Authenticator, GateKeys, Gatekeeper, Inspected, Login, LoginForm, PasswordPolicy, Rule, Schema,
    Visit,
};
use libfuzzer_sys::fuzz_target;

fn gk() -> &'static Gatekeeper {
    static G: OnceLock<Gatekeeper> = OnceLock::new();
    G.get_or_init(|| {
        let schema = Schema::builder("web").build().unwrap();
        Gatekeeper::builder(schema, GateKeys::derive(&[6; 32]).unwrap())
            .unwrap()
            .password_policy(PasswordPolicy::insecure_for_tests())
            .origin("https://example.com")
            .build()
            .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let q = data.len() / 4;
    let (cookie, rest) = data.split_at(q);
    let (token, rest) = rest.split_at(q.min(rest.len()));
    let (site, origin) = rest.split_at(rest.len() / 2);
    let visit = Visit::new("192.0.2.1".parse().unwrap())
        .method(b"POST")
        .cookie_header(Some(cookie))
        .fetch_site(Some(site))
        .origin(Some(origin));
    let Ok(id) = gk().authenticate(Inspected::new(), &visit) else {
        return;
    };
    let Ok(page) = gk().authorize(id, &Rule::guest_only()) else {
        return;
    };
    let out = gk().login(
        &page,
        &visit,
        LoginForm {
            identifier: "x@y.z",
            password: "irrelevant pw",
            csrf: token,
        },
    );
    assert!(matches!(out, Login::Failed(_)));
});
