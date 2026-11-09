//! Any Cookie and Authorization header values: never a panic, always a
//! guest (no token this gate issued can appear by chance).
#![no_main]

use std::sync::OnceLock;

use gatekeeper_io::{Authenticator, GateKeys, Gatekeeper, Inspected, Locator, Schema, Visit};
use libfuzzer_sys::fuzz_target;

fn gk() -> &'static Gatekeeper {
    static G: OnceLock<Gatekeeper> = OnceLock::new();
    G.get_or_init(|| {
        let schema = Schema::builder("web").permission("p").build().unwrap();
        Gatekeeper::builder(schema, GateKeys::derive(&[5; 32]).unwrap())
            .unwrap()
            .locator(Locator::CookieOrBearer("__Host-sid".into()))
            .build()
            .unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let cut = data.len() / 2;
    let (cookie, auth) = data.split_at(cut);
    let visit = Visit::new("192.0.2.1".parse().unwrap())
        .cookie_header(Some(cookie))
        .authorization(Some(auth))
        .user_agent(Some(auth));
    match gk().authenticate(Inspected::new(), &visit) {
        Ok(id) => assert!(id.is_guest()),
        Err(_) => panic!("refused without an account"),
    }
});
