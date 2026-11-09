//! Invariants for any input.

use std::sync::{Arc, OnceLock};

use gatekeeper_io::*;
use proptest::prelude::*;

fn gk() -> &'static Gatekeeper {
    static G: OnceLock<Gatekeeper> = OnceLock::new();
    G.get_or_init(|| {
        let schema = Schema::builder("web").permission("p").build().unwrap();
        Gatekeeper::builder(schema, GateKeys::derive(&[8; 32]).unwrap())
            .unwrap()
            .locator(Locator::CookieOrBearer(DEFAULT_COOKIE.into()))
            .signals(Arc::new(MemorySignals::new(16)))
            .build()
            .unwrap()
    })
}

fn attrs() -> impl Strategy<Value = Attrs> {
    prop::collection::vec((0u8..16, any::<u64>()), 0..16).prop_map(|kv| {
        let mut a = Attrs::new();
        for (k, v) in kv {
            a.set(access_gate::AttrId::from_index(k), v);
        }
        a
    })
}

fn perms() -> impl Strategy<Value = PermSet> {
    prop::collection::vec(any::<u8>(), 0..40)
        .prop_map(|b| b.into_iter().map(Perm::from_index).collect())
}

proptest! {
    /// What sign-in packs into the session, every request unpacks unchanged.
    #[test]
    fn payload_round_trip(p in perms(), tenant in proptest::option::of(any::<u64>()), a in attrs()) {
        let bytes = __encode_payload(p, tenant, &a).unwrap();
        prop_assert!(bytes.len() <= auth_gate::MAX_PAYLOAD);
        let s = __decode_payload(&bytes).unwrap();
        prop_assert_eq!(*s.perms(), p);
        prop_assert_eq!(s.tenant(), tenant);
        prop_assert_eq!(*s.attrs(), a);
    }

    /// A payload cut short or grown never decodes.
    #[test]
    fn payload_damage_fails_closed(p in perms(), a in attrs(), cut in 1usize..8, extra in any::<u8>()) {
        let bytes = __encode_payload(p, Some(1), &a).unwrap();
        prop_assert!(__decode_payload(&bytes[..bytes.len().saturating_sub(cut)]).is_none());
        let mut grown = bytes.clone();
        grown.push(extra);
        prop_assert!(__decode_payload(&grown).is_none());
    }

    /// No Cookie or Authorization header makes a guest into a member, and
    /// none makes the gate refuse.
    #[test]
    fn headers_never_sign_in(cookie in prop::collection::vec(any::<u8>(), 0..200), auth in "\\PC{0,120}") {
        let v = Visit::new("192.0.2.1".parse().unwrap())
            .cookie_header(Some(&cookie))
            .authorization(Some(auth.as_bytes()));
        let id = gk().authenticate(Inspected::new(), &v).unwrap();
        prop_assert!(id.is_guest());
    }

    /// A guest is cleared by a public rule and refused by any rule that
    /// needs a signed-in subject.
    #[test]
    fn guests_and_rules(cookie in "[a-zA-Z0-9_=; -]{0,80}") {
        let v = Visit::new("192.0.2.1".parse().unwrap()).cookie_header(Some(cookie.as_bytes()));
        let id = gk().authenticate(Inspected::new(), &v).unwrap();
        prop_assert!(gk().authorize(id.clone(), &Rule::guest()).is_ok());
        prop_assert_eq!(gk().authorize(id, &Rule::signed_in()).unwrap_err().status(), 401);
    }
}
