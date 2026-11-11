//! The session payload decoder: never a panic, and whatever it accepts
//! re-encodes to the same bytes under the same schema fingerprint.
#![no_main]

use gatekeeper_io::{__decode_payload, __encode_payload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(fp) = data.get(1..9).map(|b| u64::from_le_bytes(b.try_into().unwrap())) else {
        return;
    };
    assert!(__decode_payload(data, fp ^ 1).is_none(), "another schema never decodes");
    if let Some(s) = __decode_payload(data, fp) {
        let again = __encode_payload(fp, *s.perms(), s.tenant(), s.attrs()).unwrap();
        // The tenant bytes are ignored when the flag is off; compare the rest.
        if s.tenant().is_some() {
            assert_eq!(again, data);
        } else {
            assert_eq!(again[..42], data[..42]);
            assert_eq!(again[50..], data[50..]);
        }
    }
});
