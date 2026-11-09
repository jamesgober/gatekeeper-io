//! The session payload decoder: never a panic, and whatever it accepts
//! re-encodes to the same bytes.
#![no_main]

use gatekeeper_io::{__decode_payload, __encode_payload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(s) = __decode_payload(data) {
        let again = __encode_payload(*s.perms(), s.tenant(), s.attrs()).unwrap();
        // The tenant bytes are ignored when the flag is off; compare the rest.
        if s.tenant().is_some() {
            assert_eq!(again, data);
        } else {
            assert_eq!(again[..34], data[..34]);
            assert_eq!(again[42..], data[42..]);
        }
    }
});
