//! The authorization subject, packed into the session payload at sign-in
//! and unpacked on every request (a few copies, no allocation).
//!
//! ```text
//! version (1) | perms (32) | tenant flag (1) | tenant (8) | attr mask (2) | values (8 each)
//! ```

use access_gate::{AttrId, Attrs, PermSet, Status, Subject};
use auth_gate::{AuthError, Member, Payload, StandingClass, StandingSnapshot, UnixTime, UserId};

const VERSION: u8 = 1;

pub(crate) fn encode(
    perms: PermSet,
    tenant: Option<u64>,
    attrs: &Attrs,
) -> Result<Payload, AuthError> {
    let mut b = [0u8; 172];
    b[0] = VERSION;
    b[1..33].copy_from_slice(&perms.to_bytes());
    if let Some(t) = tenant {
        b[33] = 1;
        b[34..42].copy_from_slice(&t.to_le_bytes());
    }
    let mut mask = 0u16;
    let mut pos = 44;
    for (id, v) in attrs.iter() {
        mask |= 1 << id.index();
        b[pos..pos + 8].copy_from_slice(&v.to_le_bytes());
        pos += 8;
    }
    b[42..44].copy_from_slice(&mask.to_le_bytes());
    Payload::new(&b[..pos])
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// The subject for `member`. `None` if the payload is not one this crate
/// wrote (a payload from another version fails closed: the request becomes
/// a guest).
pub(crate) fn decode(member: &Member) -> Option<Subject> {
    decode_parts(
        member.payload().as_bytes(),
        member.user(),
        member.standing(),
        member.factor_at(),
    )
}

pub(crate) fn decode_parts(
    b: &[u8],
    user: UserId,
    standing: StandingSnapshot,
    factor_at: Option<UnixTime>,
) -> Option<Subject> {
    if b.len() < 44 || b[0] != VERSION || b[33] > 1 {
        return None;
    }
    let perms = PermSet::from_bytes(b.get(1..33)?.try_into().ok()?);
    let mut s = Subject::new(user.as_u128()).with_perms(perms);
    if b[33] == 1 {
        s = s.with_tenant(u64_at(b, 34)?);
    }
    let mask = u16::from_le_bytes([b[42], b[43]]);
    let mut attrs = Attrs::new();
    let mut pos = 44;
    for i in 0..16u8 {
        if mask & (1 << i) != 0 {
            attrs.set(AttrId::from_index(i), u64_at(b, pos)?);
            pos += 8;
        }
    }
    if pos != b.len() {
        return None;
    }
    s = s.with_attrs(attrs);
    let status = match standing.class {
        StandingClass::PendingVerification => Status::PendingVerification,
        StandingClass::Suspended => Status::Suspended {
            until: standing.until.map(|t| t.as_millis()),
        },
        // Locked accounts keep their sessions; banned never get here.
        StandingClass::Active | StandingClass::Locked | StandingClass::Banned => Status::Active,
    };
    s = s.with_status(status);
    if let Some(at) = factor_at {
        s = s.with_factor_at(at.as_millis());
    }
    Some(s)
}

/// Fuzzing and property-test hook: decode a payload as an active
/// session's. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn __decode_payload(bytes: &[u8]) -> Option<Subject> {
    decode_parts(
        bytes,
        UserId::from_u128(1),
        StandingSnapshot::default(),
        None,
    )
}

/// Fuzzing and property-test hook: encode a payload. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn __encode_payload(perms: PermSet, tenant: Option<u64>, attrs: &Attrs) -> Option<Vec<u8>> {
    encode(perms, tenant, attrs)
        .ok()
        .map(|p| p.as_bytes().to_vec())
}

/// The account id of a subject.
pub(crate) fn user_of(s: &Subject) -> UserId {
    UserId::from_u128(s.id())
}
