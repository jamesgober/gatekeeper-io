//! The authorization subject, packed into the session payload at sign-in
//! and unpacked on every request (a few copies, no allocation).
//!
//! ```text
//! version (1) | schema fingerprint (8) | perms (32) | tenant flag (1) | tenant (8)
//!   | attr mask (2) | values (8 each)
//! ```
//!
//! Permission and attribute bits are positions in the schema, so the
//! payload carries the schema's fingerprint and is refused when it differs:
//! a redeploy that reorders or inserts a permission ends old sessions
//! instead of handing them other permissions.

use access_gate::{AttrId, Attrs, PermSet, Status, Subject};
use auth_gate::{AuthError, Member, Payload, StandingClass, StandingSnapshot, UnixTime, UserId};

const VERSION: u8 = 2;
const HEAD: usize = 1 + 8 + 32 + 1 + 8 + 2;

pub(crate) fn encode(
    fingerprint: u64,
    perms: PermSet,
    tenant: Option<u64>,
    attrs: &Attrs,
) -> Result<Payload, AuthError> {
    let mut b = [0u8; HEAD + 16 * 8];
    b[0] = VERSION;
    b[1..9].copy_from_slice(&fingerprint.to_le_bytes());
    b[9..41].copy_from_slice(&perms.to_bytes());
    if let Some(t) = tenant {
        b[41] = 1;
        b[42..50].copy_from_slice(&t.to_le_bytes());
    }
    let mut mask = 0u16;
    let mut pos = HEAD;
    for (id, v) in attrs.iter() {
        mask |= 1 << id.index();
        b[pos..pos + 8].copy_from_slice(&v.to_le_bytes());
        pos += 8;
    }
    b[50..52].copy_from_slice(&mask.to_le_bytes());
    Payload::new(&b[..pos])
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// The subject for `member` under the schema with `fingerprint`. `None` if
/// the payload is not one this crate wrote for that schema: the request
/// becomes a guest and the session ends.
pub(crate) fn decode(member: &Member, fingerprint: u64) -> Option<Subject> {
    decode_parts(
        member.payload().as_bytes(),
        fingerprint,
        member.user(),
        member.standing(),
        member.factor_at(),
    )
}

pub(crate) fn decode_parts(
    b: &[u8],
    fingerprint: u64,
    user: UserId,
    standing: StandingSnapshot,
    factor_at: Option<UnixTime>,
) -> Option<Subject> {
    if b.len() < HEAD || b[0] != VERSION || b[41] > 1 || u64_at(b, 1)? != fingerprint {
        return None;
    }
    let perms = PermSet::from_bytes(b.get(9..41)?.try_into().ok()?);
    let mut s = Subject::new(user.as_u128()).with_perms(perms);
    if b[41] == 1 {
        s = s.with_tenant(u64_at(b, 42)?);
    }
    let mask = u16::from_le_bytes([b[50], b[51]]);
    let mut attrs = Attrs::new();
    let mut pos = HEAD;
    for i in 0..16u8 {
        if mask & (1 << i) != 0 {
            attrs.set(AttrId::from_index(i)?, u64_at(b, pos)?);
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
/// session's under `fingerprint`. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn __decode_payload(bytes: &[u8], fingerprint: u64) -> Option<Subject> {
    decode_parts(
        bytes,
        fingerprint,
        UserId::from_u128(1),
        StandingSnapshot::default(),
        None,
    )
}

/// Fuzzing and property-test hook: encode a payload. Not part of the API.
#[doc(hidden)]
#[must_use]
pub fn __encode_payload(
    fingerprint: u64,
    perms: PermSet,
    tenant: Option<u64>,
    attrs: &Attrs,
) -> Option<Vec<u8>> {
    encode(fingerprint, perms, tenant, attrs)
        .ok()
        .map(|p| p.as_bytes().to_vec())
}

/// The account id of a subject.
pub(crate) fn user_of(s: &Subject) -> UserId {
    UserId::from_u128(s.id())
}
