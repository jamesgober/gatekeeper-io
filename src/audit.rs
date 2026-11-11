//! Audit: sign-ins, sign-outs, bans, and standing changes, into an
//! audit-trail hash chain.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use audit_trail::{
    Action, Actor, Chain, Digest, Hasher, MonotonicClock, Outcome, OwnedRecord, Record, Sink,
    SinkError, Target, Timestamp,
};
use auth_gate::{Clock, UserId};
use crypt_io::{Zeroizing, mac::Blake3Mac};

/// What happened, for the audit log.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum AuditAction {
    /// A sign-in succeeded.
    SignIn,
    /// A sign-in failed.
    SignInFailed,
    /// A sign-out.
    SignOut,
    /// Every session of an account ended.
    SignOutEverywhere,
    /// An account's standing changed (ban, suspension, lift).
    StandingChanged,
    /// An account's roles changed.
    RolesChanged,
    /// A password changed.
    PasswordChanged,
    /// An account was created.
    AccountCreated,
    /// A TOTP secret was enrolled (or a replacement started).
    TotpEnrolled,
    /// A TOTP secret was confirmed and is now the factor.
    TotpConfirmed,
    /// TOTP was removed.
    TotpRemoved,
    /// New recovery codes were issued (the old ones stop working).
    RecoveryCodesIssued,
    /// A passkey was registered.
    PasskeyAdded,
    /// A passkey was removed.
    PasskeyRemoved,
}

impl AuditAction {
    /// The stable action name in the log.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SignIn => "auth.sign_in",
            Self::SignInFailed => "auth.sign_in.failed",
            Self::SignOut => "auth.sign_out",
            Self::SignOutEverywhere => "auth.sign_out.everywhere",
            Self::StandingChanged => "auth.standing.changed",
            Self::RolesChanged => "auth.roles.changed",
            Self::PasswordChanged => "auth.password.changed",
            Self::AccountCreated => "auth.account.created",
            Self::TotpEnrolled => "auth.factor.totp.enrolled",
            Self::TotpConfirmed => "auth.factor.totp.confirmed",
            Self::TotpRemoved => "auth.factor.totp.removed",
            Self::RecoveryCodesIssued => "auth.factor.recovery.issued",
            Self::PasskeyAdded => "auth.factor.passkey.added",
            Self::PasskeyRemoved => "auth.factor.passkey.removed",
        }
    }
}

/// One audit event. Holds no secret.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuditEvent {
    /// Who acted: an account, `system`, or `guest`.
    pub actor: String,
    /// What.
    pub action: AuditAction,
    /// The account acted on, and detail (the standing, a reason code).
    pub target: String,
    /// Whether it worked.
    pub outcome: Outcome,
}

impl AuditEvent {
    pub(crate) fn new(
        actor: Option<UserId>,
        action: AuditAction,
        target: String,
        outcome: Outcome,
    ) -> Self {
        Self {
            actor: actor.map_or_else(|| "system".into(), |u| u.to_string()),
            action,
            target,
            outcome,
        }
    }
}

/// Where audit events go.
pub trait AuditLog: Send + Sync {
    /// Record one event. A log that cannot write must not stop the gate;
    /// it reports the failure through its own channel.
    fn record(&self, event: &AuditEvent);
}

/// Keyed BLAKE3 (crypt-io) as the chain's hash, so a writer without the key
/// cannot rebuild the chain after editing it.
pub struct KeyedBlake3 {
    key: Zeroizing<[u8; 32]>,
    mac: Blake3Mac,
}

impl KeyedBlake3 {
    /// A hasher keyed with `key`.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            mac: Blake3Mac::new(&key),
            key: Zeroizing::new(key),
        }
    }
}

impl Hasher for KeyedBlake3 {
    fn reset(&mut self) {
        self.mac = Blake3Mac::new(&self.key);
    }

    fn update(&mut self, bytes: &[u8]) {
        self.mac.update(bytes);
    }

    fn finalize(&mut self, out: &mut Digest) {
        let mac = core::mem::replace(&mut self.mac, Blake3Mac::new(&self.key));
        *out = Digest::from_bytes(mac.finalize());
    }
}

struct ClockAdapter(Arc<dyn Clock>);

impl audit_trail::Clock for ClockAdapter {
    fn now(&self) -> Timestamp {
        Timestamp::from_nanos(self.0.now().as_millis().saturating_mul(1_000_000))
    }
}

/// An audit-trail chain behind a lock, as an [`AuditLog`].
pub struct ChainAudit<S: Sink + Send> {
    failed: AtomicU64,
    chain: Mutex<Chain<KeyedBlake3, S, MonotonicClock<ClockAdapter>>>,
}

impl<S: Sink + Send> ChainAudit<S> {
    /// A chain writing to `sink`, hashed with keyed BLAKE3 under `key`,
    /// timed by `clock`.
    pub fn new(sink: S, key: [u8; 32], clock: Arc<dyn Clock>) -> Self {
        Self {
            failed: AtomicU64::new(0),
            chain: Mutex::new(Chain::new(
                KeyedBlake3::new(key),
                sink,
                // Records must carry increasing times, even when the wall
                // clock repeats or steps back.
                MonotonicClock::new(ClockAdapter(clock)),
            )),
        }
    }

    /// How many events could not be appended (a full or closed sink). A
    /// health check should alert on any.
    #[must_use]
    pub fn failures(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }

    /// Run `f` on the sink (to read back a memory sink in tests).
    pub fn with_sink<T>(&self, f: impl FnOnce(&mut S) -> T) -> Option<T> {
        self.chain.lock().ok().map(|mut c| f(c.sink_mut()))
    }
}

/// The default number of records an in-memory audit chain keeps.
pub const MEMORY_AUDIT_RECORDS: usize = 10_000;

/// An audit-trail sink that keeps the last `cap` records in memory and
/// counts what it dropped. The chain stays verifiable from the oldest kept
/// record on (its `prev_hash` is the link). For tests and local
/// development; a deployment writes to a file or a log service.
#[derive(Debug)]
pub struct RingSink {
    cap: usize,
    records: VecDeque<OwnedRecord>,
    dropped: u64,
}

impl RingSink {
    /// Keep at most `cap` records.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            records: VecDeque::new(),
            dropped: 0,
        }
    }

    /// The records kept, oldest first.
    pub fn records(&self) -> impl Iterator<Item = &OwnedRecord> {
        self.records.iter()
    }

    /// How many old records were dropped to stay within the bound.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }
}

impl Sink for RingSink {
    fn write(&mut self, record: &Record<'_>) -> Result<(), SinkError> {
        if self.records.len() == self.cap {
            self.records.pop_front();
            self.dropped += 1;
        }
        self.records.push_back(OwnedRecord::from_record(record));
        Ok(())
    }
}

impl ChainAudit<RingSink> {
    /// A chain kept in memory, bounded to [`MEMORY_AUDIT_RECORDS`] (the
    /// oldest go first).
    #[must_use]
    pub fn memory(key: [u8; 32], clock: Arc<dyn Clock>) -> Self {
        Self::memory_with_capacity(key, clock, MEMORY_AUDIT_RECORDS)
    }

    /// A chain kept in memory, bounded to `cap` records.
    #[must_use]
    pub fn memory_with_capacity(key: [u8; 32], clock: Arc<dyn Clock>, cap: usize) -> Self {
        Self::new(RingSink::new(cap), key, clock)
    }

    /// The records kept, oldest first.
    #[must_use]
    pub fn records(&self) -> Vec<OwnedRecord> {
        self.with_sink(|s| s.records().cloned().collect())
            .unwrap_or_default()
    }

    /// How many old records were dropped to stay within the bound.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.with_sink(|s| s.dropped()).unwrap_or(0)
    }

    /// The action names so far, oldest first.
    #[must_use]
    pub fn actions(&self) -> Vec<String> {
        self.records()
            .iter()
            .map(|r| r.as_record().action().as_str().to_owned())
            .collect()
    }
}

impl<S: Sink + Send> AuditLog for ChainAudit<S> {
    fn record(&self, e: &AuditEvent) {
        let ok = self.chain.lock().is_ok_and(|mut chain| {
            chain
                .append(
                    Actor::new(&e.actor),
                    Action::new(e.action.name()),
                    Target::new(&e.target),
                    e.outcome,
                )
                .is_ok()
        });
        if !ok {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl<S: Sink + Send> core::fmt::Debug for ChainAudit<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ChainAudit(..)")
    }
}
