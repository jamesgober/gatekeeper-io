//! The gatekeeper: both gates, sign-in and sign-out, CSRF, audit.

use core::fmt;
use std::sync::Arc;

use access_gate::{Attrs, Resource, Rule, Schema, authorize_with};
use audit_trail::Outcome;
use auth_gate::{
    Actor, AuthError, AuthGate, AuthGateBuilder, Authentication, Clock, EndReason, FailureReason,
    GateKeys, IdentityStore, LockoutPolicy, MemorySignals, PasswordPolicy, Presented,
    Refusal as AuthRefusal, RelyingParty, SessionPolicy, SessionStore, SessionToken, SignIn,
    Signal, SignalKind, SignalSink, Standing, StoreError, SystemClock, UserId, Verified,
};
use cookie_net::SetCookie;
use csrf_sec::{Binding, Csrf, OsPads, RequestFacts};

use crate::{
    audit::{AuditAction, AuditEvent, AuditLog, ChainAudit},
    refusal::{Refusal, RefusalKind},
    stage::{Cleared, Identified, Identity, Inspected},
    subject,
    visit::{Locator, Visit},
};

/// The cookie that binds a guest's login-form CSRF token. It holds 32
/// random bytes and nothing is stored for it on the server, so a flood of
/// visitors cannot fill the session store.
pub const PRE_SESSION_COOKIE: &str = "__Host-pre";

/// Authentication at the core, for every request.
pub trait Authenticator: Send + Sync {
    /// Turn an inspected request into an identified one, or refuse it
    /// (a banned account).
    ///
    /// # Errors
    ///
    /// A [`Refusal`] to send straight to the response pipeline.
    fn authenticate(&self, stage: Inspected, visit: &Visit<'_>) -> Result<Identified, Refusal>;
}

/// A starter authenticator: every request is a guest. Correct, just
/// minimal, for bringing a server up before sign-in exists; replaced by a
/// [`Gatekeeper`] in one line of wiring.
#[derive(Clone, Copy, Debug, Default)]
pub struct EveryoneGuest;

impl Authenticator for EveryoneGuest {
    fn authenticate(&self, _: Inspected, _: &Visit<'_>) -> Result<Identified, Refusal> {
        Ok(Identified::guest(None))
    }
}

/// Profile fields the service owns that rules need (`org_id`), loaded at
/// sign-in only.
pub trait AttributeSource: Send + Sync {
    /// Set the attributes of `user` that `schema` declares and this source
    /// owns.
    ///
    /// # Errors
    ///
    /// [`StoreError`]; the sign-in then fails closed.
    fn load(&self, user: UserId, schema: &Schema, attrs: &mut Attrs) -> Result<(), StoreError>;
}

/// The login form's fields.
#[derive(Clone, Copy)]
pub struct LoginForm<'a> {
    /// Email or user name.
    pub identifier: &'a str,
    /// The password.
    pub password: &'a str,
    /// The CSRF token from the form.
    pub csrf: &'a [u8],
}

impl fmt::Debug for LoginForm<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginForm(..)")
    }
}

/// The second-factor form's fields.
#[derive(Clone, Copy)]
pub struct CodeForm<'a> {
    /// The challenge from [`Login::SecondFactor`].
    pub challenge: &'a str,
    /// The TOTP code or a recovery code.
    pub code: &'a str,
    /// The CSRF token from the form.
    pub csrf: &'a [u8],
}

impl fmt::Debug for CodeForm<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeForm(..)")
    }
}

/// A passkey assertion, base64url-decoded by the caller.
#[derive(Clone, Copy, Debug)]
pub struct PasskeyForm<'a> {
    /// `rawId`.
    pub credential: &'a [u8],
    /// `clientDataJSON`.
    pub client_data_json: &'a [u8],
    /// `authenticatorData`.
    pub authenticator_data: &'a [u8],
    /// `signature`.
    pub signature: &'a [u8],
    /// The CSRF token from the page.
    pub csrf: &'a [u8],
}

/// A CSRF token for a form, and the cookie it is bound to when the visitor
/// is a guest.
#[derive(Clone, PartialEq, Eq)]
pub struct FormToken {
    token: String,
    set_cookie: Option<String>,
}

impl FormToken {
    /// The hidden field's value.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The `Set-Cookie` the page must carry (a new pre-session cookie).
    #[must_use]
    pub fn set_cookie(&self) -> Option<&str> {
        self.set_cookie.as_deref()
    }
}

impl fmt::Debug for FormToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FormToken(..)")
    }
}

/// The result of a sign-in step.
#[derive(Debug)]
pub enum Login {
    /// Signed in: answer `303 See Other` with these cookies, so the next
    /// request passes the gate signed in.
    SignedIn(SignedIn),
    /// The password was right; ask for the code, carrying this challenge.
    SecondFactor(SecondFactor),
    /// Refused: show the form again with [`LoginFailed::message`].
    Failed(LoginFailed),
}

/// A finished sign-in.
#[derive(Debug)]
pub struct SignedIn {
    user: UserId,
    token: SessionToken,
    cookies: Vec<String>,
}

impl SignedIn {
    /// The account.
    #[must_use]
    pub const fn user(&self) -> UserId {
        self.user
    }

    /// The `Set-Cookie` values to send: the new session cookie, and the
    /// pre-session cookie cleared.
    pub fn set_cookies(&self) -> impl Iterator<Item = &str> {
        self.cookies.iter().map(String::as_str)
    }

    /// The token itself, for API clients that use a bearer header.
    #[must_use]
    pub fn token(&self) -> &str {
        self.token.as_str()
    }
}

/// A pending second factor.
#[derive(Clone, PartialEq, Eq)]
pub struct SecondFactor {
    challenge: String,
}

impl SecondFactor {
    /// The hidden field for the code form.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

impl fmt::Debug for SecondFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecondFactor(..)")
    }
}

/// Why a sign-in step failed (for logs and audit).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum LoginFailure {
    /// Already signed in.
    AlreadySignedIn,
    /// The CSRF check failed.
    Csrf,
    /// The credentials were refused.
    Credentials(FailureReason),
    /// A store could not answer.
    Unavailable,
}

/// A refused sign-in step.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LoginFailed {
    reason: LoginFailure,
}

impl LoginFailed {
    /// Why.
    #[must_use]
    pub const fn reason(&self) -> LoginFailure {
        self.reason
    }

    /// The text to show: the same for every reason.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        auth_gate::FAILURE_MESSAGE
    }
}

/// A finished sign-out: answer `303 See Other` with this cookie.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignedOut {
    set_cookie: Option<String>,
}

impl SignedOut {
    /// The `Set-Cookie` that clears the session cookie.
    #[must_use]
    pub fn set_cookie(&self) -> Option<&str> {
        self.set_cookie.as_deref()
    }
}

/// Configures a [`Gatekeeper`]. Start with [`Gatekeeper::builder`].
#[must_use = "a builder does nothing until `build` is called"]
pub struct GatekeeperBuilder {
    schema: Schema,
    auth: AuthGateBuilder,
    csrf_key: [u8; 32],
    audit_key: [u8; 32],
    locator: Locator,
    origin: Option<String>,
    signals: Option<Arc<dyn SignalSink>>,
    clock: Option<Arc<dyn Clock>>,
    audit: Option<Arc<dyn AuditLog>>,
    attributes: Option<Arc<dyn AttributeSource>>,
}

impl GatekeeperBuilder {
    /// Where accounts live (an adapter, or [`auth_gate::MemoryIdentities`]).
    pub fn identities(mut self, store: Arc<dyn IdentityStore>) -> Self {
        self.auth = self.auth.identities(store);
        self
    }

    /// Where sessions live (an adapter, or [`auth_gate::MemorySessions`]).
    pub fn sessions(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.auth = self.auth.sessions(store);
        self
    }

    /// The security bridge every signal goes to.
    pub fn signals(mut self, sink: Arc<dyn SignalSink>) -> Self {
        self.signals = Some(sink);
        self
    }

    /// Where audit events go. Default: an audit-trail chain in memory.
    pub fn audit(mut self, log: Arc<dyn AuditLog>) -> Self {
        self.audit = Some(log);
        self
    }

    /// The service's own profile attributes.
    pub fn attributes(mut self, source: Arc<dyn AttributeSource>) -> Self {
        self.attributes = Some(source);
        self
    }

    /// The clock.
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Where the credential is (from the profile). Default: the
    /// `__Host-sid` cookie.
    pub fn locator(mut self, locator: Locator) -> Self {
        self.locator = locator;
        self
    }

    /// The site's own origin (`https://example.com`), for the CSRF origin
    /// check.
    pub fn origin(mut self, origin: &str) -> Self {
        self.origin = Some(origin.into());
        self
    }

    /// Password rules and cost.
    pub fn password_policy(mut self, policy: PasswordPolicy) -> Self {
        self.auth = self.auth.password_policy(policy);
        self
    }

    /// Session lifetimes.
    pub fn session_policy(mut self, policy: SessionPolicy) -> Self {
        self.auth = self.auth.session_policy(policy);
        self
    }

    /// Automatic locking.
    pub fn lockout_policy(mut self, policy: LockoutPolicy) -> Self {
        self.auth = self.auth.lockout_policy(policy);
        self
    }

    /// Build.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidInput`] for a session cookie name without the
    /// `__Host-` prefix; otherwise as [`AuthGateBuilder::build`].
    pub fn build(self) -> Result<Gatekeeper, AuthError> {
        if let Some(name) = self.locator.cookie_name() {
            if !name.starts_with("__Host-") || SetCookie::delete(name).is_err() {
                return Err(AuthError::InvalidInput(
                    "session cookie name needs the __Host- prefix",
                ));
            }
        }
        let clock = self.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let signals = self
            .signals
            .unwrap_or_else(|| Arc::new(MemorySignals::default()));
        let audit = self
            .audit
            .unwrap_or_else(|| Arc::new(ChainAudit::memory(self.audit_key, clock.clone())));
        let csrf = Csrf::new(self.csrf_key).map_err(|_| AuthError::Crypto)?;
        let auth = self
            .auth
            .clock(clock.clone())
            .signals(signals.clone())
            .build()?;
        Ok(Gatekeeper {
            auth,
            schema: Arc::new(self.schema),
            csrf,
            locator: self.locator,
            origin: self.origin,
            signals,
            clock,
            audit,
            attributes: self.attributes,
        })
    }
}

/// Both gates in one place: authentication on the core for every request,
/// authorization in the router after the route match, plus sign-in,
/// sign-out, CSRF for both, standing changes, and audit.
///
/// It owns no database: the service's [`Schema`] says what, store adapters
/// say where, key-vault supplies the master secret.
pub struct Gatekeeper {
    auth: AuthGate,
    schema: Arc<Schema>,
    csrf: Csrf,
    locator: Locator,
    origin: Option<String>,
    signals: Arc<dyn SignalSink>,
    clock: Arc<dyn Clock>,
    audit: Arc<dyn AuditLog>,
    attributes: Option<Arc<dyn AttributeSource>>,
}

impl fmt::Debug for Gatekeeper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gatekeeper")
            .field("service", &self.schema.service())
            .field("locator", &self.locator)
            .finish_non_exhaustive()
    }
}

fn derive_key(from: &[u8; 32], label: &str) -> Result<[u8; 32], AuthError> {
    let mut out = [0u8; 32];
    crypt_io::kdf::hkdf_sha256_into(from, Some(b"gatekeeper-io/v1"), label.as_bytes(), &mut out)
        .map_err(|_| AuthError::Crypto)?;
    Ok(out)
}

impl Gatekeeper {
    /// Start configuring a gatekeeper for the service `schema` describes,
    /// with keys derived from the master secret.
    ///
    /// # Errors
    ///
    /// [`AuthError::Crypto`] if key derivation fails.
    pub fn builder(schema: Schema, keys: GateKeys) -> Result<GatekeeperBuilder, AuthError> {
        let csrf_key = keys.csrf_key();
        let audit_key = derive_key(&csrf_key, "audit chain")?;
        Ok(GatekeeperBuilder {
            schema,
            auth: AuthGate::builder(keys),
            csrf_key,
            audit_key,
            locator: Locator::default(),
            origin: None,
            signals: None,
            clock: None,
            audit: None,
            attributes: None,
        })
    }

    /// The authentication gate, for calls this type does not wrap
    /// (factor enrolment, passkey registration, devices).
    #[must_use]
    pub fn auth(&self) -> &AuthGate {
        &self.auth
    }

    /// The compiled schema.
    #[must_use]
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    fn signal(&self, kind: SignalKind, visit: &Visit<'_>, user: Option<UserId>) {
        self.signals.signal(&Signal {
            kind,
            confidence: 50,
            source: Some(visit.peer),
            user,
            session: None,
            at: self.clock.now(),
        });
    }

    fn clear_cookie(&self) -> Option<String> {
        let name = self.locator.cookie_name()?;
        SetCookie::delete(name).ok().map(|c| c.encode())
    }

    fn presented<'a>(&self, visit: &Visit<'a>) -> Presented<'a> {
        Presented::new()
            .peer(visit.peer)
            .user_agent(visit.user_agent)
            .token(self.locator.locate(visit))
    }

    // ------------------------------------------------------- the two gates

    /// Authorize an identified request for `rule` (route check).
    ///
    /// # Errors
    ///
    /// A [`Refusal`]: 401 when signing in would help, 403 otherwise.
    pub fn authorize(&self, stage: Identified, rule: &Rule) -> Result<Cleared, Refusal> {
        self.decide(stage, rule, None)
    }

    /// Authorize an identified request for `rule` on `resource` (object
    /// check: owner, tenant, attributes).
    ///
    /// # Errors
    ///
    /// As [`authorize`](Self::authorize).
    pub fn authorize_on(
        &self,
        stage: Identified,
        rule: &Rule,
        resource: &Resource,
    ) -> Result<Cleared, Refusal> {
        self.decide(stage, rule, Some(resource))
    }

    /// The decision alone, without producing a stage: for frameworks that
    /// keep their own proof that the check ran (web-net's handler context).
    ///
    /// # Errors
    ///
    /// As [`authorize`](Self::authorize).
    pub fn check(
        &self,
        stage: &Identified,
        rule: &Rule,
        resource: Option<&Resource>,
    ) -> Result<(), Refusal> {
        let now = self.clock.now().as_millis();
        authorize_with(self.schema.guests(), stage.subject(), rule, resource, now).map_err(|d| {
            self.signals.signal(&Signal {
                kind: SignalKind::AccessDenied,
                confidence: 50,
                source: None,
                user: stage.user(),
                session: stage.identity().session(),
                at: self.clock.now(),
            });
            Refusal::from_denial(d).with_cookie(stage.set_cookie.clone())
        })
    }

    fn decide(
        &self,
        stage: Identified,
        rule: &Rule,
        resource: Option<&Resource>,
    ) -> Result<Cleared, Refusal> {
        self.check(&stage, rule, resource)?;
        Ok(Cleared { inner: stage })
    }

    // ------------------------------------------------------------- CSRF

    fn facts<'a>(&'a self, visit: &Visit<'a>) -> RequestFacts<'a> {
        let mut f = RequestFacts::new(visit.method);
        if let Some(v) = visit.fetch_site {
            f = f.fetch_site(v);
        }
        if let Some(v) = visit.origin {
            f = f.origin(v);
        }
        if let Some(v) = visit.referer {
            f = f.referer(v);
        }
        if let Some(o) = &self.origin {
            f = f.own_origin(o.as_str());
        }
        f
    }

    /// A CSRF token for a form on a guest's page (the login form). Reuses
    /// the visitor's pre-session cookie or makes one; nothing is stored on
    /// the server.
    ///
    /// # Errors
    ///
    /// [`RefusalKind::Unavailable`] if the random source fails.
    pub fn login_form(&self, stage: &Cleared, visit: &Visit<'_>) -> Result<FormToken, Refusal> {
        let _ = stage;
        let fail = || Refusal::new(RefusalKind::Unavailable);
        let (pre, set_cookie) = match visit.cookie(PRE_SESSION_COOKIE) {
            crate::visit::Located::Found(v) if v.len() == 43 => (v.to_vec(), None),
            _ => {
                let mut raw = [0u8; 32];
                mod_rand::tier3::fill_bytes(&mut raw).map_err(|_| fail())?;
                let value = b64(&raw);
                let cookie = SetCookie::new(PRE_SESSION_COOKIE, &value)
                    .map_err(|_| fail())?
                    .encode();
                (value.into_bytes(), Some(cookie))
            }
        };
        let token = self
            .csrf
            .issue_at(
                &Binding::new(&pre).scope("login"),
                self.clock.now().as_secs(),
                &mut OsPads,
            )
            .map_err(|_| fail())?;
        Ok(FormToken {
            token: token.as_str().to_owned(),
            set_cookie,
        })
    }

    fn check_login_csrf(&self, visit: &Visit<'_>, token: &[u8]) -> bool {
        let crate::visit::Located::Found(pre) = visit.cookie(PRE_SESSION_COOKIE) else {
            return false;
        };
        let binding = Binding::new(pre).scope("login");
        let ok = self
            .csrf
            .check_at(
                &self.facts(visit),
                &binding,
                token,
                self.clock.now().as_secs(),
            )
            .is_ok();
        if !ok {
            self.signal(SignalKind::CsrfRejected, visit, None);
        }
        ok
    }

    /// A CSRF token for a signed-in page's forms, bound to the session.
    ///
    /// # Errors
    ///
    /// [`RefusalKind::NeedsSignIn`] for a guest.
    pub fn csrf_token(&self, stage: &Cleared) -> Result<String, Refusal> {
        let sid = stage
            .identity()
            .session()
            .ok_or(Refusal::new(RefusalKind::NeedsSignIn))?;
        let token = self
            .csrf
            .issue_at(
                &Binding::new(sid.as_bytes()),
                self.clock.now().as_secs(),
                &mut OsPads,
            )
            .map_err(|_| Refusal::new(RefusalKind::Unavailable))?;
        Ok(token.as_str().to_owned())
    }

    /// Check a signed-in form's CSRF token and the request's origin facts.
    ///
    /// # Errors
    ///
    /// [`RefusalKind::Csrf`] (403).
    pub fn check_csrf(
        &self,
        stage: &Cleared,
        visit: &Visit<'_>,
        token: &[u8],
    ) -> Result<(), Refusal> {
        let Some(sid) = stage.identity().session() else {
            return Err(Refusal::new(RefusalKind::NeedsSignIn));
        };
        let verdict = self.csrf.check_at(
            &self.facts(visit),
            &Binding::new(sid.as_bytes()),
            token,
            self.clock.now().as_secs(),
        );
        if verdict.is_err() {
            self.signal(SignalKind::CsrfRejected, visit, stage.user());
            return Err(Refusal::new(RefusalKind::Csrf));
        }
        Ok(())
    }

    // ------------------------------------------------- sign-in, sign-out

    /// `POST /login` (rule: guests only). Checks the CSRF token, then the
    /// password inside the gate. Argon2id runs here: call it off any
    /// connection-serving thread.
    #[must_use]
    pub fn login(&self, stage: &Cleared, visit: &Visit<'_>, form: LoginForm<'_>) -> Login {
        if !stage.is_guest() {
            return Login::Failed(LoginFailed {
                reason: LoginFailure::AlreadySignedIn,
            });
        }
        if !self.check_login_csrf(visit, form.csrf) {
            return Login::Failed(LoginFailed {
                reason: LoginFailure::Csrf,
            });
        }
        let p = self.presented(visit);
        let out = self.auth.sign_in(form.identifier, form.password, &p);
        self.finish(out, visit)
    }

    /// The code form after [`Login::SecondFactor`].
    #[must_use]
    pub fn second_factor(&self, stage: &Cleared, visit: &Visit<'_>, form: CodeForm<'_>) -> Login {
        if !stage.is_guest() {
            return Login::Failed(LoginFailed {
                reason: LoginFailure::AlreadySignedIn,
            });
        }
        if !self.check_login_csrf(visit, form.csrf) {
            return Login::Failed(LoginFailed {
                reason: LoginFailure::Csrf,
            });
        }
        let p = self.presented(visit);
        let out = self.auth.second_factor(form.challenge, form.code, &p);
        self.finish(out, visit)
    }

    /// Sign in with a passkey assertion (rule: guests only).
    #[must_use]
    pub fn login_passkey(
        &self,
        stage: &Cleared,
        visit: &Visit<'_>,
        rp: &RelyingParty,
        form: PasskeyForm<'_>,
    ) -> Login {
        if !stage.is_guest() {
            return Login::Failed(LoginFailed {
                reason: LoginFailure::AlreadySignedIn,
            });
        }
        if !self.check_login_csrf(visit, form.csrf) {
            return Login::Failed(LoginFailed {
                reason: LoginFailure::Csrf,
            });
        }
        let p = self.presented(visit);
        let out = self.auth.sign_in_passkey(
            rp,
            form.credential,
            form.client_data_json,
            form.authenticator_data,
            form.signature,
            &p,
        );
        self.finish(out, visit)
    }

    fn finish(&self, out: SignIn, visit: &Visit<'_>) -> Login {
        match out {
            SignIn::Verified(v) => match self.start_session(v, visit) {
                Ok(s) => Login::SignedIn(s),
                Err(_) => Login::Failed(LoginFailed {
                    reason: LoginFailure::Unavailable,
                }),
            },
            SignIn::NeedsSecondFactor(c) => Login::SecondFactor(SecondFactor {
                challenge: c.to_text(),
            }),
            SignIn::Failed(f) => {
                self.audit.record(&AuditEvent::new(
                    None,
                    AuditAction::SignInFailed,
                    format!("reason={:?}", f.reason()),
                    Outcome::Denied,
                ));
                let reason = if f.reason() == FailureReason::Unavailable {
                    LoginFailure::Unavailable
                } else {
                    LoginFailure::Credentials(f.reason())
                };
                Login::Failed(LoginFailed { reason })
            }
        }
    }

    fn start_session(&self, v: Verified, visit: &Visit<'_>) -> Result<SignedIn, AuthError> {
        let user = v.user();
        let account = self
            .auth
            .identities()
            .account(user)?
            .ok_or(AuthError::Store(StoreError::NotFound))?;
        let perms = self.schema.grants(account.roles.iter());
        let mut attrs = Attrs::new();
        for (name, value) in &account.attrs {
            if let Some(id) = self.schema.attribute(name) {
                attrs.set(id, *value);
            }
        }
        if let Some(src) = &self.attributes {
            src.load(user, &self.schema, &mut attrs)?;
        }
        let payload = subject::encode(perms, account.tenant, &attrs)?;
        let issued = self.auth.issue(v, payload, &self.presented(visit))?;
        let mut cookies = Vec::with_capacity(2);
        if let Some(name) = self.locator.cookie_name() {
            let max_age = self.auth.session_policy().absolute.as_secs().max(1);
            let c = cookie_net::session_cookie(name, issued.token.as_str(), max_age)
                .map_err(|_| AuthError::InvalidInput("session cookie"))?;
            cookies.push(c.encode());
        }
        if let Ok(c) = SetCookie::delete(PRE_SESSION_COOKIE) {
            cookies.push(c.encode());
        }
        self.audit.record(&AuditEvent::new(
            Some(user),
            AuditAction::SignIn,
            format!("session={}", issued.record.id),
            Outcome::Success,
        ));
        Ok(SignedIn {
            user,
            token: issued.token,
            cookies,
        })
    }

    /// `POST /logout` (rule: signed in). Checks the CSRF token, ends the
    /// session on the server, and clears the cookie.
    ///
    /// # Errors
    ///
    /// [`RefusalKind::NeedsSignIn`] for a guest, [`RefusalKind::Csrf`] for a
    /// bad token.
    pub fn logout(
        &self,
        stage: Cleared,
        visit: &Visit<'_>,
        csrf: &[u8],
    ) -> Result<SignedOut, Refusal> {
        self.check_csrf(&stage, visit, csrf)?;
        let Some(digest) = stage.inner.digest else {
            return Err(Refusal::new(RefusalKind::NeedsSignIn));
        };
        self.auth
            .sessions()
            .end(&digest, EndReason::SignedOut, self.clock.now())
            .map_err(|_| Refusal::new(RefusalKind::Unavailable))?;
        self.audit.record(&AuditEvent::new(
            stage.user(),
            AuditAction::SignOut,
            stage
                .identity()
                .session()
                .map_or_else(String::new, |s| format!("session={s}")),
            Outcome::Success,
        ));
        Ok(SignedOut {
            set_cookie: self.clear_cookie(),
        })
    }

    // ------------------------------------------------------------ admin

    /// Create an account with a password and roles.
    ///
    /// # Errors
    ///
    /// As [`AuthGate::create_account`].
    pub fn create_account(
        &self,
        identifier: &str,
        password: &str,
        standing: Standing,
        roles: &[&str],
    ) -> Result<UserId, AuthError> {
        let user = self
            .auth
            .create_account(identifier, password, standing, roles)?;
        self.audit.record(&AuditEvent::new(
            None,
            AuditAction::AccountCreated,
            format!("user={user}"),
            Outcome::Success,
        ));
        Ok(user)
    }

    /// Set an account's standing (ban, suspend, lift), recorded with who did
    /// it. A ban ends every session at once.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`].
    pub fn set_standing(
        &self,
        user: UserId,
        standing: Standing,
        by: Actor,
    ) -> Result<(), AuthError> {
        let class = standing.class();
        let res = self.auth.set_standing(user, standing);
        let actor = match by {
            Actor::Admin(a) => Some(a),
            Actor::System => None,
        };
        self.audit.record(&AuditEvent::new(
            actor,
            AuditAction::StandingChanged,
            format!("user={user} standing={class:?}"),
            if res.is_ok() {
                Outcome::Success
            } else {
                Outcome::Error
            },
        ));
        res
    }

    /// Replace an account's roles. Its sessions end, so the next sign-in
    /// carries the new permissions.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`].
    pub fn set_roles(&self, user: UserId, roles: &[&str], by: Actor) -> Result<(), AuthError> {
        self.auth.identities().set_roles(user, roles)?;
        self.auth.sign_out_everywhere(user)?;
        let actor = match by {
            Actor::Admin(a) => Some(a),
            Actor::System => None,
        };
        self.audit.record(&AuditEvent::new(
            actor,
            AuditAction::RolesChanged,
            format!("user={user} roles={}", roles.join(",")),
            Outcome::Success,
        ));
        Ok(())
    }

    /// Change a password; every session of the account ends.
    ///
    /// # Errors
    ///
    /// As [`AuthGate::change_password`].
    pub fn change_password(&self, user: UserId, new_password: &str) -> Result<(), AuthError> {
        self.auth.change_password(user, new_password)?;
        self.audit.record(&AuditEvent::new(
            Some(user),
            AuditAction::PasswordChanged,
            format!("user={user}"),
            Outcome::Success,
        ));
        Ok(())
    }
}

impl Authenticator for Gatekeeper {
    fn authenticate(&self, _stage: Inspected, visit: &Visit<'_>) -> Result<Identified, Refusal> {
        let p = self.presented(visit);
        match self.auth.authenticate(&p) {
            Authentication::Guest(g) => {
                let mut id = Identified::guest(if g.clear_cookie() {
                    self.clear_cookie()
                } else {
                    None
                });
                if let crate::visit::Located::Found(pre) = visit.cookie(PRE_SESSION_COOKIE) {
                    if pre.len() == 43 {
                        id.pre = core::str::from_utf8(pre).ok().map(str::to_owned);
                    }
                }
                Ok(id)
            }
            Authentication::Member(m) => match subject::decode(&m) {
                Some(subject) => Ok(Identified {
                    identity: Identity::Member {
                        user: subject::user_of(&subject),
                        session: m.session_id(),
                        subject,
                    },
                    digest: Some(*m.digest()),
                    set_cookie: None,
                    pre: None,
                }),
                None => {
                    let _ = self.auth.end_session(&m);
                    Ok(Identified::guest(self.clear_cookie()))
                }
            },
            Authentication::Refused(AuthRefusal::Banned { until }) => {
                Err(Refusal::new(RefusalKind::Banned { until }).with_cookie(self.clear_cookie()))
            }
        }
    }
}

fn b64(raw: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::with_capacity((raw.len() * 8).div_ceil(6));
    for c in raw.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(c.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(c.get(2).copied().unwrap_or(0));
        for i in 0..=c.len() {
            s.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    s
}
