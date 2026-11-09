//! Ports for signing people in on the hosts of apps behind the gateway.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authentication::sessions::handoff::SessionHandoff;
use ianua_domain::domains::authentication::sessions::mfa_challenge::MfaChallenge;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    Audience, DomainName, Fact, Issuer, Lifetime, Nonce, ServiceId, SessionId, TokenHash,
    TrustedDeviceId, UserId,
};
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::ports::authentication::{WireOutcome, WireRequest};
use crate::tenancy::ScopedTenant;

/// What an app session token is minted to say.
#[derive(Debug, Clone)]
pub struct AppSessionGrant {
    /// The tenant's issuer, which the gateway holds the token's `iss` to.
    pub issuer: Issuer,
    /// The audience of the service whose sign-in was used.
    pub audience: Audience,
    /// The host the token is good on, and nowhere else.
    pub host: DomainName,
    /// The person signed in.
    pub user_id: UserId,
    /// The session behind the token, checked on every request.
    pub session_id: SessionId,
    /// The service whose app sign-in opened the session.
    pub service_id: ServiceId,
    /// How strongly the person proved who they are.
    pub assurance: AssuranceLevel,
    /// When the token lapses; never after the session does.
    pub expires_at: OffsetDateTime,
    /// How long the session may go unused before it ends, as the tenant set
    /// it when the person signed in; `None` when it never idles out.
    pub idle_timeout: Option<Duration>,
    /// The trusted device the session was signed in from, written as
    /// `did`, so a device posture check knows the device without a lookup.
    pub signed_in_from: Fact<TrustedDeviceId>,
}

/// What a bearer token for a service accepting an app's sign-in by token is
/// minted to say. An ordinary access token for that service's audience.
#[derive(Debug, Clone)]
pub struct AppAccessGrant {
    /// The tenant's issuer.
    pub issuer: Issuer,
    /// The audience of the service the token is for.
    pub audience: Audience,
    /// The person signed in.
    pub user_id: UserId,
    /// The session the token was fetched under.
    pub session_id: SessionId,
    /// The service whose sign-in opened that session. The gateway refuses
    /// the token once the session has ended.
    pub owner: ServiceId,
    /// How strongly the person proved who they are.
    pub assurance: AssuranceLevel,
    /// When the token lapses; minutes from now, never after the session.
    pub expires_at: OffsetDateTime,
    /// How long the session may go unused, as the tenant set it.
    pub idle_timeout: Option<Duration>,
    /// The trusted device the session was signed in from, written as
    /// `did`.
    pub signed_in_from: Fact<TrustedDeviceId>,
}

/// A minted app session token. The token is a credential and is never
/// printed.
pub struct IssuedAppSession {
    /// The signed token, for the host's session cookie.
    pub token: Secret,
    /// When it lapses.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for IssuedAppSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedAppSession")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Dyn-safe port for minting and reading app session tokens, signed with the
/// tenant's key and typed so they are never taken for a bearer token.
#[async_trait]
pub trait AppSessionTokens: Send + Sync {
    /// Mints a token saying what `grant` says.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the tenant has no signing key
    /// or signing fails.
    async fn issue(
        &self,
        tenant_id: &ScopedTenant,
        grant: &AppSessionGrant,
    ) -> Result<IssuedAppSession, DomainError>;

    /// Mints a short-lived bearer token saying what `grant` says, for a
    /// service that accepts an app's sign-in by token.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the tenant has no signing key
    /// or signing fails.
    async fn issue_access(
        &self,
        tenant_id: &ScopedTenant,
        grant: &AppAccessGrant,
    ) -> Result<IssuedAppSession, DomainError>;

    /// Reads a token presented on `host`: its type, signature, expiry and
    /// host must all hold.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Unauthorized` if any of them does not.
    async fn read(
        &self,
        tenant_id: &ScopedTenant,
        token: &Secret,
        host: &DomainName,
    ) -> Result<AppSessionClaim, DomainError>;
}

/// What an app session cookie claims, to be held against the session it
/// names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppSessionClaim {
    /// The session the cookie was minted for.
    pub session_id: SessionId,
    /// The person it says is signed in.
    pub user_id: UserId,
    /// The service whose app sign-in it says opened the session.
    pub service_id: ServiceId,
    /// How long the session may go unused, as the token was minted with.
    pub idle_timeout: Option<Duration>,
    /// The trusted device it says the session was signed in from, from its
    /// `did`; unknown when it names none.
    pub signed_in_from: Fact<TrustedDeviceId>,
}

/// Dyn-safe port the gateway consults on every request carrying an app
/// session, so a session ended by signing out, by an administrator or by a
/// password change stops working on the next request rather than when its
/// cookie expires.
#[async_trait]
pub trait AppSessionCheck: Send + Sync + TenantScoped {
    /// When the session `claim` names stops counting, or `None` when it does
    /// not count now. It counts while active, unexpired, used within its
    /// idle timeout, past its second factor, held by that person and opened
    /// by that service's app sign-in. A missing session does not count.
    ///
    /// The answer is its absolute end or the moment it goes idle from its
    /// last use as read, whichever is first. Ann's next request after that
    /// moment asks the store again and is answered from what her use has
    /// since moved, so a cache may repeat the answer up to it and no longer.
    /// A live session is recorded as used, so it does not idle out while
    /// the person is still active.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the session cannot be read or recorded.
    async fn live_until(
        &self,
        tenant_id: &ScopedTenant,
        claim: &AppSessionClaim,
    ) -> Result<Option<OffsetDateTime>, DomainError>;

    /// Whether `claim` names a session that counts now, as
    /// [`live_until`](Self::live_until) decides.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the session cannot be read or recorded.
    async fn is_live(
        &self,
        tenant_id: &ScopedTenant,
        claim: &AppSessionClaim,
    ) -> Result<bool, DomainError> {
        Ok(self.live_until(tenant_id, claim).await?.is_some())
    }
}

/// Seals what the gateway and the API say to each other on one relay
/// channel, with a key both derive from the platform secret for that
/// channel and nothing else uses: the gateway's questions, and the API's
/// answers bound to the question they answer.
pub trait RequestSeal: Send + Sync {
    /// The seal over `body`, a question.
    fn seal(&self, body: &[u8]) -> String;

    /// Whether `seal` is the seal over `body`, a question, compared in
    /// constant time.
    fn verifies(&self, body: &[u8], seal: &str) -> bool;

    /// The seal over `body`, the answer to the question that carried
    /// `nonce`. It never holds as a question's seal, nor for an answer to
    /// another question, so an answer cannot be forged without the key
    /// nor moved from one question to another.
    fn seal_answer(&self, nonce: &Nonce, body: &[u8]) -> String;

    /// Whether `seal` is the seal over `body` as the answer to the
    /// question that carried `nonce`, compared in constant time.
    fn verifies_answer(&self, nonce: &Nonce, body: &[u8], seal: &str) -> bool;
}

/// Dyn-safe port remembering which request nonces were already used.
#[async_trait]
pub trait NonceLedger: Send + Sync {
    /// Spends `nonce`, remembering it for `ttl`. `true` only if it was
    /// unspent; a ledger that cannot tell answers `false`, so an unchecked
    /// request is a refused one.
    async fn spend(&self, nonce: &Nonce, ttl: Lifetime) -> bool;
}

/// Dyn-safe port the gateway hands app sign-in requests to.
#[async_trait]
pub trait AppSignInBroker: Send + Sync {
    /// Sends `request` to the API and returns its answer.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` if the API cannot be reached in
    /// time or answers with something that is not an outcome.
    async fn submit(&self, request: WireRequest) -> Result<WireOutcome, DomainError>;
}

/// Dyn-safe port for the second-factor step of an app sign-in.
#[async_trait]
pub trait MfaChallengeStore: Send + Sync + TenantScoped {
    /// Saves a challenge, new or with another wrong code counted.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the challenge cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        challenge: &MfaChallenge<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Finds the challenge whose token hashes to `token_hash`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the challenge cannot be read.
    async fn find_by_token_hash(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<MfaChallenge<ResolvedTenant>>, DomainError>;

    /// Removes a challenge once it is answered or given up.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the challenge cannot be deleted.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<(), DomainError>;
}

/// Dyn-safe port for the one-time passes that carry a session to a host of a
/// service accepting it with a cookie of its own.
#[async_trait]
pub trait HandoffStore: Send + Sync + TenantScoped {
    /// Saves a new handoff.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the handoff cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        handoff: &SessionHandoff<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Removes and returns the handoff whose code hashes to `token_hash`, so
    /// a code is used once however many times it is sent.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the handoff cannot be taken.
    async fn take(
        &self,
        tenant_id: &ScopedTenant,
        token_hash: &TokenHash,
    ) -> Result<Option<SessionHandoff<ResolvedTenant>>, DomainError>;
}
