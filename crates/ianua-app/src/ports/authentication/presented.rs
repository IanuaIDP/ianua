//! Reading the credentials a request presents at the gateway: the tenant's
//! own tokens, an app's session cookie, a consumer's token or API key.
//!
//! The gateway hands each credential over as it arrived and never parses a
//! JWT or digests a key itself. A reader checks what only it can: the
//! signature under the right keys, with the algorithm the key pins (never
//! `none`, never the one the header names), the token's type, issuer,
//! audience, and `exp`, `nbf` and `iat` within a minute's skew. What the
//! stored records say about the credential, whether its person may still
//! sign in, its session is live or its delegation stands, is the
//! application's to ask.

use async_trait::async_trait;
use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
use ianua_domain::domains::authorization::policy::claims::Claim;
use ianua_domain::domains::oauth::grants::token_binding::JwkThumbprint;
use ianua_domain::domains::proxy::request::context::AgentLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    ActionCallId, AgentId, Audience, DelegationId, DomainName, Fact, FederatedSubject, HttpsUrl,
    Issuer, KeyPrefix, PermissionName, PrincipalRef, RouteId, Scope, ServiceId, StreamRouteId,
    TenantId, TokenHash, UserId,
};
use time::OffsetDateTime;

use crate::ports::authentication::AppSessionClaim;
use crate::tenancy::ScopedTenant;

/// What a reader made of a presented token: what it says, or why it is
/// refused. A reader that could not check at all answers with an error
/// instead, so a check that failed is never read as a refusal it did not
/// make, nor as a pass.
#[derive(Debug, Clone)]
pub enum TokenReading<T> {
    /// The token checked out, and says this.
    Read(T),
    /// The token is refused for this reason.
    Refused(TokenFault),
}

/// Why a reader refused a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFault {
    /// It is no token of the kind asked for: malformed, typed as another
    /// kind, signed with an algorithm or key not accepted, a signature that
    /// does not hold, or a claim that cannot be read.
    Invalid,
    /// It is past its `exp`.
    Expired,
    /// It is before its `nbf`, or says it was issued ahead of the clock.
    NotYetValid,
    /// Its `iss` is not the issuer expected.
    WrongIssuer,
    /// Its `aud` does not name the audience expected.
    WrongAudience,
    /// It was minted for another host, another tenant, or by another
    /// service's sign-in than the one this host takes.
    WrongHost,
}

/// What a bearer token must say to be taken on a route.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedToken<'a> {
    /// The issuer its `iss` must name.
    pub issuer: &'a Issuer,
    /// The audience its `aud`, a string or a list, must name.
    pub audience: &'a Audience,
}

/// What an app session cookie must say to be taken on a host.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedSession<'a> {
    /// The tenant's issuer, which its `iss` must name.
    pub issuer: &'a Issuer,
    /// The audience of the service whose sign-in made it.
    pub audience: &'a Audience,
    /// The host it was presented on, which it must name.
    pub host: &'a DomainName,
    /// The service whose sign-in must have opened its session.
    pub owner: &'a ServiceId,
}

/// The issuer and subject a token claims, read without checking anything.
/// Only good for choosing whose keys check it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedToken {
    /// Its `iss`.
    pub issuer: Issuer,
    /// Its `sub`.
    pub subject: FederatedSubject,
}

/// A token the tenant signed, by whom it names.
#[derive(Debug, Clone)]
pub enum TenantToken {
    /// A person's.
    Person(PersonToken),
    /// An agent's task token, minted from a delegation.
    Agent(Box<AgentToken>),
}

/// A token the tenant signed for a person.
#[derive(Debug, Clone)]
pub struct PersonToken {
    /// The person, its `sub`.
    pub user_id: UserId,
    /// The scopes it carries, from `scope` or `scp`.
    pub scopes: Vec<Scope>,
    /// How strongly the person proved who they are, from `aal`. Unknown
    /// when the claim is missing or unreadable, never read as the lowest.
    pub assurance: Fact<AssuranceLevel>,
    /// When it stops being valid, its `exp`.
    pub expires_at: OffsetDateTime,
    /// What it was issued under, which must still stand.
    pub issued_under: IssuedUnder,
    /// The claims it asserts about the person beyond the registered ones,
    /// such as the attributes the tenant puts in its tokens, each as the
    /// tenant's policy rules compare them. A claim whose name or value is
    /// not one a rule can compare is left out. Empty when it asserts none.
    pub claims: Vec<Claim>,
}

/// What a person's token was issued under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuedUnder {
    /// An app session, which `ias` and `sid` name: a bearer token an app's
    /// page fetched for a service accepting its sign-in by token.
    AppSession(AppSessionClaim),
    /// An OAuth grant, whose access token record must still stand.
    Grant,
}

/// An agent's task token, read whole.
#[derive(Debug, Clone)]
pub struct AgentToken {
    /// The agent acting, its `act`.
    pub agent_id: AgentId,
    /// The delegation it was minted from, its `jti`.
    pub delegation_id: DelegationId,
    /// Whom the agent acts for, its `obo`.
    pub acting_for: PrincipalRef,
    /// The HTTP permissions the delegation grants, from `permissions`.
    pub permissions: Vec<PermissionName>,
    /// Everything the token confines the agent to. A confinement claim the
    /// reader cannot read refuses the token: dropping it would lift it.
    ///
    /// Its `metering` is `Metered` with the `RequestBudget` of `bmax` per
    /// `bwin` seconds when the token states both, and `Unmetered` when it
    /// states no `bmax` (a window alone caps nothing). A `bmax` without a
    /// window, or a zero window, is [`TokenFault::Invalid`]: dropping the
    /// cap would lift it.
    pub limits: AgentLimits,
    /// The thumbprint of the key `limits.key_binding` names, which a
    /// `DPoP` proof must be signed with. `None` exactly when the token is a
    /// bearer token.
    pub bound_key: Option<JwkThumbprint>,
    /// When it stops being valid, its `exp`.
    pub expires_at: OffsetDateTime,
}

/// An app session cookie, read whole.
#[derive(Debug, Clone, Copy)]
pub struct AppSessionToken {
    /// The session it names, with its person and service.
    pub claim: AppSessionClaim,
    /// How strongly the person proved who they are, from `aal`.
    pub assurance: Fact<AssuranceLevel>,
    /// When it stops being valid, its `exp`.
    pub expires_at: OffsetDateTime,
}

/// A consumer's own token, once its keys checked it.
#[derive(Debug, Clone)]
pub struct ConsumerToken {
    /// Its `iss`.
    pub issuer: Issuer,
    /// Its `sub`.
    pub subject: FederatedSubject,
    /// The scopes it carries, from `scope` or `scp`.
    pub scopes: Vec<Scope>,
    /// When it stops being valid, its `exp`.
    pub expires_at: OffsetDateTime,
}

/// A consumer's API key, as its consumer is found and checked by.
#[derive(Debug, Clone)]
pub struct PresentedKey {
    /// The prefix the key starts with, which finds the consumer.
    pub prefix: KeyPrefix,
    /// The digest of the whole key, under the key consumer keys are
    /// digested with.
    pub digest: TokenHash,
}

/// Dyn-safe port reading the tokens the tenant signs, as a request at the
/// gateway presents them, with the tenant's keys.
///
/// A bearer token must be typed `at+jwt`; an agent's must also name the
/// tenant's agent audience besides the route's. An app session must be
/// typed as one and name the tenant in `tid`.
#[async_trait]
pub trait PresentedTokens: Send + Sync {
    /// The issuer and subject `token` claims, without checking it, or
    /// `None` when it is no JWT naming both.
    fn claimed(&self, token: &Secret) -> Option<ClaimedToken>;

    /// What a bearer `token` says, once it checks out as one the tenant
    /// signed for `expected`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the tenant's keys cannot
    /// be read.
    async fn read_bearer(
        &self,
        tenant_id: &ScopedTenant,
        token: &Secret,
        expected: ExpectedToken<'_>,
    ) -> Result<TokenReading<TenantToken>, DomainError>;

    /// What an app session cookie's `token` says, once it checks out as one
    /// the tenant signed for `expected`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the tenant's keys cannot
    /// be read.
    async fn read_app_session(
        &self,
        tenant_id: &ScopedTenant,
        token: &Secret,
        expected: ExpectedSession<'_>,
    ) -> Result<TokenReading<AppSessionToken>, DomainError>;

    /// The tenant and route a run pass `token` claims, without checking
    /// it, or `None` when it is no JWT naming both. Only good for choosing
    /// whose keys check it, and which route it may reach.
    fn claimed_pass(&self, token: &Secret) -> Option<ClaimedPass>;

    /// What a run pass `token` says, once it checks out as one the tenant
    /// signed under `issuer`, typed as a pass and naming the tenant.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the tenant's keys cannot
    /// be read.
    async fn read_run_pass(
        &self,
        tenant_id: &ScopedTenant,
        token: &Secret,
        issuer: &Issuer,
    ) -> Result<TokenReading<RunPassToken>, DomainError>;
}

/// The one thing a run pass reaches, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassReach {
    /// A route, called by a Protected apps step.
    Route(RouteId),
    /// A stream route, reached by a Protected data step.
    StreamRoute(StreamRouteId),
}

/// The tenant and what a run pass claims, read without checking anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimedPass {
    /// Its `tid`.
    pub tenant_id: TenantId,
    /// What it names.
    pub reaches: PassReach,
}

/// A run pass, read whole: one call of a workflow run, acting as its
/// person, on one route or stream route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunPassToken {
    /// The call it was made for, its `jti`.
    pub call_id: ActionCallId,
    /// The person the run acts for, its `sub`.
    pub user_id: UserId,
    /// The one thing it reaches.
    pub reaches: PassReach,
    /// When it stops being valid, its `exp`.
    pub expires_at: OffsetDateTime,
}

/// Dyn-safe port checking a consumer's own token against the keys the
/// consumer publishes. The keys are fetched with a timeout of a few
/// seconds and may be cached; a fetch that hangs fails the check.
#[async_trait]
pub trait ConsumerTokenVerifier: Send + Sync {
    /// What `token` says, once it checks out under the keys published at
    /// `keys_at` for `expected`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the keys cannot be
    /// fetched in time.
    async fn verify(
        &self,
        token: &Secret,
        keys_at: &HttpsUrl,
        expected: ExpectedToken<'_>,
    ) -> Result<TokenReading<ConsumerToken>, DomainError>;
}

/// Port reading a presented consumer API key into what finds and checks
/// its consumer, under the key consumer keys are digested with.
pub trait ConsumerKeyDigests: Send + Sync {
    /// The prefix and digest of `key`, or `None` when it does not have the
    /// shape of a consumer's API key.
    fn presented(&self, key: &Secret) -> Option<PresentedKey>;
}
