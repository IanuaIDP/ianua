//! Authenticate: who a request at the gateway comes from, proven from the
//! one credential it presents, for the gateway's identity stage.
//!
//! A route taking client certificates takes nothing else: a bearer token,
//! however valid, is not read there. Elsewhere the credential decides:
//!
//! - a bearer token is a consumer's API key when it has one's shape, a
//!   consumer's own token when it claims another issuer than the tenant,
//!   and otherwise a token the tenant signed, for a person or an agent;
//! - an API key header carries a consumer's key;
//! - the session cookie carries a token the tenant signed, and must show it
//!   was not forged by another site;
//! - an app session cookie is held to its host, the sign-in that opened it
//!   and a session that must still be live;
//! - with no credential, a client certificate the handshake verified signs
//!   its consumer in;
//! - on the workflow listener, a bearer is a run pass, taken only on a
//!   route open to workflows and the one it was made for.
//!
//! Deny by default. A route whose policy is unknown needs a caller, one
//! whose service pins no audience takes no token as identity, one with no
//! issuer takes no token at all, and any check that fails refuses.

use std::sync::Arc;

use ianua_domain::domains::proxy::request::context::RouteRequirements;
use ianua_domain::domains::proxy::request::cross_site::PageOrigin;
use ianua_domain::domains::routing::backend::upstream::{RouteIdentity, TokenAudience};
use ianua_domain::types::{CertificateFingerprint, Fact};

use crate::context::QuotaCharge;
use crate::ports::authentication::{ExpectedToken, PresentedTokens, TenantToken};
use crate::ports::authorization::AccessRecordStore;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::oauth::sender::DpopHeader;
use crate::use_cases::proxy::credentials::agent::{self, AgentPorts};
use crate::use_cases::proxy::credentials::checking::{Bearer, Checking};
use crate::use_cases::proxy::credentials::consumer::{self, ConsumerPorts, ForeignToken};
use crate::use_cases::proxy::credentials::outcome::{Identification, Refusal, read};
use crate::use_cases::proxy::credentials::person::{self, PersonPorts};
use crate::use_cases::proxy::credentials::presented::{Presented, RequestTarget};
use crate::use_cases::proxy::credentials::run_pass;

/// A request at the gateway, with the credential the gateway extracted
/// from it.
#[derive(Clone)]
pub struct AuthenticateRequest {
    /// The one credential it presents.
    pub presented: Presented,
    /// The client certificate the TLS handshake verified, if any.
    pub certificate: Fact<CertificateFingerprint>,
    /// Its `DPoP` header.
    pub dpop: DpopHeader,
    /// Where it was sent.
    pub target: RequestTarget,
    /// What its matched route asks of it.
    pub route: RouteRequirements,
}

/// The ports [`AuthenticateUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AuthenticatePorts {
    /// Reads the tokens the tenant signed.
    pub tokens: Arc<dyn PresentedTokens>,
    /// What callers hold, from the tenant's records.
    pub access_records: Arc<dyn AccessRecordStore>,
    /// Checks a person's credential still stands.
    pub people: PersonPorts,
    /// Checks an agent may still act.
    pub agents: AgentPorts,
    /// Signs consumers in.
    pub consumers: ConsumerPorts,
}

/// Proves who a request at the gateway comes from.
pub struct AuthenticateUseCase {
    ports: AuthenticatePorts,
}

/// What a request offers to prove its caller with.
struct Offered {
    presented: Presented,
    certificate: Fact<CertificateFingerprint>,
    dpop: DpopHeader,
}

impl AuthenticateUseCase {
    /// A use case checking through `ports`.
    #[must_use]
    pub fn new(ports: AuthenticatePorts) -> Self {
        Self { ports }
    }

    /// Who `request` comes from, checked again on a connection that was
    /// admitted and counted when it opened: the same check as
    /// [`Query::execute`], but a consumer's quota is not counted again.
    ///
    /// # Errors
    ///
    /// - The refusals [`Query::execute`] lists, but for
    ///   [`Refusal::QuotaSpent`].
    pub(crate) async fn rechecked(
        &self,
        tenant: &ScopedTenant,
        request: AuthenticateRequest,
    ) -> Result<Identification, Refusal> {
        self.identified(tenant, request, QuotaCharge::AlreadyCounted)
            .await
    }

    /// Who `request` comes from, a consumer counted against its quota as
    /// `charge` says.
    async fn identified(
        &self,
        tenant: &ScopedTenant,
        request: AuthenticateRequest,
        charge: QuotaCharge,
    ) -> Result<Identification, Refusal> {
        let AuthenticateRequest {
            presented,
            certificate,
            dpop,
            target,
            route,
        } = request;
        let checking = Checking {
            tenant,
            target: &target,
            route: &route,
            tokens: self.ports.tokens.as_ref(),
            records: self.ports.access_records.as_ref(),
            charge,
        };
        match route.identity {
            RouteIdentity::ClientCertificate => self.by_certificate(&checking, &certificate).await,
            RouteIdentity::Token => {
                let offered = Offered {
                    presented,
                    certificate,
                    dpop,
                };
                self.by_offered(&checking, offered).await
            }
        }
    }

    /// The consumer of the client certificate, the only identity a
    /// certificate route takes.
    async fn by_certificate(
        &self,
        checking: &Checking<'_>,
        certificate: &Fact<CertificateFingerprint>,
    ) -> Result<Identification, Refusal> {
        let Fact::Known(fingerprint) = certificate else {
            return Err(Refusal::Missing);
        };
        consumer::by_certificate(&self.ports.consumers, checking, fingerprint).await
    }

    /// The caller of the credential a token route was offered.
    async fn by_offered(
        &self,
        checking: &Checking<'_>,
        offered: Offered,
    ) -> Result<Identification, Refusal> {
        let dpop = offered.dpop;
        match offered.presented {
            Presented::Nothing => self.by_nothing(checking, &offered.certificate).await,
            Presented::Bearer(token) => self.by_bearer(checking, Bearer { token, dpop }).await,
            Presented::ApiKey(key) => consumer::by_key(&self.ports.consumers, checking, &key).await,
            Presented::SessionCookie { token, csrf } => {
                checking.ensure_not_forged(PageOrigin::Elsewhere, csrf)?;
                self.by_bearer(checking, Bearer { token, dpop }).await
            }
            Presented::AppSession(cookie) => {
                person::by_app_session(&self.ports.people, checking, cookie).await
            }
            Presented::RunPass(token) => {
                run_pass::by_run_pass(&self.ports.people, checking, &token).await
            }
        }
    }

    /// The consumer of a client certificate presented alone, or nobody
    /// where the route lets anyone through.
    async fn by_nothing(
        &self,
        checking: &Checking<'_>,
        certificate: &Fact<CertificateFingerprint>,
    ) -> Result<Identification, Refusal> {
        if let Fact::Known(fingerprint) = certificate {
            return consumer::by_certificate(&self.ports.consumers, checking, fingerprint).await;
        }
        anonymous_where_open(checking.route)
    }

    /// The caller of a bearer token, sorted by what it turns out to be.
    async fn by_bearer(
        &self,
        checking: &Checking<'_>,
        bearer: Bearer,
    ) -> Result<Identification, Refusal> {
        if bearer.token.is_empty() {
            return Err(Refusal::Invalid);
        }
        if let Some(key) = self.ports.consumers.keys.presented(&bearer.token) {
            return consumer::by_digest(&self.ports.consumers, checking, key).await;
        }
        let TokenAudience::Pinned(audience) = &checking.route.token_audience else {
            return anonymous_where_unpinned(checking.route);
        };
        let issuer = checking.issuer()?;
        match self.ports.tokens.claimed(&bearer.token) {
            Some(claimed) if claimed.issuer != *issuer => {
                let foreign = ForeignToken {
                    token: &bearer.token,
                    claimed,
                    audience,
                };
                consumer::by_token(&self.ports.consumers, checking, foreign).await
            }
            Some(_) | None => {
                let expected = ExpectedToken { issuer, audience };
                self.by_tenant_token(checking, bearer, expected).await
            }
        }
    }

    /// The person or agent a token the tenant signed names.
    async fn by_tenant_token(
        &self,
        checking: &Checking<'_>,
        bearer: Bearer,
        expected: ExpectedToken<'_>,
    ) -> Result<Identification, Refusal> {
        let reading = checking
            .tokens
            .read_bearer(checking.tenant, &bearer.token, expected)
            .await
            .map_err(Refusal::unavailable)?;
        match read(reading)? {
            TenantToken::Person(token) => {
                person::by_token(&self.ports.people, checking, token, bearer).await
            }
            TenantToken::Agent(token) => {
                agent::by_token(&self.ports.agents, checking, *token, bearer).await
            }
        }
    }
}

impl Query for AuthenticateUseCase {
    type Caller = ScopedTenant;
    type Input = AuthenticateRequest;
    type Output = Result<Identification, Refusal>;

    /// Who `request`, sent to `tenant`, comes from.
    ///
    /// Missing, invalid, withdrawn or uncheckable credentials are refused.
    /// A public route accepts a request without credentials as anonymous.
    ///
    /// # Errors
    ///
    /// - [`Refusal::Missing`] for missing required identity/certificate; [`Refusal::Invalid`], [`Refusal::Expired`], [`Refusal::WrongIssuer`], [`Refusal::WrongAudience`] or [`Refusal::WrongHost`] for unusable credentials.
    /// - [`Refusal::UnknownSubject`] or [`Refusal::Inactive`] for no holder able to sign in; [`Refusal::Revoked`] for withdrawn backing access.
    /// - [`Refusal::CrossSite`] for a cross-site cookie mutation without CSRF proof; [`Refusal::DpopMismatch`] for a missing bound-key proof.
    /// - [`Refusal::QuotaSpent`] for an exhausted consumer quota; [`Refusal::Unavailable`] for store, key or counter failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        request: AuthenticateRequest,
    ) -> Result<Identification, Refusal> {
        self.identified(tenant, request, QuotaCharge::PerRequest)
            .await
    }
}

/// Nobody, where the route lets anyone through; a refusal for want of a
/// credential where it needs a caller, or its policy is unknown.
fn anonymous_where_open(route: &RouteRequirements) -> Result<Identification, Refusal> {
    match &route.policy {
        Fact::Known(policy) if !policy.requires_auth() => Ok(Identification::Anonymous),
        Fact::Known(_) | Fact::Unknown => Err(Refusal::Missing),
    }
}

/// What a token is worth on a route whose service pins no audience: the
/// service would take a token minted for any of the tenant's clients, so
/// none is taken as identity. A public route goes on without it; any other
/// refuses it.
fn anonymous_where_unpinned(route: &RouteRequirements) -> Result<Identification, Refusal> {
    anonymous_where_open(route).map_err(|_| Refusal::WrongAudience)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use async_trait::async_trait;
    use ianua_domain::domains::agents::authority::capability::{
        ActionApproval, McpGrant, RequestBudget,
    };
    use ianua_domain::domains::agents::identity::standing::AgentStanding;
    use ianua_domain::domains::agents::identity::token_attack::KeyProofFault;
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::authorization::permission::{SystemPermission, UserAction};
    use ianua_domain::domains::authorization::policy::claims::{Claim, ClaimName, ClaimValue};
    use ianua_domain::domains::consumers::consumer::Consumer;
    use ianua_domain::domains::crypto::jwk::JwkComponents;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::oauth::clients::client::GrantType;
    use ianua_domain::domains::oauth::grants::access_token::{AccessToken, TokenSubject};
    use ianua_domain::domains::oauth::grants::token_binding::JwkThumbprint;
    use ianua_domain::domains::proxy::access::question::DpopBinding;
    use ianua_domain::domains::proxy::request::context::{
        AgentLimits, Caller, ConsumerCredential, KeyBinding, Metering, UserSignIn,
    };
    use ianua_domain::domains::proxy::request::cross_site::CsrfEcho;
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::domains::routing::route::WorkflowUse;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::shared::errors::DomainError;
    use ianua_domain::shared::model::restriction::Restriction;
    use ianua_domain::shared::security::secret::Secret;
    use ianua_domain::types::{
        ActionCallId, AgentId, Audience, DelegationId, DomainName, Expiry, FederatedSubject,
        HttpMethod, HttpUrl, Issuer, PermissionName, PrincipalRef, RouteId, Scope, Seconds,
        ServiceId, SessionId, StreamRouteId, TokenId, TrustedDeviceId, UserId,
    };
    use time::OffsetDateTime;

    use super::*;
    use crate::ports::TenantScoped;
    use crate::ports::agents::DelegationRevocationCheck;
    use crate::ports::authentication::{
        AgentToken, AppSessionClaim, AppSessionToken, ClaimedToken, ConsumerToken, IssuedUnder,
        PassReach, PersonToken, RunPassToken, TokenFault, TokenReading,
    };
    use crate::ports::authorization::AccessRecords;
    use crate::ports::oauth::SignedDpopProof;
    use crate::test_support::agents::{FakeAgentStandings, FakeDelegationRevocations};
    use crate::test_support::authentication::{
        FakeAnswer, FakeAppSessionCheck, FakeConsumerTokenVerifier, FakePresentedTokens,
    };
    use crate::test_support::authorization::{
        FakeAccessRecordStore, stored_assignment, stored_role,
    };
    use crate::test_support::consumers::{
        PARTNER_ISSUER, PARTNER_SUBJECT, billing_sync, billing_sync_expiring, certificate_holder,
        consumer_holding, consumers_of_test_tenant, partner_feed, sign_in_of,
    };
    use crate::test_support::identity::{FakeUserStore, stored_user};
    use crate::test_support::oauth::{
        FakeAccessTokenStore, FakeDpopReplayGuard, FakeDpopVerifier, TEST_ACCESS_TOKEN,
        TokenEndpoint, access_row, stored_client, test_issuer,
    };
    use crate::test_support::{block_on, test_ctx};
    use crate::use_cases::oauth::flows::ResolveAccessTokenUseCase;
    use crate::use_cases::oauth::sender::SenderProofPorts;
    use crate::use_cases::proxy::credentials::{AppSessionCookie, KeyMismatch, Proven};

    const VIEW_USERS: SystemPermission = SystemPermission::Users(UserAction::View);

    /// Where every test request is sent.
    const TARGET: &str = "https://reports.acme.test/reports";

    /// The audience of the reports app, which its routes pin.
    fn reports() -> Audience {
        Audience::new("reports-app").unwrap()
    }

    fn in_an_hour() -> OffsetDateTime {
        clock::now() + time::Duration::hours(1)
    }

    /// A route of the reports app that needs a signed-in caller.
    fn route() -> RouteRequirements {
        RouteRequirements {
            expected_issuer: Fact::Known(test_issuer()),
            token_audience: TokenAudience::Pinned(reports()),
            policy: Fact::Known(RoutePolicy::Authenticated),
            ..RouteRequirements::default()
        }
    }

    /// A `GET` to the reports app presenting `presented`.
    fn request(presented: Presented) -> AuthenticateRequest {
        AuthenticateRequest {
            presented,
            certificate: Fact::Unknown,
            dpop: DpopHeader::NotSent,
            target: RequestTarget {
                method: HttpMethod::Get,
                url: HttpUrl::new(TARGET).unwrap(),
            },
            route: route(),
        }
    }

    /// [`request`], sent as a `POST`.
    fn posted(presented: Presented) -> AuthenticateRequest {
        let mut request = request(presented);
        request.target.method = HttpMethod::Post;
        request
    }

    fn bearer() -> Presented {
        Presented::Bearer(Secret::new("a.signed.token"))
    }

    fn session_of(user_id: UserId) -> AppSessionClaim {
        AppSessionClaim {
            session_id: SessionId::new(),
            user_id,
            service_id: ServiceId::new(),
            idle_timeout: None,
            signed_in_from: Fact::Unknown,
        }
    }

    /// A token the tenant signed for `user_id`, reading `read`, at AAL2.
    fn person_token(user_id: UserId, issued_under: IssuedUnder) -> TenantToken {
        TenantToken::Person(PersonToken {
            user_id,
            scopes: vec![Scope::new("read").unwrap()],
            assurance: Fact::Known(AssuranceLevel::Aal2),
            expires_at: in_an_hour(),
            issued_under,
            claims: Vec::new(),
        })
    }

    /// The bearer token an app's page fetched for `user_id`'s session.
    fn app_token(user_id: UserId) -> TenantToken {
        person_token(user_id, IssuedUnder::AppSession(session_of(user_id)))
    }

    fn limits(key_binding: KeyBinding) -> AgentLimits {
        AgentLimits {
            intent_envelope: Restriction::Unrestricted,
            mcp: McpGrant::default(),
            resource_scope: Restriction::Unrestricted,
            max_data_class: Restriction::Unrestricted,
            key_binding,
            approval: ActionApproval::NotRequired,
            metering: Metering::Unmetered,
        }
    }

    /// The key the report runner holds.
    fn runner_key() -> KeyBinding {
        KeyBinding::Key(JwkComponents::Okp {
            kid: String::new(),
            crv: "Ed25519".to_owned(),
            x: "runner-public-key".to_owned(),
        })
    }

    fn runner_thumbprint() -> JwkThumbprint {
        JwkThumbprint::new("r".repeat(43)).unwrap()
    }

    /// The report runner's task token, granting `reports:read`.
    fn agent_token(key_binding: KeyBinding, bound_key: Option<JwkThumbprint>) -> AgentToken {
        AgentToken {
            agent_id: AgentId::new(),
            delegation_id: DelegationId::new(),
            acting_for: PrincipalRef::User(UserId::new()),
            permissions: vec![PermissionName::new("reports:read").unwrap()],
            limits: limits(key_binding),
            bound_key,
            expires_at: in_an_hour(),
        }
    }

    /// A proof the runner signed with `key` for a `GET` to [`TARGET`].
    fn proof_by(key: JwkThumbprint) -> SenderProofPorts {
        let signed = SignedDpopProof {
            thumbprint: key,
            jti: TokenId::new("proof-1").unwrap(),
            method: "GET".to_owned(),
            url: TARGET.to_owned(),
            issued_at: clock::now(),
        };
        SenderProofPorts {
            dpop_verifier: Arc::new(FakeDpopVerifier::accepting(signed)),
            dpop_replays: Arc::new(FakeDpopReplayGuard::default()),
        }
    }

    /// An app session cookie on the reports host, sent from `origin` with
    /// `csrf`.
    fn app_cookie(origin: PageOrigin, csrf: CsrfEcho) -> Presented {
        Presented::AppSession(AppSessionCookie {
            token: Secret::new("a.session.cookie"),
            host: DomainName::new("reports.acme.test").unwrap(),
            owner: ServiceId::new(),
            audience: reports(),
            origin,
            csrf,
        })
    }

    /// The gateway's view of the acme tenant: Ann, active and a viewer,
    /// and every other port as its neutral fake.
    struct World {
        ann: UserId,
        tokens: FakePresentedTokens,
        users: Arc<FakeUserStore>,
        records: AccessRecords,
        sessions: Arc<FakeAppSessionCheck>,
        grants: Arc<ResolveAccessTokenUseCase>,
        standings: Arc<FakeAgentStandings>,
        revocations: Arc<dyn DelegationRevocationCheck>,
        sender: SenderProofPorts,
        consumers: ConsumerPorts,
    }

    impl World {
        fn new() -> Self {
            let ann = UserId::new();
            let viewer = stored_role("viewer", vec![VIEW_USERS], Vec::new());
            let records = AccessRecords {
                assignments: vec![stored_assignment(PrincipalRef::User(ann), *viewer.id())],
                roles: vec![viewer],
                ..AccessRecords::default()
            };
            Self {
                ann,
                tokens: FakePresentedTokens::default(),
                users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                records,
                sessions: Arc::new(FakeAppSessionCheck(AtomicBool::new(true))),
                grants: PersonPorts::fakes().grants,
                standings: Arc::new(FakeAgentStandings::default()),
                revocations: Arc::new(FakeDelegationRevocations::default()),
                sender: SenderProofPorts::fakes(),
                consumers: ConsumerPorts::fakes(),
            }
        }

        /// The world where the reader takes every bearer token as `token`.
        fn reading(token: TenantToken) -> Self {
            Self {
                tokens: FakePresentedTokens::reading_bearer(token),
                ..Self::new()
            }
        }

        /// The world where `consumer` holds the viewer's right and signs in
        /// with its own credential.
        fn with_consumer(mut self, consumer: Consumer<ResolvedTenant>) -> Self {
            self.records = consumer_holding(consumer.id(), &[VIEW_USERS]);
            self.consumers = ConsumerPorts {
                consumer_store: consumers_of_test_tenant(consumer.clone()),
                authorities: sign_in_of(consumer, &[VIEW_USERS]),
                ..ConsumerPorts::fakes()
            };
            self
        }

        fn authenticate(self, request: AuthenticateRequest) -> Result<Identification, Refusal> {
            let tenant = test_ctx().tenant_id();
            let use_case = AuthenticateUseCase::new(AuthenticatePorts {
                tokens: Arc::new(self.tokens),
                access_records: Arc::new(FakeAccessRecordStore::holding(tenant, self.records)),
                people: PersonPorts {
                    user_store: self.users,
                    app_sessions: self.sessions,
                    grants: self.grants,
                },
                agents: AgentPorts {
                    standings: self.standings,
                    revocations: self.revocations,
                    sender: self.sender,
                },
                consumers: self.consumers,
            });
            block_on(use_case.execute(&test_ctx().tenant(), request))
        }
    }

    /// The caller `result` proved.
    fn proven_in(result: Result<Identification, Refusal>) -> Proven {
        match result {
            Ok(Identification::Proven(proven)) => *proven,
            other => panic!("expected a proven caller, got {other:?}"),
        }
    }

    fn user_of(proven: &Proven) -> (UserId, UserSignIn) {
        match proven.verified.caller {
            Caller::User { user_id, sign_in } => (user_id, sign_in),
            Caller::Agent { .. } | Caller::Consumer { .. } => panic!("not a person"),
        }
    }

    fn consumer_of(proven: &Proven) -> ConsumerCredential {
        match proven.verified.caller {
            Caller::Consumer { credential, .. } => credential,
            Caller::User { .. } | Caller::Agent { .. } => panic!("not a consumer"),
        }
    }

    /// A revocation check whose store cannot be read.
    struct UnreachableRevocations;

    impl TenantScoped for UnreachableRevocations {}

    #[async_trait]
    impl DelegationRevocationCheck for UnreachableRevocations {
        async fn is_revoked(
            &self,
            _: &ScopedTenant,
            _: &DelegationId,
        ) -> Result<bool, DomainError> {
            Err(DomainError::infra_msg("the delegations cannot be read"))
        }
    }

    /// An authenticated route refuses a request without credentials as missing
    /// identity.
    #[test]
    fn a_request_with_nothing_is_refused_where_a_caller_is_needed() {
        let result = World::new().authenticate(request(Presented::Nothing));

        assert_eq!(result.unwrap_err(), Refusal::Missing);
    }

    /// An unknown route policy does not admit an anonymous request; it requires
    /// a credential.
    #[test]
    fn a_route_whose_policy_is_unknown_needs_a_caller() {
        let mut unknown = request(Presented::Nothing);
        unknown.route.policy = Fact::Unknown;

        let result = World::new().authenticate(unknown);

        assert_eq!(result.unwrap_err(), Refusal::Missing);
    }

    /// A visitor opens a public page with nothing. They go on as nobody.
    #[test]
    fn a_public_route_lets_a_request_with_nothing_through_as_anonymous() {
        let mut public = request(Presented::Nothing);
        public.route.policy = Fact::Known(RoutePolicy::Public);

        let result = World::new().authenticate(public);

        assert!(matches!(result, Ok(Identification::Anonymous)));
    }

    /// Ann's page fetched a token for the reports app under her session.
    /// She is proven, with her session, the viewer role from the records,
    /// the token's scope and AAL2, until the token runs out.
    #[test]
    fn a_persons_token_proves_them_with_what_the_records_give() {
        let world = World::new();
        let ann = world.ann;
        let world = World {
            tokens: FakePresentedTokens::reading_bearer(app_token(ann)),
            ..world
        };

        let proven = proven_in(world.authenticate(request(bearer())));

        let (user_id, sign_in) = user_of(&proven);
        assert_eq!(user_id, ann);
        assert!(matches!(sign_in, UserSignIn::Session(_)));
        assert!(!proven.claims.permissions.is_empty());
        assert_eq!(proven.claims.role_names.len(), 1);
        assert_eq!(proven.claims.role_ids.len(), 1);
        assert_eq!(proven.claims.scopes, vec![Scope::new("read").unwrap()]);
        assert_eq!(proven.claims.current_aal, Fact::Known(AssuranceLevel::Aal2));
        assert!(matches!(proven.verified.expiry, Expiry::At(_)));
    }

    /// Ann's token asserts she is in finance. The proof carries that claim
    /// for the tenant's policy, and what the records give her, read once,
    /// for the access decision to take as it is.
    #[test]
    fn a_persons_proof_carries_the_claims_and_holdings_it_was_made_from() {
        let world = World::new();
        let ann = world.ann;
        let finance = Claim::new(
            ClaimName::new("department").unwrap(),
            ClaimValue::new("finance").unwrap(),
        );
        let TenantToken::Person(mut token) = app_token(ann) else {
            panic!("a person's token");
        };
        token.claims = vec![finance.clone()];
        let world = World {
            tokens: FakePresentedTokens::reading_bearer(TenantToken::Person(token)),
            ..world
        };

        let proven = proven_in(world.authenticate(request(bearer())));

        assert_eq!(proven.claims.asserted, Fact::Known(vec![finance]));
        assert!(proven.held.holdings().holds(VIEW_USERS));
        assert_eq!(proven.held.roles(), proven.claims.role_ids.as_slice());
    }

    /// The token reader's expiry refusal reaches the caller as expired identity.
    #[test]
    fn an_expired_token_is_refused() {
        let world = World {
            tokens: FakePresentedTokens::refusing(TokenFault::Expired),
            ..World::new()
        };

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::Expired);
    }

    /// A token minted for billing is refused on the reports route for the wrong
    /// audience.
    #[test]
    fn a_token_for_another_audience_is_refused() {
        let world = World::new();
        let ann = world.ann;
        let world = World {
            tokens: FakePresentedTokens {
                minted_for: Some(Audience::new("billing-app").unwrap()),
                ..FakePresentedTokens::reading_bearer(app_token(ann))
            },
            ..world
        };

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::WrongAudience);
    }

    /// Without a pinned audience, an authenticated route rejects the token
    /// while a public route treats the same presentation as anonymous.
    #[test]
    fn a_service_pinning_no_audience_takes_no_token() {
        let mut needs_caller = request(bearer());
        needs_caller.route.token_audience = TokenAudience::NoTokenAccepted;
        let mut public = request(bearer());
        public.route.token_audience = TokenAudience::NoTokenAccepted;
        public.route.policy = Fact::Known(RoutePolicy::Public);

        let refused = World::new().authenticate(needs_caller);
        let anonymous = World::new().authenticate(public);

        assert_eq!(refused.unwrap_err(), Refusal::WrongAudience);
        assert!(matches!(anonymous, Ok(Identification::Anonymous)));
    }

    /// A token cannot prove identity while the route's expected issuer is
    /// unknown.
    #[test]
    fn no_token_is_taken_while_the_issuer_is_unknown() {
        let world = World::reading(app_token(UserId::new()));
        let mut unissued = request(bearer());
        unissued.route.expected_issuer = Fact::Unknown;

        let result = world.authenticate(unissued);

        assert_eq!(result.unwrap_err(), Refusal::WrongIssuer);
    }

    /// A token naming an absent account is refused as an unknown subject.
    #[test]
    fn a_token_for_nobody_the_tenant_knows_is_refused() {
        let world = World::reading(app_token(UserId::new()));

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::UnknownSubject);
    }

    /// A validly read token cannot authenticate a deactivated account.
    #[test]
    fn a_deactivated_persons_token_is_refused() {
        let world = World::new();
        let ann = world.ann;
        let users = Arc::new(FakeUserStore::empty());
        users.add(stored_user(ann, "ann@acme.test", UserStatus::Deactivated));
        let world = World {
            tokens: FakePresentedTokens::reading_bearer(app_token(ann)),
            users,
            ..world
        };

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::Inactive);
    }

    /// An app token backed by an ended session is refused as revoked.
    #[test]
    fn a_token_whose_app_session_ended_is_refused() {
        let world = World::new();
        let ann = world.ann;
        let world = World {
            tokens: FakePresentedTokens::reading_bearer(app_token(ann)),
            sessions: Arc::new(FakeAppSessionCheck(AtomicBool::new(false))),
            ..world
        };

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::Revoked);
    }

    /// Unreadable token-verification keys produce an unavailable refusal.
    #[test]
    fn a_token_is_refused_when_the_keys_cannot_be_read() {
        let world = World {
            tokens: FakePresentedTokens::unreachable(),
            ..World::new()
        };

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::Unavailable);
    }

    /// The reader app presents Ann's OAuth access token, whose grant
    /// stands. Ann is proven, signed in by token.
    #[test]
    fn a_standing_oauth_grant_proves_its_person() {
        let reader = stored_client("Reader", &[GrantType::AuthorizationCode]);
        let mut endpoint = TokenEndpoint::serving(reader);
        let row = access_row(&endpoint.client, TokenSubject::Person(endpoint.ann));
        let token = AccessToken::reconstitute(row).unwrap();
        endpoint.tokens = Arc::new(FakeAccessTokenStore::holding(&test_ctx().tenant(), token));
        let ann = endpoint.ann;
        let world = World {
            tokens: FakePresentedTokens::reading_bearer(person_token(ann, IssuedUnder::Grant)),
            users: endpoint.users.clone(),
            grants: endpoint.resolver(),
            ..World::new()
        };
        let presented = Presented::Bearer(Secret::new(TEST_ACCESS_TOKEN));

        let proven = proven_in(world.authenticate(request(presented)));

        assert_eq!(user_of(&proven), (ann, UserSignIn::Token));
    }

    /// An OAuth token without a live backing grant is refused as revoked.
    #[test]
    fn a_token_whose_grant_was_revoked_is_refused() {
        let world = World::new();
        let ann = world.ann;
        let world = World {
            tokens: FakePresentedTokens::reading_bearer(person_token(ann, IssuedUnder::Grant)),
            ..world
        };

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::Revoked);
    }

    /// The report runner presents its bearer task token. It is proven as
    /// the agent under its delegation, with what the delegation granted.
    #[test]
    fn a_task_token_proves_its_agent() {
        let token = agent_token(KeyBinding::Bearer, None);
        let agent_id = token.agent_id;
        let world = World::reading(TenantToken::Agent(Box::new(token)));

        let proven = proven_in(world.authenticate(request(bearer())));

        assert!(matches!(
            proven.verified.caller,
            Caller::Agent { agent_id: proven_id, .. } if proven_id == agent_id
        ));
        assert_eq!(
            proven.claims.permissions,
            vec![PermissionName::new("reports:read").unwrap()]
        );
    }

    /// The runner's delegation allows 100 requests a minute. The budget the
    /// token states reaches the proven caller, for the budget stage to count.
    #[test]
    fn a_task_tokens_budget_reaches_the_proven_agent() {
        let budget = RequestBudget::new(100, Seconds::new(60)).unwrap();
        let mut token = agent_token(KeyBinding::Bearer, None);
        token.limits.metering = Metering::Metered(budget);
        let world = World::reading(TenantToken::Agent(Box::new(token)));

        let proven = proven_in(world.authenticate(request(bearer())));

        assert!(matches!(
            &proven.verified.caller,
            Caller::Agent { limits, .. } if limits.metering == Metering::Metered(budget)
        ));
    }

    /// Revoking the runner's delegation makes its unexpired task token fail
    /// authentication as revoked.
    #[test]
    fn a_task_token_of_a_revoked_delegation_is_refused() {
        let token = agent_token(KeyBinding::Bearer, None);
        let revocations = Arc::new(FakeDelegationRevocations::default());
        revocations.revoke(&test_ctx().tenant(), token.delegation_id);
        let world = World {
            revocations,
            ..World::reading(TenantToken::Agent(Box::new(token)))
        };

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::Revoked);
    }

    /// A suspended agent's task token is refused as revoked.
    #[test]
    fn a_task_token_of_a_suspended_agent_is_refused() {
        let token = agent_token(KeyBinding::Bearer, None);
        let standings = Arc::new(FakeAgentStandings::default());
        standings.set(
            &test_ctx().tenant(),
            token.agent_id,
            AgentStanding::Suspended,
        );
        let world = World {
            standings,
            ..World::reading(TenantToken::Agent(Box::new(token)))
        };

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::Revoked);
    }

    /// An unreadable delegation revocation store makes task-token
    /// authentication unavailable.
    #[test]
    fn a_task_token_is_refused_when_its_delegation_cannot_be_read() {
        let token = agent_token(KeyBinding::Bearer, None);
        let world = World {
            revocations: Arc::new(UnreachableRevocations),
            ..World::reading(TenantToken::Agent(Box::new(token)))
        };

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::Unavailable);
    }

    /// The runner presents its key-bound token with a fresh proof of its
    /// key for this request. It is proven, and the proof says its key was
    /// shown, for a policy that asks for one.
    #[test]
    fn a_bound_task_token_with_its_keys_proof_proves_its_agent() {
        let token = agent_token(runner_key(), Some(runner_thumbprint()));
        let world = World {
            sender: proof_by(runner_thumbprint()),
            ..World::reading(TenantToken::Agent(Box::new(token)))
        };
        let mut proved = request(bearer());
        proved.dpop = DpopHeader::Sent(Secret::new("a.dpop.proof"));

        let result = world.authenticate(proved);

        assert_eq!(proven_in(result).binding, DpopBinding::Bound);
    }

    /// An agent's bearer token proves its agent without any key, so the
    /// proof says no key was shown.
    #[test]
    fn a_bearer_task_token_proves_no_key() {
        let token = agent_token(KeyBinding::Bearer, None);
        let world = World::reading(TenantToken::Agent(Box::new(token)));

        let result = world.authenticate(request(bearer()));

        assert_eq!(proven_in(result).binding, DpopBinding::Unbound);
    }

    /// A bound task token with no proof or another key's proof is refused;
    /// each mismatch identifies the agent and the specific proof fault.
    #[test]
    fn a_bound_task_token_without_its_keys_proof_is_refused() {
        let agent_id = AgentId::new();
        let bound = || AgentToken {
            agent_id,
            ..agent_token(runner_key(), Some(runner_thumbprint()))
        };
        let bare = World::reading(TenantToken::Agent(Box::new(bound())));
        let mallorys = World {
            sender: proof_by(JwkThumbprint::new("m".repeat(43)).unwrap()),
            ..World::reading(TenantToken::Agent(Box::new(bound())))
        };
        let mut with_proof = request(bearer());
        with_proof.dpop = DpopHeader::Sent(Secret::new("a.dpop.proof"));

        let unproved = bare.authenticate(request(bearer()));
        let misproved = mallorys.authenticate(with_proof);

        let mismatch = |fault| Refusal::DpopMismatch(KeyMismatch { agent_id, fault });
        assert_eq!(unproved.unwrap_err(), mismatch(KeyProofFault::NotSent));
        assert_eq!(
            misproved.unwrap_err(),
            mismatch(KeyProofFault::ByAnotherKey)
        );
    }

    /// "billing-sync" sends its API key in the key header. It is proven as
    /// the consumer, with what its role gives.
    #[test]
    fn a_consumers_api_key_proves_it() {
        let world = World::new().with_consumer(billing_sync());
        let key = Presented::ApiKey(Secret::new("sk_live_abc.hash123"));

        let proven = proven_in(world.authenticate(request(key)));

        assert_eq!(consumer_of(&proven), ConsumerCredential::ApiKey);
        assert!(!proven.claims.permissions.is_empty());
    }

    /// "billing-sync"'s key was handed out until next week. The proof holds
    /// until then, so a tunnel opened with it closes when the key does.
    #[test]
    fn a_consumers_key_is_proven_until_it_expires() {
        let next_week = clock::now() + time::Duration::days(7);
        let world = World::new().with_consumer(billing_sync_expiring(Expiry::At(next_week)));
        let key = Presented::ApiKey(Secret::new("sk_live_abc.hash123"));

        let proven = proven_in(world.authenticate(request(key)));

        assert_eq!(proven.verified.expiry, Expiry::At(next_week));
    }

    /// A consumer key that expired yesterday identifies no known subject today.
    #[test]
    fn an_expired_consumer_key_is_refused() {
        let yesterday = clock::now() - time::Duration::days(1);
        let world = World::new().with_consumer(billing_sync_expiring(Expiry::At(yesterday)));
        let key = Presented::ApiKey(Secret::new("sk_live_abc.hash123"));

        let result = world.authenticate(request(key));

        assert_eq!(result.unwrap_err(), Refusal::UnknownSubject);
    }

    /// "billing-sync" sends its API key as a bearer token instead. It is
    /// read as the key it is, never as a JWT.
    #[test]
    fn an_api_key_sent_as_a_bearer_token_proves_its_consumer() {
        let world = World::new().with_consumer(billing_sync());
        let key = Presented::Bearer(Secret::new("sk_live_abc.hash123"));

        let proven = proven_in(world.authenticate(request(key)));

        assert_eq!(consumer_of(&proven), ConsumerCredential::ApiKey);
    }

    /// A guessed key under a known consumer prefix is refused as an unknown
    /// subject.
    #[test]
    fn a_wrong_key_under_a_known_prefix_is_refused() {
        let world = World::new().with_consumer(billing_sync());
        let guessed = Presented::ApiKey(Secret::new("sk_live_abc.guessed"));

        let result = world.authenticate(request(guessed));

        assert_eq!(result.unwrap_err(), Refusal::UnknownSubject);
    }

    /// The edge device's certificate route takes the certificate its
    /// handshake verified, and proves the device's consumer.
    #[test]
    fn a_client_certificate_proves_its_consumer() {
        let fingerprint = CertificateFingerprint::from_digest([7; 32]);
        let world = World::new().with_consumer(certificate_holder(fingerprint));
        let mut on_certificate_route = request(Presented::Nothing);
        on_certificate_route.route.identity = RouteIdentity::ClientCertificate;
        on_certificate_route.certificate = Fact::Known(fingerprint);

        let proven = proven_in(world.authenticate(on_certificate_route));

        assert_eq!(consumer_of(&proven), ConsumerCredential::Certificate);
    }

    /// A valid bearer token cannot replace the missing certificate on a
    /// certificate-only route.
    #[test]
    fn a_certificate_route_takes_no_token() {
        let world = World::new();
        let ann = world.ann;
        let world = World {
            tokens: FakePresentedTokens::reading_bearer(app_token(ann)),
            ..world
        };
        let mut on_certificate_route = request(bearer());
        on_certificate_route.route.identity = RouteIdentity::ClientCertificate;

        let result = world.authenticate(on_certificate_route);

        assert_eq!(result.unwrap_err(), Refusal::Missing);
    }

    /// "partner-feed" signs its own token for the reports app. Its keys
    /// check it, and it is proven as the consumer with the token's scopes,
    /// until the token runs out, since its credential never does.
    #[test]
    fn a_consumers_own_token_proves_it() {
        let issuer = Issuer::new(PARTNER_ISSUER).unwrap();
        let subject = FederatedSubject::new(PARTNER_SUBJECT).unwrap();
        let expires_at = in_an_hour();
        let mut world = World::new().with_consumer(partner_feed());
        world.consumers.verifier = Arc::new(FakeConsumerTokenVerifier(FakeAnswer::Answers(
            TokenReading::Read(ConsumerToken {
                issuer: issuer.clone(),
                subject: subject.clone(),
                scopes: vec![Scope::new("read").unwrap()],
                expires_at,
            }),
        )));
        world.tokens.claimed = Some(ClaimedToken { issuer, subject });

        let proven = proven_in(world.authenticate(request(bearer())));

        assert_eq!(consumer_of(&proven), ConsumerCredential::Token);
        assert_eq!(proven.claims.scopes, vec![Scope::new("read").unwrap()]);
        assert_eq!(proven.verified.expiry, Expiry::At(expires_at));
    }

    /// A token claiming an issuer absent from the tenant's consumers is
    /// refused as an unknown subject.
    #[test]
    fn a_token_claiming_an_unknown_consumer_is_refused() {
        let mut world = World::new();
        world.tokens.claimed = Some(ClaimedToken {
            issuer: Issuer::new("https://eve.example.test").unwrap(),
            subject: FederatedSubject::new("billing-sync").unwrap(),
        });

        let result = world.authenticate(request(bearer()));

        assert_eq!(result.unwrap_err(), Refusal::UnknownSubject);
    }

    /// Ann's browser posts from the app's own page with her app session
    /// cookie. She is proven by her session.
    #[test]
    fn an_app_session_cookie_from_its_own_page_proves_its_person() {
        let world = World::new();
        let ann = world.ann;
        let world = World {
            tokens: FakePresentedTokens::reading_session(AppSessionToken {
                claim: session_of(ann),
                assurance: Fact::Known(AssuranceLevel::Aal2),
                expires_at: in_an_hour(),
            }),
            ..world
        };
        let cookie = app_cookie(PageOrigin::Trusted, CsrfEcho::default());

        let proven = proven_in(world.authenticate(posted(cookie)));

        assert!(matches!(user_of(&proven), (id, UserSignIn::Session(_)) if id == ann));
    }

    /// Ann signed in from her remembered laptop, and both her app session
    /// cookie and the token her page fetched say so. The proof carries the
    /// laptop for a device posture check.
    #[test]
    fn a_session_credential_carries_the_device_it_was_signed_in_from() {
        let laptop = TrustedDeviceId::new();
        let from_laptop = |ann| AppSessionClaim {
            signed_in_from: Fact::Known(laptop),
            ..session_of(ann)
        };
        let by_cookie = World::new();
        let by_cookie = World {
            tokens: FakePresentedTokens::reading_session(AppSessionToken {
                claim: from_laptop(by_cookie.ann),
                assurance: Fact::Known(AssuranceLevel::Aal2),
                expires_at: in_an_hour(),
            }),
            ..by_cookie
        };
        let by_token = World::new();
        let by_token = World {
            tokens: FakePresentedTokens::reading_bearer(person_token(
                by_token.ann,
                IssuedUnder::AppSession(from_laptop(by_token.ann)),
            )),
            ..by_token
        };
        let cookie = app_cookie(PageOrigin::Trusted, CsrfEcho::default());

        let from_cookie = proven_in(by_cookie.authenticate(posted(cookie)));
        let from_token = proven_in(by_token.authenticate(request(bearer())));

        assert_eq!(from_cookie.claims.signed_in_from, Fact::Known(laptop));
        assert_eq!(from_token.claims.signed_in_from, Fact::Known(laptop));
    }

    /// Cross-site POST requests lacking CSRF proof are refused with either an
    /// app-session cookie or a session cookie.
    #[test]
    fn a_cross_site_cookie_post_is_refused() {
        let app_session = app_cookie(PageOrigin::Elsewhere, CsrfEcho::default());
        let session_cookie = Presented::SessionCookie {
            token: Secret::new("a.signed.token"),
            csrf: CsrfEcho::default(),
        };

        let from_app = World::new().authenticate(posted(app_session));
        let from_cookie = World::new().authenticate(posted(session_cookie));

        assert_eq!(from_app.unwrap_err(), Refusal::CrossSite);
        assert_eq!(from_cookie.unwrap_err(), Refusal::CrossSite);
    }

    /// An app-session reader's wrong-host refusal reaches the caller unchanged.
    #[test]
    fn an_app_session_from_another_host_is_refused() {
        let world = World {
            tokens: FakePresentedTokens::refusing(TokenFault::WrongHost),
            ..World::new()
        };
        let cookie = app_cookie(PageOrigin::Trusted, CsrfEcho::default());

        let result = world.authenticate(request(cookie));

        assert_eq!(result.unwrap_err(), Refusal::WrongHost);
    }

    /// The reports route, opened to workflows.
    fn open_route(route_id: RouteId) -> RouteRequirements {
        RouteRequirements {
            route_id: Fact::Known(route_id),
            workflow_use: WorkflowUse::Open,
            ..route()
        }
    }

    /// A pass made for one call of Ann's run, on `route_id`.
    fn pass_of(ann: UserId, route_id: RouteId) -> RunPassToken {
        RunPassToken {
            call_id: ActionCallId::new(),
            user_id: ann,
            reaches: PassReach::Route(route_id),
            expires_at: in_an_hour(),
        }
    }

    /// The world where the reader takes every run pass as `pass`.
    fn passing(world: World, pass: RunPassToken) -> World {
        World {
            tokens: FakePresentedTokens::reading_pass(pass),
            ..world
        }
    }

    /// A request on the workflow listener carrying a pass, to `route`.
    fn with_pass(route: RouteRequirements) -> AuthenticateRequest {
        AuthenticateRequest {
            route,
            ..request(Presented::RunPass(Secret::new("a.run.pass")))
        }
    }

    /// Ann's run reads the reports route, open to workflows, with a pass
    /// made for that route. She is proven, signed in through the run's
    /// call, holding the viewer role, with no assurance claimed for her.
    #[test]
    fn a_run_pass_proves_its_person_on_the_route_it_was_made_for() {
        let world = World::new();
        let (ann, reports) = (world.ann, RouteId::new());
        let pass = pass_of(ann, reports);
        let world = passing(world, pass);

        let proven = proven_in(world.authenticate(with_pass(open_route(reports))));

        assert_eq!(
            user_of(&proven),
            (ann, UserSignIn::WorkflowRun(pass.call_id))
        );
        assert_eq!(proven.claims.role_names.len(), 1);
        assert_eq!(proven.claims.current_aal, Fact::Unknown);
    }

    /// A run pass is refused for the wrong audience when its route is closed
    /// to workflows.
    #[test]
    fn a_run_pass_is_refused_on_a_route_closed_to_workflows() {
        let world = World::new();
        let reports = RouteId::new();
        let world = passing(world, pass_of(UserId::new(), reports));
        let closed = RouteRequirements {
            route_id: Fact::Known(reports),
            ..route()
        };

        let result = world.authenticate(with_pass(closed));

        assert_eq!(result.unwrap_err(), Refusal::WrongAudience);
    }

    /// Opening both routes to workflows does not let a run pass reach a route
    /// other than the one it names.
    #[test]
    fn a_run_pass_for_another_route_is_refused() {
        let world = World::new();
        let ann = world.ann;
        let world = passing(world, pass_of(ann, RouteId::new()));

        let result = world.authenticate(with_pass(open_route(RouteId::new())));

        assert_eq!(result.unwrap_err(), Refusal::WrongAudience);
    }

    /// A pass naming a stream route cannot authenticate on a web route open
    /// to workflows.
    #[test]
    fn a_run_pass_for_a_stream_route_reaches_no_route() {
        let world = World::new();
        let ann = world.ann;
        let route = RouteId::new();
        let pass = RunPassToken {
            reaches: PassReach::StreamRoute(StreamRouteId::new()),
            ..pass_of(ann, route)
        };
        let world = passing(world, pass);

        let result = world.authenticate(with_pass(open_route(route)));

        assert_eq!(result.unwrap_err(), Refusal::WrongAudience);
    }

    /// A run pass belonging to a deactivated person is refused as inactive.
    #[test]
    fn a_run_pass_of_a_deactivated_person_is_refused() {
        let world = World::new();
        let (ann, reports) = (world.ann, RouteId::new());
        let users = Arc::new(FakeUserStore::empty());
        users.add(stored_user(ann, "ann@acme.test", UserStatus::Deactivated));
        let world = World {
            users,
            ..passing(world, pass_of(ann, reports))
        };

        let result = world.authenticate(with_pass(open_route(reports)));

        assert_eq!(result.unwrap_err(), Refusal::Inactive);
    }

    /// An unavailable run-pass reader produces an unavailable refusal.
    #[test]
    fn a_run_pass_is_refused_when_the_keys_cannot_be_read() {
        let world = World {
            tokens: FakePresentedTokens {
                pass: FakeAnswer::Unreachable,
                ..FakePresentedTokens::default()
            },
            ..World::new()
        };

        let result = world.authenticate(with_pass(open_route(RouteId::new())));

        assert_eq!(result.unwrap_err(), Refusal::Unavailable);
    }

    /// A run pass rejected by the token reader is refused as invalid.
    #[test]
    fn a_run_pass_the_reader_refuses_is_refused() {
        let world = World::new();

        let result = world.authenticate(with_pass(open_route(RouteId::new())));

        assert_eq!(result.unwrap_err(), Refusal::Invalid);
    }
}
