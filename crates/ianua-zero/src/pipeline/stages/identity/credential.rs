//! The Identity stage: the request's credential handed to
//! `AuthenticateUseCase` as it arrived, and its answer enforced.
//!
//! The credential, the `DPoP` header and the address a proof must name are
//! read off the request by [`crate::request`]; the client certificate is
//! the one the handshake verified. A proven caller is recorded on the
//! context with what their credential carries, and handed on whole to the
//! Policy stage, which decides on what the proof read of them rather than
//! reading it again. Nobody passes only where the route is public.

use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::agents::enforcement::RecordStolenBindingRequest;
use ianua_app::use_cases::authentication::sessions::{SessionStanding, WatchUseRequest};
use ianua_app::use_cases::oauth::sender::DpopHeader;
use ianua_app::use_cases::proxy::credentials::{
    AuthenticateRequest, Identification, KeyMismatch, Proven, Refusal,
};
use ianua_domain::domains::proxy::request::context::{
    Caller, PipelineContext, RouteRequirements, UserSignIn,
};
use ianua_domain::domains::proxy::request::device::RequestDevice;
use ianua_domain::domains::proxy::stages::decision::StageDecision;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificateFingerprint, DenialStatus, Fact, IpAddress, SessionId};

use super::{IdentityStages, deny, pass};
use crate::listen::{ClientCertificate, ConnectionFacts};
use crate::pipeline::facts::RequestFacts;
use crate::request::{self, CredentialRefusal, ListenerRole};

/// What the Identity stage decided, and whom it established for the Policy
/// stage.
#[derive(Debug)]
pub(crate) struct IdentityOutcome {
    /// The decision the pipeline enforces.
    pub decision: StageDecision,
    /// Who the request comes from, with what they hold, as the access
    /// decision takes it. `None` exactly when the decision is a deny, so the
    /// Policy stage never decides on a caller nobody proved.
    pub identification: Option<Identification>,
}

impl IdentityOutcome {
    /// A refusal: nobody established.
    fn refused(decision: StageDecision) -> Self {
        Self {
            decision,
            identification: None,
        }
    }

    /// A pass, recorded as `code`, establishing `identification`.
    fn passed(code: &str, identification: Identification) -> Self {
        Self {
            decision: pass(code),
            identification: Some(identification),
        }
    }
}

impl IdentityStages {
    /// The Identity stage: who the request comes from, proven from the one
    /// credential it presents.
    ///
    /// A proven caller is recorded on `ctx` with their claims. Nobody
    /// passes on a public route alone. A credential the gateway cannot read
    /// one way only, and every refusal of the use case, is a deny.
    ///
    /// # Errors
    ///
    /// - [`DomainError::InvalidTransition`] when `ctx` already holds a
    ///   caller: the stage ran twice, and the request is refused rather
    ///   than given a second caller.
    pub(crate) async fn identity(
        &self,
        facts: &RequestFacts,
        ctx: &mut PipelineContext,
    ) -> Result<IdentityOutcome, DomainError> {
        let request = match authenticate_request(facts, &ctx.route) {
            Ok(request) => request,
            Err(unaskable) => return Ok(IdentityOutcome::refused(unaskable.denial())),
        };
        let identified = self.authenticate.execute(&facts.tenant, request).await;
        if let Err(Refusal::DpopMismatch(mismatch)) = &identified {
            self.record_stolen(facts, *mismatch).await;
        }
        let identified = self.watched(facts, &ctx.ip_address, identified).await;
        let outcome = settled(identified, ctx)?;
        ctx.device = RequestDevice::named_by(
            verified_certificate(&facts.connection),
            ctx.claims.signed_in_from,
        );
        Ok(outcome)
    }

    /// `identified`, unless the session behind it stopped looking like its
    /// holder, or could not be looked at. A person proved by a session has
    /// each use held against where it was last used, so a cookie copied to
    /// another country stops on its first request there. A look that fails
    /// or runs out refuses the request, within the record's bound, as
    /// every other doubt about a credential does.
    async fn watched(
        &self,
        facts: &RequestFacts,
        ip: &Fact<IpAddress>,
        identified: Result<Identification, Refusal>,
    ) -> Result<Identification, Refusal> {
        let Some(session_id) = session_behind(&identified) else {
            return identified;
        };
        let request = WatchUseRequest {
            session_id,
            ip_address: ip.clone(),
        };
        let watched = self
            .watch_session
            .execute(&facts.tenant, &facts.auditor, request);
        match tokio::time::timeout(self.record_timeout, watched).await {
            Ok(Ok(SessionStanding::Stands)) => identified,
            Ok(Ok(SessionStanding::Stopped)) => Err(Refusal::Revoked),
            Ok(Err(error)) => Err(session_unwatched(&error)),
            Err(_) => Err(session_unwatched(&"the look timed out")),
        }
    }

    /// Records `mismatch` as a stolen agent token when it looks like one,
    /// within the record's bound. The request is refused whether or not the
    /// record is written, so a failure is only logged.
    async fn record_stolen(&self, facts: &RequestFacts, mismatch: KeyMismatch) {
        let request = RecordStolenBindingRequest {
            agent_id: mismatch.agent_id,
            fault: mismatch.fault,
        };
        let recorded = self
            .stolen_tokens
            .execute(&facts.tenant, &facts.auditor, request);
        match tokio::time::timeout(self.record_timeout, recorded).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "a stolen agent token was not recorded"),
            Err(_) => tracing::warn!("recording a stolen agent token timed out"),
        }
    }
}

/// The session the proven caller in `identified` came with, when there is
/// one. Only a person's session has a holder to look like.
fn session_behind(identified: &Result<Identification, Refusal>) -> Option<SessionId> {
    let Ok(Identification::Proven(proven)) = identified else {
        return None;
    };
    let Caller::User {
        sign_in: UserSignIn::Session(session_id),
        ..
    } = proven.verified.caller
    else {
        return None;
    };
    Some(session_id)
}

/// The refusal of a request whose session's use could not be looked at.
fn session_unwatched(error: &impl std::fmt::Display) -> Refusal {
    tracing::warn!(%error, "a session's use could not be held against where it was last used");
    Refusal::Unavailable
}

/// The question for the use case, or the refusal of a request whose
/// credential or address cannot be read one way only. The address a proof
/// must name is spelled with the scheme of the listener the request came
/// on.
fn authenticate_request(
    facts: &RequestFacts,
    route: &RouteRequirements,
) -> Result<AuthenticateRequest, Unaskable> {
    let admitted = &facts.admitted;
    let presented = match facts.listener {
        ListenerRole::ByHost => {
            request::presented(&facts.headers, admitted.host(), &facts.cookies)?
        }
        ListenerRole::ByRunPass => request::run_pass(&facts.headers)?,
    };
    let dpop = request::dpop(&facts.headers)?;
    let target = request::target(
        admitted.method(),
        facts.scheme,
        admitted.host(),
        admitted.path(),
    )
    .ok_or(Unaskable::TargetUnnamed)?;
    Ok(AuthenticateRequest {
        presented,
        certificate: verified_certificate(&facts.connection),
        dpop,
        target,
        route: route.clone(),
    })
}

/// What the Identity stage asked the use case about this request, for
/// asking again on the connection it opens. Its one-time key proof was
/// spent at the handshake, so later checks say so rather than send it
/// twice. `None` when the request's credential cannot be read one way,
/// which the Identity stage already refused it for.
pub(crate) fn held_credential(
    facts: &RequestFacts,
    route: &RouteRequirements,
) -> Option<AuthenticateRequest> {
    let mut request = authenticate_request(facts, route).ok()?;
    request.dpop = DpopHeader::ProvenAtOpen;
    Some(request)
}

/// The client certificate the handshake verified, and nothing else: one
/// that was not asked for, not sent or could not be checked proves nobody.
pub(crate) fn verified_certificate(connection: &ConnectionFacts) -> Fact<CertificateFingerprint> {
    match connection.client_certificate() {
        ClientCertificate::Verified(fingerprint) => Fact::Known(*fingerprint),
        ClientCertificate::NotAsked
        | ClientCertificate::NotPresented
        | ClientCertificate::Unverifiable => Fact::Unknown,
    }
}

/// The use case's answer, enforced on `ctx`.
fn settled(
    identified: Result<Identification, Refusal>,
    ctx: &mut PipelineContext,
) -> Result<IdentityOutcome, DomainError> {
    match identified {
        Ok(Identification::Proven(proven)) => established(proven, ctx),
        Ok(Identification::Anonymous) => Ok(anonymous(&ctx.route)),
        Err(refusal) => Ok(IdentityOutcome::refused(refused(refusal))),
    }
}

/// `proven` recorded as the request's caller, with their claims on the
/// context for the stages after it, and the whole proof for the Policy
/// stage.
///
/// # Errors
///
/// - [`DomainError::InvalidTransition`] when `ctx` already holds a caller.
fn established(
    proven: Box<Proven>,
    ctx: &mut PipelineContext,
) -> Result<IdentityOutcome, DomainError> {
    ctx.authenticate(proven.verified.clone())?;
    ctx.claims = proven.claims.clone();
    Ok(IdentityOutcome::passed(
        "caller_proven",
        Identification::Proven(proven),
    ))
}

/// Nobody, let through only where the route's known policy asks for no
/// caller. The use case answers so only there; a route it misread is still
/// refused here.
fn anonymous(route: &RouteRequirements) -> IdentityOutcome {
    match &route.policy {
        Fact::Known(policy) if !policy.requires_auth() => {
            IdentityOutcome::passed("anonymous_on_public_route", Identification::Anonymous)
        }
        Fact::Known(_) | Fact::Unknown => IdentityOutcome::refused(refused(Refusal::Missing)),
    }
}

/// The deny a refusal of the use case is answered with: 401 for a
/// credential that proves nobody here, a withdrawn one included (a session
/// signed out, a key revoked), so a browser is sent to sign in again; 403
/// for one whose holder may not pass; 429 for a spent quota; 503 when
/// nothing could be checked.
fn refused(refusal: Refusal) -> StageDecision {
    match refusal {
        Refusal::Missing => deny(DenialStatus::UNAUTHORIZED, "credential_missing"),
        Refusal::Invalid => deny(DenialStatus::UNAUTHORIZED, "credential_invalid"),
        Refusal::Expired => deny(DenialStatus::UNAUTHORIZED, "credential_expired"),
        Refusal::WrongIssuer => deny(DenialStatus::UNAUTHORIZED, "credential_wrong_issuer"),
        Refusal::WrongAudience => deny(DenialStatus::UNAUTHORIZED, "credential_wrong_audience"),
        Refusal::WrongHost => deny(DenialStatus::UNAUTHORIZED, "credential_wrong_host"),
        Refusal::UnknownSubject => deny(DenialStatus::UNAUTHORIZED, "subject_unknown"),
        Refusal::DpopMismatch(_) => deny(DenialStatus::UNAUTHORIZED, "dpop_proof_mismatch"),
        Refusal::Inactive => deny(DenialStatus::FORBIDDEN, "subject_inactive"),
        Refusal::Revoked => deny(DenialStatus::UNAUTHORIZED, "credential_revoked"),
        Refusal::CrossSite => deny(DenialStatus::FORBIDDEN, "cross_site_request"),
        Refusal::QuotaSpent => deny(DenialStatus::TOO_MANY_REQUESTS, "consumer_quota_spent"),
        Refusal::Unavailable => deny(
            DenialStatus::SERVICE_UNAVAILABLE,
            "credential_check_unavailable",
        ),
    }
}

/// Why a request could not be put to the use case at all.
enum Unaskable {
    /// Its credential was sent twice, or could not be read.
    Credential(CredentialRefusal),
    /// The address a proof must name could not be named.
    TargetUnnamed,
}

impl From<CredentialRefusal> for Unaskable {
    fn from(refusal: CredentialRefusal) -> Self {
        Self::Credential(refusal)
    }
}

impl Unaskable {
    /// The deny: 400 for a credential sent twice or an address that cannot
    /// be named, 401 for a credential the gateway cannot read at all.
    fn denial(self) -> StageDecision {
        match self {
            Self::Credential(CredentialRefusal::Repeated(_)) => {
                deny(DenialStatus::BAD_REQUEST, "credential_repeated")
            }
            Self::Credential(CredentialRefusal::Unreadable(_)) => {
                deny(DenialStatus::UNAUTHORIZED, "credential_unreadable")
            }
            Self::TargetUnnamed => deny(DenialStatus::BAD_REQUEST, "request_target_unnamed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use http::Request;
    use http::request::Builder;
    use ianua_app::ports::authentication::{
        AppSessionClaim, IssuedUnder, PersonToken, TenantToken, TokenFault,
    };
    use ianua_app::ports::authorization::AccessRecords;
    use ianua_app::test_support::authentication::{
        FakeAppSessionCheck, FakeFactorStanding, FakeGeolocator, FakePresentedTokens,
        FakeSessionStore, session_row_for,
    };
    use ianua_app::test_support::authorization::FakeAccessRecordStore;
    use ianua_app::test_support::identity::{FakeUserStore, stored_user};
    use ianua_app::test_support::oauth::test_issuer;
    use ianua_app::test_support::test_ctx;
    use ianua_app::use_cases::authentication::sessions::{WatchUsePorts, WatchUseUseCase};
    use ianua_app::use_cases::proxy::credentials::{AuthenticatePorts, PersonPorts};
    use ianua_domain::domains::agents::identity::token_attack::KeyProofFault;
    use ianua_domain::domains::authentication::risk_engine::assessment::IpGeolocation;
    use ianua_domain::domains::authentication::risk_engine::assurance::AssuranceLevel;
    use ianua_domain::domains::authentication::sessions::last_use::{CallerNetwork, LastUse};
    use ianua_domain::domains::authentication::sessions::session::{Session, SessionRow};
    use ianua_domain::domains::authentication::sessions::status::SessionStatus;
    use ianua_domain::domains::identity::account::user_status::UserStatus;
    use ianua_domain::domains::proxy::request::context::{Caller, UserSignIn, Verified};
    use ianua_domain::domains::routing::backend::upstream::{RouteIdentity, TokenAudience};
    use ianua_domain::domains::routing::policy::RoutePolicy;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{
        AgentId, Audience, CorrelationId, CountryCode, Expiry, PipelineId, ServiceId, SessionId,
        UserId,
    };
    use time::Duration;

    use super::*;
    use crate::pipeline::facts::fixtures::connection;
    use crate::pipeline::stages::identity::fixtures;

    /// The token every test request presents.
    const TOKEN: &str = "a.signed.token";

    /// A route of the reports app that needs a signed-in caller.
    fn route() -> RouteRequirements {
        RouteRequirements {
            expected_issuer: Fact::Known(test_issuer()),
            token_audience: TokenAudience::Pinned(Audience::new("reports-app").unwrap()),
            policy: Fact::Known(RoutePolicy::Authenticated),
            ..RouteRequirements::default()
        }
    }

    /// A request to the reports app, before the Identity stage ran.
    fn context() -> PipelineContext {
        let mut ctx = PipelineContext::new(
            test_ctx().tenant_id(),
            PipelineId::new(),
            CorrelationId::new(),
        );
        ctx.route = route();
        ctx
    }

    /// `build`, sent to the reports host over a connection whose
    /// handshake made `certificate` of the client's certificate.
    fn sent_with(build: Builder, certificate: ClientCertificate) -> RequestFacts {
        let request = build.header("host", "reports.acme.test").body(()).unwrap();
        let mut facts = RequestFacts::sent(request);
        facts.connection = connection(certificate);
        facts
    }

    fn sent(build: Builder) -> RequestFacts {
        sent_with(build, ClientCertificate::NotAsked)
    }

    /// A `GET` to the reports app with [`TOKEN`] as its bearer token.
    fn with_bearer() -> Builder {
        Request::get("/reports").header("authorization", format!("Bearer {TOKEN}"))
    }

    /// A token the tenant signed for `user_id` under a live app session, at
    /// AAL2.
    fn token_of(user_id: UserId) -> TenantToken {
        token_under(user_id, SessionId::new())
    }

    /// A token the tenant signed for `user_id` under the live app session
    /// `session_id`, at AAL2.
    fn token_under(user_id: UserId, session_id: SessionId) -> TenantToken {
        TenantToken::Person(PersonToken {
            user_id,
            scopes: Vec::new(),
            assurance: Fact::Known(AssuranceLevel::Aal2),
            expires_at: clock::now() + Duration::hours(1),
            issued_under: IssuedUnder::AppSession(AppSessionClaim {
                session_id,
                user_id,
                service_id: ServiceId::new(),
                idle_timeout: None,
                signed_in_from: Fact::Unknown,
            }),
            claims: Vec::new(),
        })
    }

    fn stages(ports: AuthenticatePorts) -> IdentityStages {
        IdentityStages::new(fixtures::parts_with(ports))
    }

    /// The gateway whose token reader answers `tokens`, knowing nobody.
    fn reading(tokens: FakePresentedTokens) -> IdentityStages {
        stages(AuthenticatePorts {
            tokens: Arc::new(tokens),
            ..AuthenticatePorts::fakes()
        })
    }

    /// The gateway of a tenant where Ann is active and her session live,
    /// its token reader answering `tokens`.
    fn knowing_ann(ann: UserId, tokens: FakePresentedTokens) -> IdentityStages {
        stages(AuthenticatePorts {
            tokens: Arc::new(tokens),
            access_records: Arc::new(FakeAccessRecordStore::holding(
                test_ctx().tenant_id(),
                AccessRecords::default(),
            )),
            people: PersonPorts {
                user_store: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                app_sessions: Arc::new(FakeAppSessionCheck(AtomicBool::new(true))),
                ..PersonPorts::fakes()
            },
            ..AuthenticatePorts::fakes()
        })
    }

    async fn identify(
        stages: &IdentityStages,
        sent: &RequestFacts,
        ctx: &mut PipelineContext,
    ) -> Result<IdentityOutcome, DomainError> {
        stages.identity(sent, ctx).await
    }

    /// Asserts `outcome` refuses with `status`, recorded as `code`, names
    /// nobody, and says nothing of the token.
    fn assert_denied(outcome: &IdentityOutcome, status: DenialStatus, code: &str) {
        let StageDecision::Deny {
            status: given,
            reason,
        } = &outcome.decision
        else {
            panic!("expected a deny, got {:?}", outcome.decision);
        };
        assert_eq!(*given, status);
        assert_eq!(reason, code);
        assert!(!reason.contains(TOKEN));
        assert!(outcome.identification.is_none());
    }

    /// Ann's app presents her token. She is recorded as the caller with her
    /// AAL2, and the whole proof goes on to the Policy stage.
    #[tokio::test]
    async fn a_proven_person_is_recorded_and_handed_to_the_policy_stage() {
        let ann = UserId::new();
        let stages = knowing_ann(ann, FakePresentedTokens::reading_bearer(token_of(ann)));
        let mut ctx = context();

        let outcome = identify(&stages, &sent(with_bearer()), &mut ctx)
            .await
            .unwrap();

        assert!(matches!(outcome.decision, StageDecision::Pass { .. }));
        assert!(matches!(
            outcome.identification,
            Some(Identification::Proven(_))
        ));
        assert!(matches!(
            ctx.authentication().caller(),
            Some(Caller::User { user_id, .. }) if *user_id == ann
        ));
        assert_eq!(ctx.claims.current_aal, Fact::Known(AssuranceLevel::Aal2));
    }

    /// Where Ann's session was last used, in Germany, a moment ago.
    fn used_in_germany() -> LastUse {
        LastUse::new(
            CallerNetwork::new("198.18.0.7").unwrap(),
            IpGeolocation::new(52.52, 13.405, CountryCode::new("DE").unwrap(), None).unwrap(),
            clock::now(),
        )
    }

    /// A gateway holding Ann's session `session_id`, last used in Germany,
    /// and placing every address in Poland.
    fn watching_session(
        ann: UserId,
        session_id: SessionId,
        sessions: &Arc<FakeSessionStore>,
    ) -> IdentityStages {
        let mut parts = fixtures::parts_with(AuthenticatePorts {
            tokens: Arc::new(FakePresentedTokens::reading_bearer(token_under(
                ann, session_id,
            ))),
            access_records: Arc::new(FakeAccessRecordStore::holding(
                test_ctx().tenant_id(),
                AccessRecords::default(),
            )),
            people: PersonPorts {
                user_store: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                app_sessions: Arc::new(FakeAppSessionCheck(AtomicBool::new(true))),
                ..PersonPorts::fakes()
            },
            ..AuthenticatePorts::fakes()
        });
        parts.watch_session = Arc::new(WatchUseUseCase::new(WatchUsePorts {
            session_store: sessions.clone(),
            geolocator: Arc::new(FakeGeolocator {
                location: Some(
                    IpGeolocation::new(52.40, 16.92, CountryCode::new("PL").unwrap(), None)
                        .unwrap(),
                ),
            }),
            factors: Arc::new(FakeFactorStanding::holding(ann)),
            users: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
        }));
        IdentityStages::new(parts)
    }

    /// Ann's session cookie is used from Poland just after she used it in
    /// Germany. It freezes, and the gateway refuses the request as a
    /// withdrawn credential, saying nothing of the token.
    #[tokio::test]
    async fn a_session_that_looks_taken_over_is_refused() {
        let ann = UserId::new();
        let session = Session::<ResolvedTenant>::reconstitute(SessionRow {
            last_use: Fact::Known(used_in_germany()),
            ..session_row_for(ann)
        })
        .unwrap();
        let session_id = *session.id();
        let sessions = Arc::new(FakeSessionStore::holding_in(
            test_ctx().tenant_id(),
            [session],
        ));
        let stages = watching_session(ann, session_id, &sessions);
        let mut ctx = context();
        ctx.ip_address = Fact::Known(IpAddress::new("198.18.1.7").unwrap());

        let outcome = identify(&stages, &sent(with_bearer()), &mut ctx)
            .await
            .unwrap();

        assert_denied(&outcome, DenialStatus::UNAUTHORIZED, "credential_revoked");
        assert_eq!(
            sessions.get_status(&session_id),
            Some(SessionStatus::Suspended)
        );
    }

    /// A protected route with no token returns 401 for missing credentials
    /// and leaves the request without an authenticated caller.
    #[tokio::test]
    async fn a_missing_token_is_refused() {
        let mut ctx = context();

        let outcome = identify(
            &reading(FakePresentedTokens::default()),
            &sent(Request::get("/reports")),
            &mut ctx,
        )
        .await
        .unwrap();

        assert_denied(&outcome, DenialStatus::UNAUTHORIZED, "credential_missing");
        assert!(ctx.authentication().caller().is_none());
    }

    /// An expired-token result yields 401 and no identification, without exposing the token.
    #[tokio::test]
    async fn an_expired_token_is_refused() {
        let stages = reading(FakePresentedTokens::refusing(TokenFault::Expired));

        let outcome = identify(&stages, &sent(with_bearer()), &mut context())
            .await
            .unwrap();

        assert_denied(&outcome, DenialStatus::UNAUTHORIZED, "credential_expired");
    }

    /// Ann's billing token is rejected by the reports route with 401 for
    /// the wrong audience and no identification.
    #[tokio::test]
    async fn a_token_for_another_audience_is_refused() {
        let ann = UserId::new();
        let tokens = FakePresentedTokens {
            minted_for: Some(Audience::new("billing-app").unwrap()),
            ..FakePresentedTokens::reading_bearer(token_of(ann))
        };

        let outcome = identify(
            &knowing_ann(ann, tokens),
            &sent(with_bearer()),
            &mut context(),
        )
        .await
        .unwrap();

        assert_denied(
            &outcome,
            DenialStatus::UNAUTHORIZED,
            "credential_wrong_audience",
        );
    }

    /// A readable token naming no stored user yields 401 for an unknown
    /// subject and no identification.
    #[tokio::test]
    async fn a_token_for_an_unknown_subject_is_refused() {
        let stages = reading(FakePresentedTokens::reading_bearer(token_of(UserId::new())));

        let outcome = identify(&stages, &sent(with_bearer()), &mut context())
            .await
            .unwrap();

        assert_denied(&outcome, DenialStatus::UNAUTHORIZED, "subject_unknown");
    }

    /// An unavailable token reader yields 503 and no identification without exposing the token.
    #[tokio::test]
    async fn an_unreachable_store_refuses_the_request() {
        let stages = reading(FakePresentedTokens::unreachable());

        let outcome = identify(&stages, &sent(with_bearer()), &mut context())
            .await
            .unwrap();

        assert_denied(
            &outcome,
            DenialStatus::SERVICE_UNAVAILABLE,
            "credential_check_unavailable",
        );
    }

    /// Authentication targets preserve HTTP for the runner listener and
    /// HTTPS for the public listener with the same request host and path.
    #[test]
    fn a_proof_names_the_scheme_of_the_listener_it_came_on() {
        let mut on_runners = sent(with_bearer());
        on_runners.scheme = crate::request::Scheme::Http;

        let public = authenticate_request(&sent(with_bearer()), &route())
            .ok()
            .unwrap();
        let runners = authenticate_request(&on_runners, &route()).ok().unwrap();

        assert_eq!(
            public.target.url.as_str(),
            "https://reports.acme.test/reports"
        );
        assert_eq!(
            runners.target.url.as_str(),
            "http://reports.acme.test/reports"
        );
    }

    #[tokio::test]
    async fn nobody_passes_on_a_public_route() {
        let mut ctx = context();
        ctx.route.policy = Fact::Known(RoutePolicy::Public);

        let outcome = identify(
            &reading(FakePresentedTokens::default()),
            &sent(Request::get("/reports")),
            &mut ctx,
        )
        .await
        .unwrap();

        assert!(matches!(outcome.decision, StageDecision::Pass { .. }));
        assert!(matches!(
            outcome.identification,
            Some(Identification::Anonymous)
        ));
        assert!(ctx.authentication().caller().is_none());
    }

    /// An anonymous result yields 401 and no identification for both an
    /// authenticated route and a route whose policy is unknown.
    #[test]
    fn nobody_is_refused_on_a_route_that_is_not_public() {
        let mut unknown = route();
        unknown.policy = Fact::Unknown;

        for requirements in [route(), unknown] {
            let outcome = anonymous(&requirements);

            assert_denied(&outcome, DenialStatus::UNAUTHORIZED, "credential_missing");
        }
    }

    /// Every refusal of the use case is a deny, each with its own reason
    /// code and the status its kind calls for.
    #[test]
    fn every_refusal_is_a_deny_with_a_fitting_status() {
        let expected = refusal_statuses();
        let mut codes = BTreeSet::new();

        for (refusal, status) in expected {
            let StageDecision::Deny {
                status: given,
                reason,
            } = refused(refusal)
            else {
                panic!("{refusal:?} was not refused");
            };
            assert_eq!(given, status, "{refusal:?}");
            codes.insert(reason);
        }

        assert_eq!(codes.len(), expected.len());
    }

    /// Each authentication refusal's status, including the proof mismatch payload.
    fn refusal_statuses() -> [(Refusal, DenialStatus); 13] {
        [
            (Refusal::Missing, DenialStatus::UNAUTHORIZED),
            (Refusal::Invalid, DenialStatus::UNAUTHORIZED),
            (Refusal::Expired, DenialStatus::UNAUTHORIZED),
            (Refusal::WrongIssuer, DenialStatus::UNAUTHORIZED),
            (Refusal::WrongAudience, DenialStatus::UNAUTHORIZED),
            (Refusal::WrongHost, DenialStatus::UNAUTHORIZED),
            (Refusal::UnknownSubject, DenialStatus::UNAUTHORIZED),
            (
                Refusal::DpopMismatch(KeyMismatch {
                    agent_id: AgentId::new(),
                    fault: KeyProofFault::NotSent,
                }),
                DenialStatus::UNAUTHORIZED,
            ),
            (Refusal::Inactive, DenialStatus::FORBIDDEN),
            (Refusal::Revoked, DenialStatus::UNAUTHORIZED),
            (Refusal::CrossSite, DenialStatus::FORBIDDEN),
            (Refusal::QuotaSpent, DenialStatus::TOO_MANY_REQUESTS),
            (Refusal::Unavailable, DenialStatus::SERVICE_UNAVAILABLE),
        ]
    }

    /// A readable token for deactivated Ann yields 403 for inactive standing
    /// and no identification.
    #[tokio::test]
    async fn an_inactive_persons_token_is_refused() {
        let ann = UserId::new();
        let users = FakeUserStore::empty();
        users.add(stored_user(ann, "ann@acme.test", UserStatus::Deactivated));
        let stages = stages(AuthenticatePorts {
            tokens: Arc::new(FakePresentedTokens::reading_bearer(token_of(ann))),
            people: PersonPorts {
                user_store: Arc::new(users),
                ..PersonPorts::fakes()
            },
            ..AuthenticatePorts::fakes()
        });

        let outcome = identify(&stages, &sent(with_bearer()), &mut context())
            .await
            .unwrap();

        assert_denied(&outcome, DenialStatus::FORBIDDEN, "subject_inactive");
    }

    /// Ann's token yields 401 for revoked credentials when its application
    /// session no longer passes verification, with no identification returned.
    #[tokio::test]
    async fn a_token_whose_session_ended_is_refused() {
        let ann = UserId::new();
        let stages = stages(AuthenticatePorts {
            tokens: Arc::new(FakePresentedTokens::reading_bearer(token_of(ann))),
            access_records: Arc::new(FakeAccessRecordStore::holding(
                test_ctx().tenant_id(),
                AccessRecords::default(),
            )),
            people: PersonPorts {
                user_store: Arc::new(FakeUserStore::with_user(ann, "ann@acme.test")),
                app_sessions: Arc::new(FakeAppSessionCheck(AtomicBool::new(false))),
                ..PersonPorts::fakes()
            },
            ..AuthenticatePorts::fakes()
        });

        let outcome = identify(&stages, &sent(with_bearer()), &mut context())
            .await
            .unwrap();

        assert_denied(&outcome, DenialStatus::UNAUTHORIZED, "credential_revoked");
    }

    /// A cookie-authenticated POST without CSRF proof yields 403 for a
    /// cross-site request and no identification.
    #[tokio::test]
    async fn a_cross_site_cookie_post_is_refused() {
        let forged = Request::post("/reports").header("cookie", format!("ianua_session={TOKEN}"));
        let stages = reading(FakePresentedTokens::default());

        let outcome = identify(&stages, &sent(forged), &mut context())
            .await
            .unwrap();

        assert_denied(&outcome, DenialStatus::FORBIDDEN, "cross_site_request");
    }

    /// Two authorization headers yield 400 for repeated credentials and no identification.
    #[tokio::test]
    async fn a_credential_sent_twice_is_refused() {
        let twice = with_bearer().header("authorization", "Bearer another.token");
        let stages = reading(FakePresentedTokens::reading_bearer(token_of(UserId::new())));

        let outcome = identify(&stages, &sent(twice), &mut context())
            .await
            .unwrap();

        assert_denied(&outcome, DenialStatus::BAD_REQUEST, "credential_repeated");
    }

    /// Basic authorization yields 401 for unreadable credentials and no identification.
    #[tokio::test]
    async fn an_unreadable_credential_is_refused() {
        let basic = Request::get("/reports").header("authorization", "Basic YW5uOnNlY3JldA==");

        let outcome = identify(
            &reading(FakePresentedTokens::default()),
            &sent(basic),
            &mut context(),
        )
        .await
        .unwrap();

        assert_denied(
            &outcome,
            DenialStatus::UNAUTHORIZED,
            "credential_unreadable",
        );
    }

    /// An unverifiable client certificate yields 401 for missing credentials
    /// on a certificate-only route, with no identification returned.
    #[tokio::test]
    async fn an_unverifiable_certificate_proves_nobody() {
        let mut ctx = context();
        ctx.route.identity = RouteIdentity::ClientCertificate;
        let request = sent_with(Request::get("/reports"), ClientCertificate::Unverifiable);

        let outcome = identify(&reading(FakePresentedTokens::default()), &request, &mut ctx)
            .await
            .unwrap();

        assert_denied(&outcome, DenialStatus::UNAUTHORIZED, "credential_missing");
    }

    /// Identifying Ann on a request already authenticated as Mallory fails
    /// with an invalid transition and preserves Mallory as its caller.
    #[tokio::test]
    async fn a_second_identity_run_cannot_swap_the_caller() {
        let ann = UserId::new();
        let stages = knowing_ann(ann, FakePresentedTokens::reading_bearer(token_of(ann)));
        let mut ctx = context();
        let mallory = UserId::new();
        ctx.authenticate(Verified {
            caller: Caller::User {
                user_id: mallory,
                sign_in: UserSignIn::Token,
            },
            expiry: Expiry::Never,
        })
        .unwrap();

        let result = identify(&stages, &sent(with_bearer()), &mut ctx).await;

        assert!(matches!(result, Err(DomainError::InvalidTransition(_))));
        assert!(matches!(
            ctx.authentication().caller(),
            Some(Caller::User { user_id, .. }) if *user_id == mallory
        ));
    }
}
