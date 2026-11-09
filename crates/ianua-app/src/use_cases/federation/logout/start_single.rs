//! Start single logout: as a person signs out, the logout requests that end
//! their sessions at the other side of each SAML trust: every app their
//! session signed in to, and the provider it was opened through.
//!
//! Each request is kept until its answer comes back, and the browser posts
//! each one in turn. This runs before the session itself is ended, while
//! the person is still signed in to it.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::FederatedIdpConnection;
use ianua_domain::domains::federation::saml::logout::{LogoutSubject, SentLogoutRequest};
use ianua_domain::domains::federation::saml::logout_builder::build_logout_request;
use ianua_domain::domains::federation::saml::name_id::SamlNameIdValue;
use ianua_domain::domains::federation::saml::trail::SamlTrail;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, SamlEntityId, SessionId};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::{
    ConnectionStore, ProviderSession, ProviderSessionStore, SamlAppSession, SamlAppSessionStore,
    SamlServiceProviderStore, SentLogoutRequestStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::federation::logout::messages::{
    LogoutSigner, OutgoingLogoutMessage, fresh_request_id,
};

/// Who this platform is to each peer.
pub struct StartSingleRequest {
    /// Its entity id as the identity provider, which apps know it by.
    pub idp_entity_id: SamlEntityId,
    /// Its entity id as a service provider, which a connection's provider
    /// knows it by.
    pub sp_entity_id: SamlEntityId,
}

/// The ports [`StartSingleUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct StartSinglePorts {
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The apps each session signed in to.
    pub app_sessions: Arc<dyn SamlAppSessionStore>,
    /// The provider sessions behind sessions here.
    pub provider_sessions: Arc<dyn ProviderSessionStore>,
    /// The tenant's SAML apps.
    pub service_providers: Arc<dyn SamlServiceProviderStore>,
    /// The tenant's connections.
    pub connections: Arc<dyn ConnectionStore>,
    /// Keeps each request until its answer comes back.
    pub sent_requests: Arc<dyn SentLogoutRequestStore>,
    /// Signs each request.
    pub signer: LogoutSigner,
}

/// Writes the logout requests a person's sign-out sends to each peer.
pub struct StartSingleUseCase {
    ports: StartSinglePorts,
}

impl StartSingleUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: StartSinglePorts) -> Self {
        Self { ports }
    }

    /// The requests to every app `session_id` signed in to that takes
    /// logouts, each raised on `trail`.
    async fn to_apps(
        &self,
        tenant: &ScopedTenant,
        session_id: &SessionId,
        issuer: &SamlEntityId,
        trail: &mut SamlTrail<ResolvedTenant>,
    ) -> Result<Vec<OutgoingLogoutMessage>, AppError> {
        let app_sessions = self
            .ports
            .app_sessions
            .list_by_session(tenant, session_id)
            .await
            .or_internal()?;
        let mut outgoing = Vec::with_capacity(app_sessions.len());
        for app_session in &app_sessions {
            let Some(sent) = self.app_request(tenant, app_session).await? else {
                continue;
            };
            outgoing.push(self.kept_and_signed(tenant, &sent, issuer, trail).await?);
        }
        Ok(outgoing)
    }

    /// The request asking the app of `app_session` to end it, unless the app
    /// is gone or takes no logouts.
    async fn app_request(
        &self,
        tenant: &ScopedTenant,
        app_session: &SamlAppSession,
    ) -> Result<Option<SentLogoutRequest>, AppError> {
        let app = self
            .ports
            .service_providers
            .find_by_id(tenant, &app_session.provider_id)
            .await
            .or_internal()?;
        let Some(app) = app else {
            return Ok(None);
        };
        let subject = LogoutSubject {
            request_id: fresh_request_id()?,
            name_id: app_session.name_id.clone(),
            session_index: app_session.session_index.clone(),
        };
        unless_no_logout_address(app.logout_request(subject))
    }

    /// The request to the provider `session_id` was opened through, unless
    /// it named no session, is gone, or takes no logouts, raised on
    /// `trail`.
    async fn to_provider(
        &self,
        tenant: &ScopedTenant,
        session_id: &SessionId,
        issuer: &SamlEntityId,
        trail: &mut SamlTrail<ResolvedTenant>,
    ) -> Result<Option<OutgoingLogoutMessage>, AppError> {
        let Some(provider) = self
            .ports
            .provider_sessions
            .find_by_session(tenant, session_id)
            .await
            .or_internal()?
        else {
            return Ok(None);
        };
        let Some(sent) = self.provider_request(tenant, &provider).await? else {
            return Ok(None);
        };
        self.kept_and_signed(tenant, &sent, issuer, trail)
            .await
            .map(Some)
    }

    /// The request asking `provider`'s connection to end its session.
    async fn provider_request(
        &self,
        tenant: &ScopedTenant,
        provider: &ProviderSession,
    ) -> Result<Option<SentLogoutRequest>, AppError> {
        let connection = self
            .ports
            .connections
            .find_by_id(tenant, &provider.connection_id)
            .await
            .or_internal()?;
        let Some(connection) = connection else {
            return Ok(None);
        };
        logout_request_to(&connection, provider)
    }

    /// `sent`, written from `issuer` and signed, kept until its answer
    /// comes back, and raised on `trail`.
    async fn kept_and_signed(
        &self,
        tenant: &ScopedTenant,
        sent: &SentLogoutRequest,
        issuer: &SamlEntityId,
        trail: &mut SamlTrail<ResolvedTenant>,
    ) -> Result<OutgoingLogoutMessage, AppError> {
        let message = build_logout_request(sent, issuer).map_err(AppError::from_domain)?;
        let signed = self
            .ports
            .signer
            .signed(tenant, &message, sent.destination().clone())
            .await?;
        self.ports
            .sent_requests
            .save(tenant, sent)
            .await
            .or_internal()?;
        trail.logout_sent(sent);
        Ok(signed)
    }

    /// Forgets which peers `session_id` reached, once their requests are
    /// written.
    async fn forget_peers(
        &self,
        tenant: &ScopedTenant,
        session_id: &SessionId,
    ) -> Result<(), AppError> {
        self.ports
            .app_sessions
            .delete_by_session(tenant, session_id)
            .await
            .or_internal()?;
        self.ports
            .provider_sessions
            .delete_by_session(tenant, session_id)
            .await
            .or_internal()
    }
}

impl Command for StartSingleUseCase {
    type Caller = CallerContext;
    type Input = StartSingleRequest;
    type Output = Result<Vec<OutgoingLogoutMessage>, AppError>;

    /// The signed logout requests to every peer the caller's session reached,
    /// each kept until its answer comes back: first each app it signed in
    /// to, then the provider it was opened through. A peer that takes no
    /// logouts, or is gone, is left out. Each request sent records
    /// `federation.logout_request_sent`, as done by the person signing out;
    /// the session's own end is recorded when it is ended.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` when the caller came with no tenant
    ///   session of their own, or it no longer counts.
    /// - `AppError::NotFound` if a request is owed and the tenant has no
    ///   signing key set.
    /// - `AppError::Internal` if the key set holds no active key, or on
    ///   signing, storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: StartSingleRequest,
    ) -> Result<Vec<OutgoingLogoutMessage>, AppError> {
        let person = self.ports.tenant_authorities.signed_in(caller).await?;
        let tenant = caller.tenant();
        let session_id = person.session.id();
        let mut trail = SamlTrail::default();
        let mut outgoing = self
            .to_apps(&tenant, session_id, &request.idp_entity_id, &mut trail)
            .await?;
        let provider = self
            .to_provider(&tenant, session_id, &request.sp_entity_id, &mut trail)
            .await?;
        outgoing.extend(provider);
        self.forget_peers(&tenant, session_id).await?;
        auditor
            .dispatch_by(
                &ActorRef::User(*person.account.id()),
                trail.take_events(&tenant),
            )
            .await
            .or_internal()?;
        Ok(outgoing)
    }
}

/// The request asking `connection`'s provider to end `provider`'s session,
/// unless it takes no logouts.
///
/// # Errors
///
/// - `AppError::Internal` if the subject cannot be written as a `NameID`,
///   which a subject never fails.
fn logout_request_to(
    connection: &FederatedIdpConnection<ResolvedTenant>,
    provider: &ProviderSession,
) -> Result<Option<SentLogoutRequest>, AppError> {
    let subject = LogoutSubject {
        request_id: fresh_request_id()?,
        name_id: SamlNameIdValue::new(provider.subject.as_str()).or_internal()?,
        session_index: provider.session_index.clone(),
    };
    unless_no_logout_address(connection.logout_request(subject))
}

/// The request `made`, or none when the peer has no logout address, or is
/// not a SAML peer.
///
/// # Errors
///
/// - `AppError::Domain` for any other refusal.
fn unless_no_logout_address(
    made: Result<SentLogoutRequest, DomainError>,
) -> Result<Option<SentLogoutRequest>, AppError> {
    match made {
        Ok(sent) => Ok(Some(sent)),
        Err(DomainError::Conflict(_)) => Ok(None),
        Err(refused) => Err(AppError::from_domain(refused)),
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::federation::service_provider::SamlServiceProviderSettings;
    use ianua_domain::types::{
        ConnectionId, FederatedSubject, SamlServiceProviderId, SessionIndex, Setting,
    };

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::crypto::{FakeSigningKeyStore, FakeXmlSigner};
    use crate::test_support::federation::{
        FakeConnectionStore, FakeProviderSessions, FakeSamlAppSessions,
        FakeSamlServiceProviderStore, FakeSentLogoutRequests, TEST_APP_SLO_URL, test_app_settings,
        test_connection, test_logout_signer, test_service_provider_with,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_session_id,
    };

    struct Harness {
        ports: StartSinglePorts,
        app_sessions: Arc<FakeSamlAppSessions>,
        provider_sessions: Arc<FakeProviderSessions>,
        sent: Arc<FakeSentLogoutRequests>,
    }

    /// Ann's session signed in to Salesforce, answered by `settings`.
    fn signed_in_to_salesforce(settings: SamlServiceProviderSettings) -> Harness {
        let tenant = test_ctx().tenant();
        let app_id = SamlServiceProviderId::new();
        let app = test_service_provider_with(app_id, ConnectionStatus::Active, settings);
        let app_sessions = Arc::new(FakeSamlAppSessions::empty());
        let kept = SamlAppSession {
            session_id: test_session_id(),
            provider_id: app_id,
            name_id: SamlNameIdValue::new("pairwise-ann").unwrap(),
            session_index: SessionIndex::new("_s1").unwrap(),
        };
        block_on(app_sessions.save(&tenant, &kept)).unwrap();
        let provider_sessions = Arc::new(FakeProviderSessions::empty());
        let sent = Arc::new(FakeSentLogoutRequests::empty());
        let ports = StartSinglePorts {
            app_sessions: app_sessions.clone(),
            provider_sessions: provider_sessions.clone(),
            service_providers: Arc::new(FakeSamlServiceProviderStore::holding(&tenant, [app])),
            sent_requests: sent.clone(),
            signer: test_logout_signer(),
            ..StartSinglePorts::fakes()
        };
        Harness {
            ports,
            app_sessions,
            provider_sessions,
            sent,
        }
    }

    fn request() -> StartSingleRequest {
        StartSingleRequest {
            idp_entity_id: SamlEntityId::new("https://auth.acme.com").unwrap(),
            sp_entity_id: SamlEntityId::new("https://auth.acme.com/sp").unwrap(),
        }
    }

    fn start(ports: StartSinglePorts) -> Result<Vec<OutgoingLogoutMessage>, AppError> {
        start_recorded(ports, &Arc::new(FakeEventDispatcher::new()))
    }

    fn start_recorded(
        ports: StartSinglePorts,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<Vec<OutgoingLogoutMessage>, AppError> {
        let auditor = test_auditor(audit.clone());
        block_on(StartSingleUseCase::new(ports).execute(&test_ctx(), &auditor, request()))
    }

    /// Ann signs out after using Salesforce. A signed logout request goes to
    /// Salesforce's logout address and is kept for its answer, her session
    /// no longer counts as signed in to it, and the request is recorded.
    #[test]
    fn a_logout_request_goes_to_each_app_signed_in_to() {
        let h = signed_in_to_salesforce(test_app_settings());
        let audit = Arc::new(FakeEventDispatcher::new());

        let outgoing = start_recorded(h.ports, &audit).unwrap();

        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.logout_request_sent"]
        );

        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].destination.as_str(), TEST_APP_SLO_URL);
        assert_eq!(h.sent.all().len(), 1);
        assert!(h.app_sessions.all().is_empty());
    }

    /// Ann signed in through Okta, which named its session. Her sign-out
    /// asks Okta to end it too, after Salesforce.
    #[test]
    fn a_logout_request_goes_to_the_provider_signed_in_through() {
        let h = signed_in_to_salesforce(test_app_settings());
        let tenant = test_ctx().tenant();
        let connection_id = ConnectionId::new();
        let okta = test_connection(connection_id, ConnectionStatus::Active);
        let behind = ProviderSession {
            session_id: test_session_id(),
            connection_id,
            subject: FederatedSubject::new("00u-ann").unwrap(),
            session_index: SessionIndex::new("_okta-1").unwrap(),
        };
        block_on(h.provider_sessions.save(&tenant, &behind)).unwrap();
        let ports = StartSinglePorts {
            connections: Arc::new(FakeConnectionStore::holding(&tenant, [okta])),
            ..h.ports
        };

        let outgoing = start(ports).unwrap();

        assert_eq!(outgoing.len(), 2);
        assert_eq!(outgoing[1].destination.as_str(), "https://idp.acme.com/slo");
        assert!(h.provider_sessions.all().is_empty());
    }

    /// Salesforce was set up without a logout address. Nothing is sent to
    /// it.
    #[test]
    fn an_app_that_takes_no_logouts_is_left_out() {
        let h = signed_in_to_salesforce(SamlServiceProviderSettings {
            logout_url: Setting::Unset,
            ..test_app_settings()
        });

        let outgoing = start(h.ports).unwrap();

        assert!(outgoing.is_empty());
        assert!(h.sent.all().is_empty());
    }

    /// Acme has no signing key. No unsigned logout request goes out, and the
    /// answer is not found.
    #[test]
    fn a_tenant_without_signing_keys_is_not_found() {
        let h = signed_in_to_salesforce(test_app_settings());
        let ports = StartSinglePorts {
            signer: LogoutSigner {
                key_store: Arc::new(FakeSigningKeyStore::empty()),
                xml_signer: Arc::new(FakeXmlSigner),
            },
            ..h.ports
        };

        let result = start(ports);

        assert!(matches!(result, Err(AppError::NotFound(_))));
        assert!(h.sent.all().is_empty());
    }

    /// A signed-out session cannot start single logout. No outgoing request
    /// is stored, and the app-session record remains.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let h = signed_in_to_salesforce(test_app_settings());
        let ports = StartSinglePorts {
            tenant_authorities: Arc::new(FakeTenantAuthorities::refusing(Refusal::SignedOut)),
            ..h.ports
        };

        let result = start(ports);

        assert!(matches!(result, Err(AppError::Unauthenticated)));
        assert!(h.sent.all().is_empty());
        assert_eq!(h.app_sessions.all().len(), 1);
    }
}
