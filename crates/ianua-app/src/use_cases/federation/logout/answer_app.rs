//! Answer app logout: one of the tenant's SAML apps asks this platform, its
//! identity provider, to log the person out.
//!
//! The browser carries the request, and the session the person holds here.
//! The request is taken only from the app it names, checked against the key
//! the app signs with, and ends the session only when it names the person
//! as this platform named them to the app. Whatever happens, the app gets a
//! signed answer saying how it went.

use std::sync::Arc;

use ianua_domain::domains::federation::saml::logout::{LogoutStatus, SamlLogoutRequest};
use ianua_domain::domains::federation::saml::logout_builder::{
    LogoutResponseParams, build_logout_response,
};
use ianua_domain::domains::federation::service_provider::SamlServiceProvider;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::SamlEntityId;

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::{
    InboundSamlMessage, SamlAppSessionStore, SamlLogoutLedger, SamlMessageReader,
    SamlServiceProviderStore,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::federation::idp::lookup::{sending_service_provider, signature_trust};
use crate::use_cases::federation::logout::messages::{
    LogoutBrowser, LogoutSigner, OutgoingLogoutMessage, SessionEnding, take_once,
};
use crate::use_cases::federation::lookup::fresh_response_id;

/// An app's logout request, as the browser brought it.
pub struct AnswerAppRequest {
    /// This platform's entity id as the identity provider, written as the
    /// answer's issuer.
    pub idp_entity_id: SamlEntityId,
    /// The request.
    pub message: InboundSamlMessage,
}

/// The ports [`AnswerAppUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AnswerAppPorts {
    /// Who is signed in to the caller's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The tenant's SAML apps.
    pub service_providers: Arc<dyn SamlServiceProviderStore>,
    /// Reads the request and checks its signature.
    pub message_reader: Arc<dyn SamlMessageReader>,
    /// The apps each session signed in to.
    pub app_sessions: Arc<dyn SamlAppSessionStore>,
    /// The logout requests taken already, so each is taken once.
    pub logout_ledger: Arc<dyn SamlLogoutLedger>,
    /// Ends the person's session.
    pub ending: SessionEnding,
    /// Signs the answer.
    pub signer: LogoutSigner,
}

/// Answers a SAML app's request to log the person out.
pub struct AnswerAppUseCase {
    ports: AnswerAppPorts,
}

impl AnswerAppUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AnswerAppPorts) -> Self {
        Self { ports }
    }

    /// The app that sent `message`, and its request, once its signature
    /// checks out.
    async fn read(
        &self,
        tenant: &ScopedTenant,
        message: &InboundSamlMessage,
    ) -> Result<(SamlServiceProvider<ResolvedTenant>, SamlLogoutRequest), AppError> {
        let reader = self.ports.message_reader.as_ref();
        let issuer = reader.issuer(message).map_err(AppError::from_domain)?;
        let store = self.ports.service_providers.as_ref();
        let app = sending_service_provider(store, tenant, &issuer).await?;
        let trust = signature_trust(&app.settings().request_signing);
        let request = reader
            .logout_request(message, &trust)
            .map_err(AppError::from_domain)?;
        Ok((app, request))
    }

    /// Logs the browser's person out when `request` names them as `app`
    /// knows them, and says how it went. A browser signed out already is
    /// logged out.
    async fn logged_out(
        &self,
        browser: &LogoutBrowser,
        auditor: &RequestAuditor,
        app: &SamlServiceProvider<ResolvedTenant>,
        request: &SamlLogoutRequest,
    ) -> Result<LogoutStatus, AppError> {
        let authorities = self.ports.tenant_authorities.as_ref();
        let Some(person) = browser.person(authorities).await? else {
            return Ok(LogoutStatus::Success);
        };
        let tenant = browser.tenant();
        if !self
            .names_the_person(&tenant, &person, app, request)
            .await?
        {
            return Ok(LogoutStatus::Failed);
        }
        let session_id = *person.session.id();
        self.ports.ending.end(&tenant, person, auditor).await?;
        self.ports
            .app_sessions
            .delete_by_session(&tenant, &session_id)
            .await
            .or_internal()?;
        Ok(LogoutStatus::Success)
    }

    /// Whether `request` names `person` as their session signed in to `app`.
    async fn names_the_person(
        &self,
        tenant: &ScopedTenant,
        person: &SignedInAccount,
        app: &SamlServiceProvider<ResolvedTenant>,
        request: &SamlLogoutRequest,
    ) -> Result<bool, AppError> {
        let signed_in_to = self
            .ports
            .app_sessions
            .list_by_session(tenant, person.session.id())
            .await
            .or_internal()?;
        Ok(signed_in_to
            .iter()
            .any(|kept| kept.provider_id == *app.id() && kept.name_id == *request.name_id()))
    }
}

impl Command for AnswerAppUseCase {
    type Caller = LogoutBrowser;
    type Input = AnswerAppRequest;
    type Output = Result<OutgoingLogoutMessage, AppError>;

    /// The signed answer to the app's logout request, for the browser to
    /// post to the app's logout address. The browser's session ends, and
    /// `authentication.session_revoked` is recorded, when the request names
    /// the person as the app knows them; the answer says it failed when it
    /// names someone else.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` if no app of the tenant sent the request, or
    ///   it is unsigned where the app signs, or its signature does not
    ///   verify, or it was taken before.
    /// - `AppError::Conflict` if the app has no logout address to answer at.
    /// - `AppError::Domain` if the request is malformed, too old, or issued
    ///   ahead of now.
    /// - `AppError::NotFound` if the tenant has no signing key set.
    /// - `AppError::Internal` on signing, storage or audit failure.
    async fn execute(
        &self,
        browser: &LogoutBrowser,
        auditor: &RequestAuditor,
        request: AnswerAppRequest,
    ) -> Result<OutgoingLogoutMessage, AppError> {
        let tenant = browser.tenant();
        let (app, logout) = self.read(&tenant, &request.message).await?;
        let answer = app.accept_logout(&logout).map_err(AppError::from_domain)?;
        take_once(self.ports.logout_ledger.as_ref(), &tenant, &logout).await?;
        let status = self.logged_out(browser, auditor, &app, &logout).await?;
        let destination = answer.destination().clone();
        let response = build_logout_response(&LogoutResponseParams {
            response_id: fresh_response_id()?,
            issuer: request.idp_entity_id,
            answer,
            status,
        })
        .map_err(AppError::from_domain)?;
        self.ports
            .signer
            .signed(&tenant, &response, destination)
            .await
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::federation::saml::logout::LogoutRequestParts;
    use ianua_domain::domains::federation::saml::name_id::SamlNameIdValue;
    use ianua_domain::domains::federation::service_provider::{
        RequestSigningRule, SamlServiceProviderSettings,
    };
    use ianua_domain::types::{CertificatePem, SamlRequestId, SamlServiceProviderId, SessionIndex};

    use super::*;
    use crate::ports::federation::SamlAppSession;
    use crate::test_support::domain::TEST_CERTIFICATE_PEM;
    use crate::test_support::federation::{
        FakeSamlAppSessions, FakeSamlMessageReader, FakeSamlServiceProviderStore,
        TEST_APP_ENTITY_ID, TEST_APP_SLO_URL, posted_message, test_app_settings,
        test_logout_signer, test_service_provider_with,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_session_id,
    };

    const ANN_AT_SALESFORCE: &str = "pairwise-ann";

    /// Salesforce's request to log out whoever it knows as `name_id`.
    fn logout_naming(name_id: &str) -> SamlLogoutRequest {
        SamlLogoutRequest::new(LogoutRequestParts {
            id: SamlRequestId::new("_logout-1").unwrap(),
            issuer: SamlEntityId::new(TEST_APP_ENTITY_ID).unwrap(),
            issued_at: ianua_domain::shared::clock::now(),
            name_id: SamlNameIdValue::new(name_id).unwrap(),
            session_indexes: Vec::new(),
        })
    }

    struct Harness {
        ports: AnswerAppPorts,
        app_sessions: Arc<FakeSamlAppSessions>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// Ann's session signed in to Salesforce, answered by `settings`, which
    /// sends `request`.
    fn harness(settings: SamlServiceProviderSettings, request: SamlLogoutRequest) -> Harness {
        let tenant = test_ctx().tenant();
        let app_id = SamlServiceProviderId::new();
        let app = test_service_provider_with(app_id, ConnectionStatus::Active, settings);
        let app_sessions = Arc::new(FakeSamlAppSessions::empty());
        let kept = SamlAppSession {
            session_id: test_session_id(),
            provider_id: app_id,
            name_id: SamlNameIdValue::new(ANN_AT_SALESFORCE).unwrap(),
            session_index: SessionIndex::new("_s1").unwrap(),
        };
        block_on(app_sessions.save(&tenant, &kept)).unwrap();
        let reader =
            FakeSamlMessageReader::from_issuer(TEST_APP_ENTITY_ID).with_logout_request(request);
        let ports = AnswerAppPorts {
            service_providers: Arc::new(FakeSamlServiceProviderStore::holding(&tenant, [app])),
            message_reader: Arc::new(reader),
            app_sessions: app_sessions.clone(),
            signer: test_logout_signer(),
            ..AnswerAppPorts::fakes()
        };
        Harness {
            ports,
            app_sessions,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn answer(
        ports: AnswerAppPorts,
        audit: &Arc<FakeEventDispatcher>,
        browser: &LogoutBrowser,
    ) -> Result<OutgoingLogoutMessage, AppError> {
        let request = AnswerAppRequest {
            idp_entity_id: SamlEntityId::new("https://auth.acme.com").unwrap(),
            message: posted_message(),
        };
        let use_case = AnswerAppUseCase::new(ports);
        block_on(use_case.execute(browser, &test_auditor(audit.clone()), request))
    }

    fn signed_in() -> LogoutBrowser {
        LogoutBrowser::SignedIn(Box::new(test_ctx()))
    }

    fn xml_of(message: &OutgoingLogoutMessage) -> String {
        String::from_utf8(STANDARD.decode(&message.base64_message).unwrap()).unwrap()
    }

    /// Ann logs out of Salesforce, which asks Acme to log her out too. Her
    /// session here ends, Salesforce is told it worked, at its logout
    /// address, and the ending is recorded.
    #[test]
    fn the_app_logs_the_person_out_here_too() {
        let h = harness(test_app_settings(), logout_naming(ANN_AT_SALESFORCE));

        let message = answer(h.ports, &h.audit, &signed_in()).unwrap();

        assert_eq!(message.destination.as_str(), TEST_APP_SLO_URL);
        assert!(xml_of(&message).contains("status:Success"));
        assert!(h.app_sessions.all().is_empty());
        assert_eq!(
            h.audit.records.lock().unwrap().as_slice(),
            ["authentication.session_revoked"]
        );
    }

    /// An app logout request succeeds once. Repeating it is forbidden,
    /// leaving exactly one session-revocation audit record.
    #[test]
    fn a_logout_request_sent_again_is_refused() {
        let h = harness(test_app_settings(), logout_naming(ANN_AT_SALESFORCE));
        let use_case = AnswerAppUseCase::new(h.ports);
        let request = || AnswerAppRequest {
            idp_entity_id: SamlEntityId::new("https://auth.acme.com").unwrap(),
            message: posted_message(),
        };
        let auditor = test_auditor(h.audit.clone());

        let first = block_on(use_case.execute(&signed_in(), &auditor, request()));
        let again = block_on(use_case.execute(&signed_in(), &auditor, request()));

        assert!(first.is_ok());
        assert!(matches!(again, Err(AppError::Forbidden(_))));
        assert_eq!(
            h.audit.records.lock().unwrap().as_slice(),
            ["authentication.session_revoked"]
        );
    }

    /// Ann's browser holds no session here any more. Salesforce is told she
    /// is logged out, and nothing is recorded.
    #[test]
    fn a_browser_signed_out_already_is_logged_out() {
        let h = harness(test_app_settings(), logout_naming(ANN_AT_SALESFORCE));

        let browser = LogoutBrowser::SignedOut(test_ctx().tenant());

        let message = answer(h.ports, &h.audit, &browser).unwrap();

        assert!(xml_of(&message).contains("status:Success"));
        assert!(h.audit.records.lock().unwrap().is_empty());
    }

    /// A logout request naming another person at the app receives a failure
    /// response, preserves the app session and records no revocation.
    #[test]
    fn a_request_naming_someone_else_ends_nothing() {
        let h = harness(test_app_settings(), logout_naming("pairwise-bob"));

        let message = answer(h.ports, &h.audit, &signed_in()).unwrap();

        assert!(xml_of(&message).contains("status:Responder"));
        assert_eq!(h.app_sessions.all().len(), 1);
        assert!(h.audit.records.lock().unwrap().is_empty());
    }

    /// A logout request whose issuer names an unknown app is forbidden.
    #[test]
    fn a_request_from_an_unknown_app_is_refused() {
        let h = harness(test_app_settings(), logout_naming(ANN_AT_SALESFORCE));
        let stranger = FakeSamlMessageReader::from_issuer("https://evil.example")
            .with_logout_request(logout_naming(ANN_AT_SALESFORCE));
        let ports = AnswerAppPorts {
            message_reader: Arc::new(stranger),
            ..h.ports
        };

        let result = answer(ports, &h.audit, &signed_in());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// When the app requires signatures, an unsigned logout request is
    /// forbidden and preserves the stored app session.
    #[test]
    fn an_unsigned_request_is_refused_where_the_app_signs() {
        let settings = SamlServiceProviderSettings {
            request_signing: RequestSigningRule::Required(
                CertificatePem::new(TEST_CERTIFICATE_PEM).unwrap(),
            ),
            ..test_app_settings()
        };
        let h = harness(settings, logout_naming(ANN_AT_SALESFORCE));

        let result = answer(h.ports, &h.audit, &signed_in());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(h.app_sessions.all().len(), 1);
    }
}
