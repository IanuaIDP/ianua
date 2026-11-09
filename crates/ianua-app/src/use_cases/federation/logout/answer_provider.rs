//! Answer provider logout: a connection's identity provider asks this
//! platform, its service provider, to log the person out.
//!
//! The browser carries the request, and the session the person holds here.
//! The request is taken only signed by a certificate the connection takes,
//! from the provider it names, and ends the session only when it names the
//! subject and the provider session that session was opened with. Whatever
//! happens, the provider gets a signed answer saying how it went.

use std::sync::Arc;

use ianua_domain::domains::federation::connection::{FederatedIdpConnection, ProviderLogout};
use ianua_domain::domains::federation::saml::logout::LogoutStatus;
use ianua_domain::domains::federation::saml::logout_builder::{
    LogoutResponseParams, build_logout_response,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{ConnectionId, SamlEntityId, SessionIndex};

use crate::acting::TenantAuthorities;
use crate::acting::tenant::SignedInAccount;
use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::{
    ConnectionStore, InboundSamlMessage, ProviderSessionStore, SamlLogoutLedger, SamlMessageReader,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::federation::logout::messages::{
    LogoutBrowser, LogoutSigner, OutgoingLogoutMessage, SessionEnding, provider_trust, take_once,
};
use crate::use_cases::federation::lookup::{existing_connection, fresh_response_id};

/// A provider's logout request, as the browser brought it.
pub struct AnswerProviderRequest {
    /// The connection whose logout address it came to.
    pub connection_id: ConnectionId,
    /// This platform's entity id as the connection's service provider,
    /// written as the answer's issuer.
    pub sp_entity_id: SamlEntityId,
    /// The request.
    pub message: InboundSamlMessage,
}

/// The ports [`AnswerProviderUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct AnswerProviderPorts {
    /// Who is signed in to the browser's session.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
    /// The tenant's connections.
    pub connections: Arc<dyn ConnectionStore>,
    /// Reads the request and checks its signature.
    pub message_reader: Arc<dyn SamlMessageReader>,
    /// The provider sessions behind sessions here.
    pub provider_sessions: Arc<dyn ProviderSessionStore>,
    /// The logout requests taken already, so each is taken once.
    pub logout_ledger: Arc<dyn SamlLogoutLedger>,
    /// Ends the person's session.
    pub ending: SessionEnding,
    /// Signs the answer.
    pub signer: LogoutSigner,
}

/// Answers a connection's provider asking to log the person out.
pub struct AnswerProviderUseCase {
    ports: AnswerProviderPorts,
}

impl AnswerProviderUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: AnswerProviderPorts) -> Self {
        Self { ports }
    }

    /// The logout `message` asks of `connection`, once it is signed by a
    /// certificate the connection takes, comes from its provider, is fresh
    /// and was never taken before.
    async fn read(
        &self,
        tenant: &ScopedTenant,
        connection: &FederatedIdpConnection<ResolvedTenant>,
        message: &InboundSamlMessage,
    ) -> Result<ProviderLogout, AppError> {
        let request = self
            .ports
            .message_reader
            .logout_request(message, &provider_trust(connection)?)
            .map_err(AppError::from_domain)?;
        let logout = connection
            .accept_logout(&request)
            .map_err(AppError::from_domain)?;
        take_once(self.ports.logout_ledger.as_ref(), tenant, &request).await?;
        Ok(logout)
    }

    /// Logs the browser's person out when `logout` names the provider
    /// session their session was opened with, and says how it went. A
    /// browser signed out already is logged out.
    async fn logged_out(
        &self,
        browser: &LogoutBrowser,
        auditor: &RequestAuditor,
        connection_id: &ConnectionId,
        logout: &ProviderLogout,
    ) -> Result<LogoutStatus, AppError> {
        let authorities = self.ports.tenant_authorities.as_ref();
        let Some(person) = browser.person(authorities).await? else {
            return Ok(LogoutStatus::Success);
        };
        let tenant = browser.tenant();
        if !self
            .names_the_person(&tenant, &person, connection_id, logout)
            .await?
        {
            return Ok(LogoutStatus::Failed);
        }
        let session_id = *person.session.id();
        self.ports.ending.end(&tenant, person, auditor).await?;
        self.ports
            .provider_sessions
            .delete_by_session(&tenant, &session_id)
            .await
            .or_internal()?;
        Ok(LogoutStatus::Success)
    }

    /// Whether `logout` names the subject, and the provider session, behind
    /// `person`'s session at `connection_id`.
    async fn names_the_person(
        &self,
        tenant: &ScopedTenant,
        person: &SignedInAccount,
        connection_id: &ConnectionId,
        logout: &ProviderLogout,
    ) -> Result<bool, AppError> {
        let behind = self
            .ports
            .provider_sessions
            .find_by_session(tenant, person.session.id())
            .await
            .or_internal()?;
        Ok(behind.is_some_and(|kept| {
            kept.connection_id == *connection_id
                && kept.subject == *logout.subject()
                && names_session(logout, &kept.session_index)
        }))
    }
}

impl Command for AnswerProviderUseCase {
    type Caller = LogoutBrowser;
    type Input = AnswerProviderRequest;
    type Output = Result<OutgoingLogoutMessage, AppError>;

    /// The signed answer to the provider's logout request, for the browser
    /// to post to the provider's logout endpoint. The browser's session
    /// ends, and `authentication.session_revoked` is recorded, when the
    /// request names the subject and provider session it was opened with;
    /// the answer says it failed when it names anyone else.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` if the connection doesn't exist, or the tenant
    ///   has no signing key set.
    /// - `AppError::Forbidden` if the request is unsigned, signed by a
    ///   certificate the connection does not take, names another issuer, or
    ///   was taken before.
    /// - `AppError::Conflict` if it is not a SAML connection, or its
    ///   provider has no logout endpoint to answer at.
    /// - `AppError::Domain` if the request is malformed, too old, or issued
    ///   ahead of now.
    /// - `AppError::Internal` on signing, storage or audit failure.
    async fn execute(
        &self,
        browser: &LogoutBrowser,
        auditor: &RequestAuditor,
        request: AnswerProviderRequest,
    ) -> Result<OutgoingLogoutMessage, AppError> {
        let tenant = browser.tenant();
        let store = self.ports.connections.as_ref();
        let connection = existing_connection(store, &tenant, &request.connection_id).await?;
        let logout = self.read(&tenant, &connection, &request.message).await?;
        let status = self
            .logged_out(browser, auditor, connection.id(), &logout)
            .await?;
        let answer = logout.answer().clone();
        let destination = answer.destination().clone();
        let response = build_logout_response(&LogoutResponseParams {
            response_id: fresh_response_id()?,
            issuer: request.sp_entity_id,
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

/// Whether `logout` asks to end `session_index`: it names it, or names no
/// session, which asks for every one.
fn names_session(logout: &ProviderLogout, session_index: &SessionIndex) -> bool {
    logout.session_indexes().is_empty() || logout.session_indexes().contains(session_index)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::federation::saml::logout::{LogoutRequestParts, SamlLogoutRequest};
    use ianua_domain::domains::federation::saml::name_id::SamlNameIdValue;
    use ianua_domain::types::{FederatedSubject, SamlRequestId};

    use super::*;
    use crate::ports::federation::ProviderSession;
    use crate::test_support::federation::{
        FakeConnectionStore, FakeProviderSessions, FakeSamlMessageReader, FakeSignature,
        posted_message, test_connection, test_logout_signer,
    };
    use crate::test_support::{
        FakeEventDispatcher, block_on, test_auditor, test_ctx, test_session_id,
    };

    const OKTA: &str = "https://idp.acme.com";
    const ANN_AT_OKTA: &str = "00u-ann";

    /// Okta's request to log out whoever it knows as `subject`, from every
    /// session.
    fn logout_naming(subject: &str) -> SamlLogoutRequest {
        SamlLogoutRequest::new(LogoutRequestParts {
            id: SamlRequestId::new("_logout-1").unwrap(),
            issuer: SamlEntityId::new(OKTA).unwrap(),
            issued_at: ianua_domain::shared::clock::now(),
            name_id: SamlNameIdValue::new(subject).unwrap(),
            session_indexes: Vec::new(),
        })
    }

    struct Harness {
        ports: AnswerProviderPorts,
        connection_id: ConnectionId,
        provider_sessions: Arc<FakeProviderSessions>,
        audit: Arc<FakeEventDispatcher>,
    }

    /// Ann's session, opened through Okta, which sends `request` signed as
    /// `signature`.
    fn harness(request: SamlLogoutRequest, signature: FakeSignature) -> Harness {
        let tenant = test_ctx().tenant();
        let connection_id = ConnectionId::new();
        let okta = test_connection(connection_id, ConnectionStatus::Active);
        let provider_sessions = Arc::new(FakeProviderSessions::empty());
        let behind = ProviderSession {
            session_id: test_session_id(),
            connection_id,
            subject: FederatedSubject::new(ANN_AT_OKTA).unwrap(),
            session_index: SessionIndex::new("_okta-1").unwrap(),
        };
        block_on(provider_sessions.save(&tenant, &behind)).unwrap();
        let reader = FakeSamlMessageReader::from_issuer(OKTA)
            .signed(signature)
            .with_logout_request(request);
        let ports = AnswerProviderPorts {
            connections: Arc::new(FakeConnectionStore::holding(&tenant, [okta])),
            message_reader: Arc::new(reader),
            provider_sessions: provider_sessions.clone(),
            signer: test_logout_signer(),
            ..AnswerProviderPorts::fakes()
        };
        Harness {
            ports,
            connection_id,
            provider_sessions,
            audit: Arc::new(FakeEventDispatcher::new()),
        }
    }

    fn answer(
        ports: AnswerProviderPorts,
        connection_id: ConnectionId,
        audit: &Arc<FakeEventDispatcher>,
        browser: &LogoutBrowser,
    ) -> Result<OutgoingLogoutMessage, AppError> {
        let request = AnswerProviderRequest {
            connection_id,
            sp_entity_id: SamlEntityId::new("https://auth.acme.com/sp").unwrap(),
            message: posted_message(),
        };
        let use_case = AnswerProviderUseCase::new(ports);
        block_on(use_case.execute(browser, &test_auditor(audit.clone()), request))
    }

    fn signed_in() -> LogoutBrowser {
        LogoutBrowser::SignedIn(Box::new(test_ctx()))
    }

    fn xml_of(message: &OutgoingLogoutMessage) -> String {
        String::from_utf8(STANDARD.decode(&message.base64_message).unwrap()).unwrap()
    }

    /// A signed provider logout request succeeds once. Repeating it is
    /// forbidden, leaving exactly one session-revocation audit record.
    #[test]
    fn a_logout_request_sent_again_is_refused() {
        let h = harness(logout_naming(ANN_AT_OKTA), FakeSignature::ByTrustedKey);
        let use_case = AnswerProviderUseCase::new(h.ports);
        let request = || AnswerProviderRequest {
            connection_id: h.connection_id,
            sp_entity_id: SamlEntityId::new("https://auth.acme.com/sp").unwrap(),
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

    /// A provider logout request issued an hour ago is refused. Its provider
    /// session remains stored and no session-revocation event is recorded.
    #[test]
    fn a_logout_request_issued_long_ago_is_refused() {
        let stale = SamlLogoutRequest::new(LogoutRequestParts {
            id: SamlRequestId::new("_logout-old").unwrap(),
            issuer: SamlEntityId::new(OKTA).unwrap(),
            issued_at: ianua_domain::shared::clock::now() - time::Duration::hours(1),
            name_id: SamlNameIdValue::new(ANN_AT_OKTA).unwrap(),
            session_indexes: Vec::new(),
        });
        let h = harness(stale, FakeSignature::ByTrustedKey);

        let result = answer(h.ports, h.connection_id, &h.audit, &signed_in());

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(h.audit.records.lock().unwrap().is_empty());
        assert_eq!(h.provider_sessions.all().len(), 1);
    }

    /// Ann logs out at Okta, which asks Acme to log her out too. Her
    /// session here ends, Okta is told it worked at its logout endpoint, and
    /// the ending is recorded.
    #[test]
    fn the_provider_logs_the_person_out_here_too() {
        let h = harness(logout_naming(ANN_AT_OKTA), FakeSignature::ByTrustedKey);

        let message = answer(h.ports, h.connection_id, &h.audit, &signed_in()).unwrap();

        assert_eq!(message.destination.as_str(), "https://idp.acme.com/slo");
        assert!(xml_of(&message).contains("status:Success"));
        assert!(h.provider_sessions.all().is_empty());
        assert_eq!(
            h.audit.records.lock().unwrap().as_slice(),
            ["authentication.session_revoked"]
        );
    }

    /// Ann's browser holds no session here any more. Okta is told she is
    /// logged out, and nothing is recorded.
    #[test]
    fn a_browser_signed_out_already_is_logged_out() {
        let h = harness(logout_naming(ANN_AT_OKTA), FakeSignature::ByTrustedKey);
        let browser = LogoutBrowser::SignedOut(test_ctx().tenant());

        let message = answer(h.ports, h.connection_id, &h.audit, &browser).unwrap();

        assert!(xml_of(&message).contains("status:Success"));
        assert!(h.audit.records.lock().unwrap().is_empty());
    }

    /// A signed logout request naming another subject receives a failure
    /// response, preserves the provider session and records no revocation.
    #[test]
    fn a_request_naming_someone_else_ends_nothing() {
        let h = harness(logout_naming("00u-bob"), FakeSignature::ByTrustedKey);

        let message = answer(h.ports, h.connection_id, &h.audit, &signed_in()).unwrap();

        assert!(xml_of(&message).contains("status:Responder"));
        assert_eq!(h.provider_sessions.all().len(), 1);
        assert!(h.audit.records.lock().unwrap().is_empty());
    }

    /// An unsigned provider logout request is forbidden and preserves the
    /// stored provider session.
    #[test]
    fn an_unsigned_request_is_refused() {
        let h = harness(logout_naming(ANN_AT_OKTA), FakeSignature::Unsigned);

        let result = answer(h.ports, h.connection_id, &h.audit, &signed_in());

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(h.provider_sessions.all().len(), 1);
    }

    /// A request comes to a connection Acme does not have. It is not found.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let h = harness(logout_naming(ANN_AT_OKTA), FakeSignature::ByTrustedKey);

        let result = answer(h.ports, ConnectionId::new(), &h.audit, &signed_in());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
