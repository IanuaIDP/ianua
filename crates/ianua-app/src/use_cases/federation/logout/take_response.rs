//! Take logout response: a peer answers a logout request this platform
//! sent, an app as identity provider or a connection's provider as service
//! provider.
//!
//! The answer is taken once, only for a request sent from here, only from
//! the peer it went to, signed as that peer signs, and within ten minutes.

use std::sync::Arc;

use ianua_domain::domains::federation::saml::logout::{LogoutStatus, SamlLogoutResponse};
use ianua_domain::domains::federation::saml::trail::SamlTrail;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ActorRef, ConnectionId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::federation::{
    ConnectionStore, InboundSamlMessage, SamlMessageReader, SamlServiceProviderStore,
    SentLogoutRequestStore, SignatureTrust,
};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::federation::idp::lookup::{sending_service_provider, signature_trust};
use crate::use_cases::federation::logout::messages::provider_trust;
use crate::use_cases::federation::lookup::existing_connection;

/// Which kind of peer the answer came back to this platform as.
pub enum Answerer {
    /// One of the tenant's SAML apps, named by the answer's issuer.
    App,
    /// The provider of this connection.
    Connection(ConnectionId),
}

/// A peer's answer, as the browser brought it.
pub struct TakeResponseRequest {
    /// Who answers.
    pub answerer: Answerer,
    /// The answer.
    pub message: InboundSamlMessage,
}

/// The ports [`TakeResponseUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct TakeResponsePorts {
    /// Reads the answer and checks its signature.
    pub message_reader: Arc<dyn SamlMessageReader>,
    /// The tenant's SAML apps.
    pub service_providers: Arc<dyn SamlServiceProviderStore>,
    /// The tenant's connections.
    pub connections: Arc<dyn ConnectionStore>,
    /// The requests sent and waiting for their answer.
    pub sent_requests: Arc<dyn SentLogoutRequestStore>,
}

/// Takes a peer's answer to a logout request sent from here.
pub struct TakeResponseUseCase {
    ports: TakeResponsePorts,
}

impl TakeResponseUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: TakeResponsePorts) -> Self {
        Self { ports }
    }

    /// The keys `answerer` signs its messages with.
    async fn trust(
        &self,
        tenant: &ScopedTenant,
        request: &TakeResponseRequest,
    ) -> Result<SignatureTrust, AppError> {
        match &request.answerer {
            Answerer::App => {
                let reader = self.ports.message_reader.as_ref();
                let issuer = reader
                    .issuer(&request.message)
                    .map_err(AppError::from_domain)?;
                let store = self.ports.service_providers.as_ref();
                let app = sending_service_provider(store, tenant, &issuer).await?;
                Ok(signature_trust(&app.settings().request_signing))
            }
            Answerer::Connection(id) => {
                let store = self.ports.connections.as_ref();
                provider_trust(&existing_connection(store, tenant, id).await?)
            }
        }
    }

    /// How the logout went, as `response` says, once it answers a request
    /// sent from here to the peer that answered, raised on `trail`.
    async fn status(
        &self,
        tenant: &ScopedTenant,
        response: &SamlLogoutResponse,
        trail: &mut SamlTrail<ResolvedTenant>,
    ) -> Result<LogoutStatus, AppError> {
        let sent = self
            .ports
            .sent_requests
            .take(tenant, response.in_response_to())
            .await
            .or_internal()?
            .ok_or_else(|| {
                AppError::Forbidden(message!(
                    "federation-no-logout-request-awaits-this-answer",
                    "no logout request awaits this answer"
                ))
            })?;
        trail
            .logout_answered(&sent, response)
            .map_err(AppError::from_domain)
    }
}

impl Command for TakeResponseUseCase {
    type Caller = ScopedTenant;
    type Input = TakeResponseRequest;
    type Output = Result<LogoutStatus, AppError>;

    /// How the logout went at the peer. The request it answers is taken, so
    /// the answer counts once, and `federation.logout_response_taken` is
    /// recorded with how it went, as done by the system: the browser that
    /// carried it is signed out already, and the peer is no principal here.
    ///
    /// # Errors
    ///
    /// - `AppError::Forbidden` if no app of the tenant sent it, its
    ///   signature does not verify or is missing where the peer signs, no
    ///   request sent from here awaits it, or it comes from another peer
    ///   than the request went to.
    /// - `AppError::NotFound` if the connection doesn't exist.
    /// - `AppError::Conflict` if the connection is not SAML, or the answer
    ///   came after ten minutes.
    /// - `AppError::Domain` if the answer is malformed.
    /// - `AppError::Internal` on storage or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: TakeResponseRequest,
    ) -> Result<LogoutStatus, AppError> {
        let trust = self.trust(tenant, &request).await?;
        let response = self
            .ports
            .message_reader
            .logout_response(&request.message, &trust)
            .map_err(AppError::from_domain)?;
        let mut trail = SamlTrail::default();
        let status = self.status(tenant, &response, &mut trail).await?;
        auditor
            .dispatch_by(&ActorRef::System, trail.take_events(tenant))
            .await
            .or_internal()?;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::federation::connection_status::ConnectionStatus;
    use ianua_domain::domains::federation::saml::logout::{LogoutResponseParts, LogoutSubject};
    use ianua_domain::domains::federation::saml::name_id::SamlNameIdValue;
    use ianua_domain::types::{SamlEntityId, SamlRequestId, SamlResponseId, SessionIndex};

    use super::*;
    use crate::test_support::federation::{
        FakeConnectionStore, FakeSamlMessageReader, FakeSentLogoutRequests, FakeSignature,
        posted_message, test_connection,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const OKTA: &str = "https://idp.acme.com";

    /// Okta's answer to the request with id `answers`, saying `status`.
    fn okta_answer(answers: &str, status: LogoutStatus) -> SamlLogoutResponse {
        SamlLogoutResponse::new(LogoutResponseParts {
            id: SamlResponseId::new("_answer-1").unwrap(),
            issuer: SamlEntityId::new(OKTA).unwrap(),
            in_response_to: SamlRequestId::new(answers).unwrap(),
            status,
        })
    }

    struct Harness {
        ports: TakeResponsePorts,
        connection_id: ConnectionId,
        sent: Arc<FakeSentLogoutRequests>,
    }

    /// Acme sent Okta the logout request `_sent-1`, and Okta answers with
    /// `answer`, signed as `signature`.
    fn harness(answer: SamlLogoutResponse, signature: FakeSignature) -> Harness {
        let tenant = test_ctx().tenant();
        let connection_id = ConnectionId::new();
        let okta = test_connection(connection_id, ConnectionStatus::Active);
        let sent_request = okta
            .logout_request(LogoutSubject {
                request_id: SamlRequestId::new("_sent-1").unwrap(),
                name_id: SamlNameIdValue::new("00u-ann").unwrap(),
                session_index: SessionIndex::new("_okta-1").unwrap(),
            })
            .unwrap();
        let sent = Arc::new(FakeSentLogoutRequests::empty());
        block_on(sent.save(&tenant, &sent_request)).unwrap();
        let reader = FakeSamlMessageReader::from_issuer(OKTA)
            .signed(signature)
            .with_logout_response(answer);
        let ports = TakeResponsePorts {
            message_reader: Arc::new(reader),
            connections: Arc::new(FakeConnectionStore::holding(&tenant, [okta])),
            sent_requests: sent.clone(),
            ..TakeResponsePorts::fakes()
        };
        Harness {
            ports,
            connection_id,
            sent,
        }
    }

    fn take(
        ports: TakeResponsePorts,
        connection_id: ConnectionId,
    ) -> Result<LogoutStatus, AppError> {
        take_recorded(ports, connection_id, &Arc::new(FakeEventDispatcher::new()))
    }

    fn take_recorded(
        ports: TakeResponsePorts,
        connection_id: ConnectionId,
        audit: &Arc<FakeEventDispatcher>,
    ) -> Result<LogoutStatus, AppError> {
        let request = TakeResponseRequest {
            answerer: Answerer::Connection(connection_id),
            message: posted_message(),
        };
        let auditor = test_auditor(audit.clone());
        block_on(TakeResponseUseCase::new(ports).execute(&test_ctx().tenant(), &auditor, request))
    }

    /// Okta answers that Ann is logged out. The answer is taken and
    /// recorded, and the request it answered no longer waits.
    #[test]
    fn the_answer_to_a_sent_request_is_taken_once() {
        let h = harness(
            okta_answer("_sent-1", LogoutStatus::Success),
            FakeSignature::ByTrustedKey,
        );
        let audit = Arc::new(FakeEventDispatcher::new());

        let status = take_recorded(h.ports, h.connection_id, &audit).unwrap();

        assert_eq!(status, LogoutStatus::Success);
        assert!(h.sent.all().is_empty());
        assert_eq!(
            audit.records.lock().unwrap().as_slice(),
            ["federation.logout_response_taken"]
        );
    }

    /// A signed logout answer is forbidden when its request identifier does
    /// not match a pending request.
    #[test]
    fn an_answer_to_no_request_sent_is_refused() {
        let h = harness(
            okta_answer("_never-sent", LogoutStatus::Success),
            FakeSignature::ByTrustedKey,
        );

        let result = take(h.ports, h.connection_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// An unsigned provider answer is forbidden and leaves the sent logout
    /// request waiting for an answer.
    #[test]
    fn an_unsigned_answer_is_refused() {
        let h = harness(
            okta_answer("_sent-1", LogoutStatus::Success),
            FakeSignature::Unsigned,
        );

        let result = take(h.ports, h.connection_id);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(h.sent.all().len(), 1);
    }

    /// An answer comes for a connection Acme does not have. It is not
    /// found.
    #[test]
    fn an_unknown_connection_is_not_found() {
        let h = harness(
            okta_answer("_sent-1", LogoutStatus::Success),
            FakeSignature::ByTrustedKey,
        );

        let result = take(h.ports, ConnectionId::new());

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
