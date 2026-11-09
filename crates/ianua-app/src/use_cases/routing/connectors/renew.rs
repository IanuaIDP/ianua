//! Renew connector: the agent inside the tenant's network asks for the
//! next certificate for the key it enrolled with.
//!
//! The agent has no session: its signing request is the proof. The
//! request is signed by the private key it names, so only the holder of
//! the enrolled key can ask, and a request for any other key, for a
//! revoked connector or for one that never enrolled is refused the same
//! way.

use std::sync::Arc;

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificateRequestPem, ConnectorId};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::{ConnectorAuthority, ConnectorStore};
use crate::services::routing::connector_certificates::{CertificateDesk, IssuedConnector, Signing};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// What an agent sends to renew.
pub struct RenewRequest {
    /// The enrolled identity whose certificate should be renewed.
    pub connector_id: ConnectorId,
    /// A new signing request for the key it enrolled with.
    pub request: CertificateRequestPem,
}

/// The ports [`RenewUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct RenewPorts {
    /// Keeps the tenant's connectors.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// Reads the request and signs the certificate.
    pub certificate_signer: Arc<dyn ConnectorAuthority>,
}

/// Renews the certificate of an enrolled connector's agent.
pub struct RenewUseCase {
    ports: RenewPorts,
}

impl RenewUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: RenewPorts) -> Self {
        Self { ports }
    }
}

impl Command for RenewUseCase {
    type Caller = ScopedTenant;
    type Input = RenewRequest;
    type Output = Result<IssuedConnector, AppError>;

    /// Signs the next certificate for the connector's key. Once it is due
    /// it lasts a day from now and `routing.connector_renewed` is
    /// recorded; before then it ends when the one held now ends.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the request does not parse or its
    ///   signature does not hold.
    /// - `AppError::Forbidden` when the tenant has no such connector, it
    ///   is revoked or not enrolled, or the request names another key.
    /// - `AppError::Internal` on signing, storage or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: RenewRequest,
    ) -> Result<IssuedConnector, AppError> {
        let key = self
            .ports
            .certificate_signer
            .key_of(&request.request)
            .map_err(AppError::from_domain)?;
        let found = self
            .ports
            .connector_store
            .find_by_id(tenant, &request.connector_id)
            .await
            .or_internal()?;
        let Some(mut connector) = found else {
            return Err(renewal_refused());
        };
        let certificate = connector.renew(&key).map_err(AppError::from_domain)?;
        CertificateDesk::over(&self.ports.certificate_signer, &self.ports.connector_store)
            .issue(
                tenant,
                auditor,
                Signing {
                    connector: &mut connector,
                    request: &request.request,
                    certificate,
                },
            )
            .await
    }
}

/// The refusal of a connector this tenant does not have, worded as the
/// domain words any other refused renewal, so ids cannot be probed.
fn renewal_refused() -> AppError {
    AppError::from_domain(DomainError::forbidden(message!(
        "routing-the-connector-may-not-renew-with",
        "the connector may not renew with this key"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::connector::PrivateConnector;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::types::TenantId;
    use time::Duration;

    use super::*;
    use crate::test_support::routing::{
        FakeConnectorAuthority, FakeConnectorStore, connector_signing_request, enrolled_connector,
        routing_admin,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The store, the authority, the audit record, the use case a test
    /// runs, and the connector enrolled with key 7.
    struct Fixture {
        connectors: Arc<FakeConnectorStore>,
        authority: Arc<FakeConnectorAuthority>,
        audit: Arc<FakeEventDispatcher>,
        use_case: RenewUseCase,
        connector: ConnectorId,
    }

    /// A fixture holding `connector` in `tenant`.
    fn fixture_in(tenant: TenantId, connector: &PrivateConnector<ResolvedTenant>) -> Fixture {
        let connectors = Arc::new(FakeConnectorStore::holding(tenant, connector));
        let authority = Arc::new(FakeConnectorAuthority::default());
        Fixture {
            use_case: RenewUseCase::new(RenewPorts {
                connector_store: connectors.clone(),
                certificate_signer: authority.clone(),
            }),
            connectors,
            authority,
            audit: Arc::new(FakeEventDispatcher::new()),
            connector: *connector.id(),
        }
    }

    /// A fixture holding the wiki connector, enrolled with key 7.
    fn fixture() -> Fixture {
        fixture_in(test_ctx().tenant_id(), &enrolled_connector("wiki", 7))
    }

    /// Asks to renew `f`'s connector with a request for key `key`.
    fn renew(f: &Fixture, key: u8) -> Result<IssuedConnector, AppError> {
        block_on(f.use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(f.audit.clone()),
            RenewRequest {
                connector_id: f.connector,
                request: connector_signing_request(key),
            },
        ))
    }

    /// Late in its certificate's day, the agent asks again for its key.
    /// It gets a certificate lasting a day from now, the connector keeps
    /// the new end, and the renewal is recorded.
    #[test]
    fn a_due_certificate_is_renewed() {
        let f = fixture();
        let _later = clock::freeze(clock::now() + Duration::hours(17));

        let renewed = renew(&f, 7).unwrap();

        assert_eq!(renewed.expires_at, clock::now() + Duration::hours(24));
        assert_eq!(f.authority.signed(), 1);
        let stored = f
            .connectors
            .stored(test_ctx().tenant_id(), &f.connector)
            .unwrap();
        assert_eq!(
            stored.certificate().unwrap().expires_at(),
            renewed.expires_at
        );
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.connector_renewed"]
        );
    }

    /// The agent's last answer was lost and it asks again at once. It gets
    /// the certificate it holds, ending when that one ends, and nothing is
    /// recorded.
    #[test]
    fn an_early_renewal_answers_the_certificate_held() {
        let f = fixture();
        let held = f
            .connectors
            .stored(test_ctx().tenant_id(), &f.connector)
            .unwrap()
            .certificate()
            .unwrap();

        let answered = renew(&f, 7).unwrap();

        assert_eq!(answered.expires_at, held.expires_at());
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Renewal for a key different from the enrolled key is forbidden.
    /// No certificate is signed and no renewal event is recorded.
    #[test]
    fn a_request_for_another_key_is_refused() {
        let f = fixture();
        let _later = clock::freeze(clock::now() + Duration::hours(17));

        let result = renew(&f, 9);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.authority.signed(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A revoked connector cannot renew with its enrolled key, and no
    /// certificate is signed.
    #[test]
    fn a_revoked_connector_is_refused() {
        let mut connector = enrolled_connector("wiki", 7);
        connector.revoke(&routing_admin()).unwrap();
        let f = fixture_in(test_ctx().tenant_id(), &connector);
        let _later = clock::freeze(clock::now() + Duration::hours(17));

        let result = renew(&f, 7);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.authority.signed(), 0);
    }

    /// Renewing another tenant's connector is forbidden and signs no certificate.
    #[test]
    fn another_tenants_connector_is_refused() {
        let f = fixture_in(TenantId::new(), &enrolled_connector("bobs", 7));

        let result = renew(&f, 7);

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.authority.signed(), 0);
    }

    /// An unsigned renewal request is refused and signs no certificate.
    #[test]
    fn an_unsigned_request_is_refused() {
        let f = fixture();

        let result = block_on(f.use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(f.audit.clone()),
            RenewRequest {
                connector_id: f.connector,
                request: CertificateRequestPem::new(
                    "-----BEGIN CERTIFICATE REQUEST-----\nunsigned\n-----END CERTIFICATE REQUEST-----",
                )
                .unwrap(),
            },
        ));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert_eq!(f.authority.signed(), 0);
    }
}
