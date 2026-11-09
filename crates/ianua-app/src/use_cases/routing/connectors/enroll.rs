//! Enroll connector: the agent inside the tenant's network presents its
//! one-time code with a signing request for its key, and gets the first
//! certificate it holds its link to the gateway with.
//!
//! The agent has no session: the code is all it proves, and the request's
//! signature shows it holds the key. So an unknown, spent, expired or
//! revoked code is refused the same way, and the refusal says no more.

use std::sync::Arc;

use ianua_domain::domains::routing::connector::PrivateConnector;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateRequestPem, TokenHash};

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::routing::{ConnectorAuthority, ConnectorCodeGenerator, ConnectorStore};
use crate::services::routing::connector_certificates::{CertificateDesk, IssuedConnector, Signing};
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;

/// What an agent presents to enroll.
pub struct EnrollRequest {
    /// The one-time code the admin was shown.
    pub code: Secret,
    /// A signing request for the key the agent holds its link with.
    pub request: CertificateRequestPem,
}

/// The ports [`EnrollUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct EnrollPorts {
    /// Keeps the tenant's connectors.
    pub connector_store: Arc<dyn ConnectorStore>,
    /// Hashes the presented code the way it was hashed when made.
    pub code_generator: Arc<dyn ConnectorCodeGenerator>,
    /// Reads the request and signs the certificate.
    pub certificate_signer: Arc<dyn ConnectorAuthority>,
}

/// Enrolls the agent of a connector awaiting enrollment.
pub struct EnrollUseCase {
    ports: EnrollPorts,
}

impl EnrollUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: EnrollPorts) -> Self {
        Self { ports }
    }

    /// The connector awaiting the code hashed as `code_hash`, refused like
    /// any bad code when none is.
    async fn awaiting(
        &self,
        tenant: &ScopedTenant,
        code_hash: &TokenHash,
    ) -> Result<PrivateConnector<ResolvedTenant>, AppError> {
        self.ports
            .connector_store
            .find_awaiting_by_code(tenant, code_hash)
            .await
            .or_internal()?
            .ok_or_else(code_refused)
    }
}

impl Command for EnrollUseCase {
    type Caller = ScopedTenant;
    type Input = EnrollRequest;
    type Output = Result<IssuedConnector, AppError>;

    /// Enrolls the connector whose code `request` presents, pins the key
    /// its signing request names, signs a certificate for that key good
    /// for a day, and records `routing.connector_enrolled`. The code is
    /// spent, and only a link held with that key is let in from now on.
    ///
    /// # Errors
    ///
    /// - `AppError::Domain` when the signing request does not parse or its
    ///   signature does not hold.
    /// - `AppError::Forbidden` when the code is unknown, spent, expired, or
    ///   its connector is revoked.
    /// - `AppError::Internal` on signing, storage or audit failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        auditor: &RequestAuditor,
        request: EnrollRequest,
    ) -> Result<IssuedConnector, AppError> {
        let key = self
            .ports
            .certificate_signer
            .key_of(&request.request)
            .map_err(AppError::from_domain)?;
        let code_hash = self.ports.code_generator.hash_presented(&request.code);
        let mut connector = self.awaiting(tenant, &code_hash).await?;
        let certificate = connector
            .enroll(&code_hash, key)
            .map_err(AppError::from_domain)?;
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

/// The refusal of a code no connector awaits, worded as the domain words
/// any other refused code.
fn code_refused() -> AppError {
    AppError::from_domain(DomainError::forbidden(message!(
        "routing-the-enrollment-code-is-not-good",
        "the enrollment code is not good"
    )))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::routing::connector::PrivateConnector;
    use ianua_domain::isolation::scope::ResolvedTenant;
    use ianua_domain::shared::clock;
    use ianua_domain::types::{ConnectorId, TenantId};

    use super::*;
    use crate::test_support::routing::{
        FakeConnectorAuthority, FakeConnectorStore, awaiting_connector, connector_key,
        connector_signing_request, routing_admin,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    /// The store, the authority, the audit record, the use case a test
    /// runs, and the connector awaiting the code `enroll-code-a`.
    struct Fixture {
        connectors: Arc<FakeConnectorStore>,
        authority: Arc<FakeConnectorAuthority>,
        audit: Arc<FakeEventDispatcher>,
        use_case: EnrollUseCase,
        connector: ConnectorId,
    }

    /// A fixture holding `connector` in `tenant`.
    fn fixture_in(tenant: TenantId, connector: &PrivateConnector<ResolvedTenant>) -> Fixture {
        let connectors = Arc::new(FakeConnectorStore::holding(tenant, connector));
        let authority = Arc::new(FakeConnectorAuthority::default());
        Fixture {
            use_case: EnrollUseCase::new(EnrollPorts {
                connector_store: connectors.clone(),
                certificate_signer: authority.clone(),
                ..EnrollPorts::fakes()
            }),
            connectors,
            authority,
            audit: Arc::new(FakeEventDispatcher::new()),
            connector: *connector.id(),
        }
    }

    /// A fixture holding the payroll connector in Ann's tenant.
    fn fixture_holding(connector: &PrivateConnector<ResolvedTenant>) -> Fixture {
        fixture_in(test_ctx().tenant_id(), connector)
    }

    /// The payroll connector, awaiting the code `enroll-code-a`.
    fn payroll() -> PrivateConnector<ResolvedTenant> {
        awaiting_connector("payroll", "enroll-code-a", &["payroll.corp.internal"])
    }

    /// Presents `code` with a request for the agent's key, 7.
    fn enroll(f: &Fixture, code: &str) -> Result<IssuedConnector, AppError> {
        block_on(f.use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(f.audit.clone()),
            EnrollRequest {
                code: Secret::new(code),
                request: connector_signing_request(7),
            },
        ))
    }

    /// Whether the stored connector lets a link with the agent's key in.
    fn admits_agent(f: &Fixture) -> bool {
        f.connectors
            .stored(test_ctx().tenant_id(), &f.connector)
            .unwrap()
            .admits_tunnel(&connector_key(7))
    }

    /// Ann's agent presents the code she was shown. The connector pins its
    /// key and lets its link in, the agent gets a certificate good for a
    /// day with the authority to check the gateway by, and the enrollment
    /// is recorded.
    #[test]
    fn the_right_code_enrolls_the_agent() {
        let f = fixture_holding(&payroll());

        let enrolled = enroll(&f, "enroll-code-a").unwrap();

        let stored = f
            .connectors
            .stored(test_ctx().tenant_id(), &f.connector)
            .unwrap();
        assert_eq!(enrolled.connector_id, f.connector);
        assert_eq!(
            enrolled.expires_at,
            stored.updated_at() + time::Duration::hours(24)
        );
        assert!(enrolled.authority_pem.contains("BEGIN CERTIFICATE"));
        assert!(admits_agent(&f));
        assert_eq!(f.authority.signed(), 1);
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.connector_enrolled"]
        );
    }

    /// An unknown code is forbidden without admitting the requested key,
    /// signing a certificate or recording enrollment.
    #[test]
    fn an_unknown_code_is_refused() {
        let f = fixture_holding(&payroll());

        let result = enroll(&f, "guessed");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(!admits_agent(&f));
        assert_eq!(f.authority.signed(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// Reusing a successfully enrolled code is forbidden, leaving exactly
    /// one signed certificate and one enrollment audit record.
    #[test]
    fn a_spent_code_is_refused() {
        let f = fixture_holding(&payroll());
        enroll(&f, "enroll-code-a").unwrap();

        let again = enroll(&f, "enroll-code-a");

        assert!(matches!(again, Err(AppError::Forbidden(_))));
        assert_eq!(f.authority.signed(), 1);
        assert_eq!(f.audit.records.lock().unwrap().len(), 1);
    }

    /// An enrollment code presented after sixty-one minutes is forbidden.
    /// No certificate is signed and no enrollment event is recorded.
    #[test]
    fn an_expired_code_is_refused() {
        let f = fixture_holding(&payroll());
        let _later = clock::freeze(clock::now() + time::Duration::minutes(61));

        let result = enroll(&f, "enroll-code-a");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.authority.signed(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A revoked connector's enrollment code is forbidden without signing a
    /// certificate or recording enrollment.
    #[test]
    fn a_revoked_connectors_code_is_refused() {
        let mut connector = payroll();
        connector.revoke(&routing_admin()).unwrap();
        let f = fixture_holding(&connector);

        let result = enroll(&f, "enroll-code-a");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.authority.signed(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// A connector of another tenant is not found by its code here, so its
    /// code enrolls nothing in this tenant.
    #[test]
    fn another_tenants_code_is_refused() {
        let f = fixture_in(TenantId::new(), &payroll());

        let result = enroll(&f, "enroll-code-a");

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert_eq!(f.authority.signed(), 0);
        assert!(f.audit.records.lock().unwrap().is_empty());
    }

    /// An unsigned certificate request is refused, and the enrollment code
    /// remains usable with a valid request.
    #[test]
    fn an_unsigned_request_is_refused_and_spends_no_code() {
        let f = fixture_holding(&payroll());

        let result = block_on(f.use_case.execute(
            &test_ctx().tenant(),
            &test_auditor(f.audit.clone()),
            EnrollRequest {
                code: Secret::new("enroll-code-a"),
                request: CertificateRequestPem::new(
                    "-----BEGIN CERTIFICATE REQUEST-----\nunsigned\n-----END CERTIFICATE REQUEST-----",
                )
                .unwrap(),
            },
        ));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(enroll(&f, "enroll-code-a").is_ok());
    }
}
