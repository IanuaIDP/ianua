//! Open client key: the private key a service presents to its upstream,
//! opened for the gateway to hand its TLS client.
//!
//! The key is sealed for the place the service keeps it when an admin
//! gives it, and only that place opens it again, so a sealed key copied to
//! another service, or another tenant's, never opens. The gateway asks once
//! per service when it loads its tables, never per request.

use std::sync::Arc;

use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{SealedSecret, ServiceId};

use crate::error::{AppError, OrInternal};
use crate::ports::authentication::SecretEncryptor;
use crate::services::sealing::opened_text;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;
use crate::use_cases::routing::services::upstream_tls::client_key_place;

/// The sealed key of one service, as the gateway read it.
pub struct OpenClientKeyRequest {
    /// The service presenting the key.
    pub service_id: ServiceId,
    /// Its client certificate's private key, sealed.
    pub sealed: SealedSecret,
}

/// The ports [`OpenClientKeyUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct OpenClientKeyPorts {
    /// Opens the sealed key.
    pub encryptor: Arc<dyn SecretEncryptor>,
}

/// Opens the private key a service presents to its upstream.
pub struct OpenClientKeyUseCase {
    ports: OpenClientKeyPorts,
}

impl OpenClientKeyUseCase {
    /// A use case opening keys through `ports`.
    #[must_use]
    pub fn new(ports: OpenClientKeyPorts) -> Self {
        Self { ports }
    }
}

impl Query for OpenClientKeyUseCase {
    type Caller = ScopedTenant;
    type Input = OpenClientKeyRequest;
    type Output = Result<Secret, AppError>;

    /// The private key PEM `request`'s service presents, opened for the
    /// place that service of `tenant` keeps it.
    ///
    /// # Errors
    ///
    /// `AppError::Internal` when the key does not open there, or opens to
    /// something that is not text. The gateway then presents no
    /// certificate and refuses the routes to that service rather than
    /// calling it without one.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        request: OpenClientKeyRequest,
    ) -> Result<Secret, AppError> {
        let place = client_key_place(tenant, &request.service_id);
        opened_text(self.ports.encryptor.as_ref(), &request.sealed, &place)
            .await
            .or_internal()
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::authentication::FakeEncryptor;
    use crate::test_support::{block_on, test_ctx};

    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n";

    fn open(tenant: &ScopedTenant, request: OpenClientKeyRequest) -> Result<Secret, AppError> {
        block_on(OpenClientKeyUseCase::new(OpenClientKeyPorts::fakes()).execute(tenant, request))
    }

    /// The gateway loads Acme's projects service, which presents a client
    /// certificate. Its key opens to the PEM Ann gave.
    #[test]
    fn a_services_key_opens_for_that_service() {
        let tenant = test_ctx().tenant();
        let service_id = ServiceId::new();
        let sealed = FakeEncryptor::sealed_for(KEY, &client_key_place(&tenant, &service_id));

        let opened = open(&tenant, OpenClientKeyRequest { service_id, sealed }).unwrap();

        assert_eq!(opened.expose(), KEY);
    }

    /// Opening a client key under a different service identifier returns an
    /// internal error, even within the same tenant.
    #[test]
    fn a_key_copied_to_another_service_does_not_open() {
        let tenant = test_ctx().tenant();
        let payments = ServiceId::new();
        let sealed = FakeEncryptor::sealed_for(KEY, &client_key_place(&tenant, &payments));

        let opened = open(
            &tenant,
            OpenClientKeyRequest {
                service_id: ServiceId::new(),
                sealed,
            },
        );

        assert!(matches!(opened, Err(AppError::Internal(_))));
    }

    /// Opening a client key in another tenant returns an internal error,
    /// even when the service identifier matches.
    #[test]
    fn a_key_of_another_tenant_does_not_open() {
        let elsewhere = ScopedTenant::for_test(TenantId::new());
        let service_id = ServiceId::new();
        let sealed = FakeEncryptor::sealed_for(KEY, &client_key_place(&elsewhere, &service_id));

        let opened = open(
            &test_ctx().tenant(),
            OpenClientKeyRequest { service_id, sealed },
        );

        assert!(matches!(opened, Err(AppError::Internal(_))));
    }
}
