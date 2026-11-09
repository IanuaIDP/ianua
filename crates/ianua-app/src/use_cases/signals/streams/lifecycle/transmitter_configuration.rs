//! Transmitter configuration: what the tenant's Shared Signals transmitter
//! offers, behind `/.well-known/ssf-configuration`.
//!
//! Any receiver may read it to discover the transmitter, so it asks for no
//! caller, only the tenant the request's host resolved to. The API adds the
//! addresses of its own routes: the configuration, status, subject and
//! verification endpoints, and the JWKS.

use ianua_domain::domains::signals::signal::SecuritySignalType;
use ianua_domain::domains::signals::stream::DeliveryMethod;
use ianua_domain::types::Issuer;

use crate::error::AppError;
use crate::services::issuers::TenantIssuers;
use crate::tenancy::ScopedTenant;
use crate::use_case::Query;

/// Every signal type a stream may ask for.
const SUPPORTED_TYPES: [SecuritySignalType; 13] = [
    SecuritySignalType::SessionRevoked,
    SecuritySignalType::SessionSuspended,
    SecuritySignalType::CredentialChanged,
    SecuritySignalType::AccountLocked,
    SecuritySignalType::AccountDisabled,
    SecuritySignalType::PermissionsChanged,
    SecuritySignalType::DeviceCompromised,
    SecuritySignalType::TokenCompromised,
    SecuritySignalType::RiskLevelChanged,
    SecuritySignalType::AssuranceChanged,
    SecuritySignalType::CredentialCompromised,
    SecuritySignalType::IdentifierChanged,
    SecuritySignalType::AccountPurged,
];

/// What the tenant's transmitter offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransmitterConfiguration {
    /// The issuer its tokens carry, the `issuer` of the metadata.
    pub issuer: Issuer,
    /// How it delivers: push and poll.
    pub delivery_methods: Vec<DeliveryMethod>,
    /// The signal types a stream may ask for. Several share one event
    /// type URI, which the API lists once.
    pub signal_types: Vec<SecuritySignalType>,
}

/// The ports [`TransmitterConfigurationUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct TransmitterConfigurationPorts {
    /// The issuer the tenant's tokens carry.
    pub issuers: TenantIssuers,
}

/// Describes the tenant's Shared Signals transmitter.
pub struct TransmitterConfigurationUseCase {
    ports: TransmitterConfigurationPorts,
}

impl TransmitterConfigurationUseCase {
    /// A use case reading through `ports`.
    #[must_use]
    pub fn new(ports: TransmitterConfigurationPorts) -> Self {
        Self { ports }
    }
}

impl Query for TransmitterConfigurationUseCase {
    type Caller = ScopedTenant;
    type Input = ();
    type Output = Result<TransmitterConfiguration, AppError>;

    /// What the transmitter of `tenant` offers.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the tenant or its organization is gone.
    /// - `AppError::Internal` on storage failure.
    async fn execute(
        &self,
        tenant: &ScopedTenant,
        (): (),
    ) -> Result<TransmitterConfiguration, AppError> {
        let issuer = self.ports.issuers.of(tenant).await?;
        Ok(TransmitterConfiguration {
            issuer,
            delivery_methods: vec![DeliveryMethod::Push, DeliveryMethod::Poll],
            signal_types: SUPPORTED_TYPES.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ianua_domain::types::HttpsUrl;

    use super::*;
    use crate::test_support::organization::FakeOrganizationStore;
    use crate::test_support::tenant::FakeTenantStore;
    use crate::test_support::{Fake, block_on, test_ctx};

    /// A receiver reads Acme's transmitter configuration. It names the
    /// issuer Acme's tokens carry and offers push and poll.
    #[test]
    fn the_configuration_names_the_tenants_issuer() {
        let use_case = TransmitterConfigurationUseCase::new(TransmitterConfigurationPorts::fakes());

        let configuration = block_on(use_case.execute(&test_ctx().tenant(), ())).unwrap();

        assert_eq!(
            configuration.issuer.as_str(),
            "https://app.test/api/v1/organizations/acme/tenants/acme"
        );
        assert_eq!(
            configuration.delivery_methods,
            [DeliveryMethod::Push, DeliveryMethod::Poll]
        );
        assert_eq!(configuration.signal_types.len(), 13);
    }

    /// A host naming a tenant nobody registered has no transmitter. It is
    /// not found.
    #[test]
    fn an_unknown_tenant_is_not_found() {
        let use_case = TransmitterConfigurationUseCase::new(TransmitterConfigurationPorts {
            issuers: TenantIssuers::new(
                Arc::new(FakeTenantStore::empty()),
                Arc::new(FakeOrganizationStore::empty()),
                HttpsUrl::fake(),
            ),
        });

        let result = block_on(use_case.execute(&test_ctx().tenant(), ()));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
