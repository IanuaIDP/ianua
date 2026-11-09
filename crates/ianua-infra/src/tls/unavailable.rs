//! Explicit absence of automatic certificate issuance.

use async_trait::async_trait;
use ianua_app::ports::domain::TlsProvisioner;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, DomainName};

/// Leaves custom domains waiting for an operator upload when no authority is configured.
pub struct NoTlsProvisioner;

#[async_trait]
impl TlsProvisioner for NoTlsProvisioner {
    async fn provision(
        &self,
        _domain: &DomainName,
    ) -> Result<(CertificatePem, Secret), DomainError> {
        Err(DomainError::infra_msg(
            "automatic certificate issuance is off; upload a certificate or configure ACME_DIRECTORY_URL",
        ))
    }
}
