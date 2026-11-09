//! Certificates signed by themselves: for development, where no authority
//! can reach the machine and the TLS path must still work end to end, and
//! for the hop behind a load balancer that holds the real certificates.
//! Browsers do not trust them, so production wires this only when
//! `TLS_TERMINATED_UPSTREAM` says TLS ends in front of the gateway.

use async_trait::async_trait;
use ianua_app::ports::domain::TlsProvisioner;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificatePem, DomainName};

/// Makes an untrusted certificate for any name, signed by its own key.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelfSignedTlsProvisioner;

#[async_trait]
impl TlsProvisioner for SelfSignedTlsProvisioner {
    async fn provision(
        &self,
        domain: &DomainName,
    ) -> Result<(CertificatePem, Secret), DomainError> {
        let key = rcgen::KeyPair::generate().map_err(DomainError::infra)?;
        let mut params = rcgen::CertificateParams::new(vec![domain.as_str().to_owned()])
            .map_err(DomainError::infra)?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain.as_str());
        let certificate = params.self_signed(&key).map_err(DomainError::infra)?;
        let chain = CertificatePem::new(certificate.pem()).map_err(DomainError::infra)?;
        Ok((chain, Secret::new(key.serialize_pem())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name gets a certificate and the key it was signed with.
    #[tokio::test]
    async fn a_name_gets_a_certificate_and_its_key() {
        let domain = DomainName::new("auth.acme.test").unwrap();

        let (chain, key) = SelfSignedTlsProvisioner.provision(&domain).await.unwrap();

        assert!(chain.as_str().contains("BEGIN CERTIFICATE"));
        assert!(key.expose().contains("PRIVATE KEY"));
    }
}
