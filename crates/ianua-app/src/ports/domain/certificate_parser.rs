//! Reading a certificate a tenant uploads.

use ianua_domain::domains::tenant::custom_domains::uploaded_certificate::ParsedCertificate;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::CertificatePem;

/// Dyn-safe port that reads an uploaded certificate chain.
///
/// The domain never parses a certificate. The adapter reads the chain's
/// leaf, checks that `private_key_pem` is the key the leaf was issued for,
/// and hands back what the leaf says about itself. Whether that may serve a
/// domain is the domain's decision, not the adapter's.
///
/// The key is only read to check the pair. The adapter keeps no copy, never
/// logs it and never puts it in an error.
///
/// Parsing is local work with no outbound call, so it is synchronous.
pub trait CertificateParser: Send + Sync {
    /// What the leaf of `chain` says about itself, once `private_key_pem`
    /// is its key.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when the chain or the key cannot be
    ///   read, the chain holds no certificate, or the key is not the leaf's.
    fn parse(
        &self,
        chain: &CertificatePem,
        private_key_pem: &Secret,
    ) -> Result<ParsedCertificate, DomainError>;
}
