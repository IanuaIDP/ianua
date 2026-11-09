//! What a caller is shown of a domain's certificate: never its key.

use ianua_domain::domains::tenant::custom_domains::certificate::{
    CertificateBundle, CertificateSource, Renewal,
};
use ianua_domain::types::{CertificateId, DomainId};
use time::OffsetDateTime;

/// A domain's certificate as a caller sees it: where it came from, who
/// renews it and when it runs out. The chain stays with the proxy and the
/// private key never leaves the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDetail {
    /// The certificate's id.
    pub id: CertificateId,
    /// The domain it serves.
    pub domain_id: DomainId,
    /// Issued through ACME, or uploaded with what it says about itself.
    pub source: CertificateSource,
    /// Who renews it before it runs out.
    pub renewal: Renewal,
    /// When it was issued, or starts being valid for an uploaded one.
    pub issued_at: OffsetDateTime,
    /// When it stops being valid.
    pub expires_at: OffsetDateTime,
    /// Whole days until it runs out, or 0 once it has.
    pub days_until_expiry: u32,
}

impl From<&CertificateBundle> for CertificateDetail {
    fn from(cert: &CertificateBundle) -> Self {
        Self {
            id: *cert.id(),
            domain_id: *cert.domain_id(),
            source: cert.source().clone(),
            renewal: cert.renewal(),
            issued_at: cert.issued_at(),
            expires_at: cert.expires_at(),
            days_until_expiry: cert.days_until_expiry(),
        }
    }
}
