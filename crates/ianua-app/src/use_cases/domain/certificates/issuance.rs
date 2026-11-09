//! Obtaining a certificate for a registered domain, which first issuance and
//! renewal both do.

use ianua_domain::domains::tenant::custom_domains::certificate::{
    CertificateBundle, IssuedCertificate,
};
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::clock;
use time::Duration;

use crate::error::{AppError, OrInternal};
use crate::use_cases::domain::certificates::TlsProvisioners;

/// How long a certificate an authority issues stays valid.
const VALIDITY_DAYS: i64 = 90;

/// A fresh certificate for `domain`, proved the way its connection allows.
///
/// The private key travels as a secret. The certificate store seals it
/// before it reaches storage.
///
/// # Errors
///
/// - `AppError::Internal` if the authority refuses, or the issued dates are
///   inconsistent.
pub(super) async fn issued_certificate(
    provisioners: &TlsProvisioners,
    domain: &RegisteredDomain<ResolvedTenant>,
) -> Result<CertificateBundle, AppError> {
    let (certificate_pem, private_key_pem) = provisioners
        .for_connection(domain.connection())
        .provision(domain.domain())
        .await
        .or_internal()?;
    let issued_at = clock::now();
    CertificateBundle::new(IssuedCertificate {
        domain_id: *domain.id(),
        certificate_pem,
        private_key_pem,
        issued_at,
        expires_at: issued_at + Duration::days(VALIDITY_DAYS),
    })
    .ok_or_else(|| AppError::internal_msg("the certificate expires before it was issued"))
}
