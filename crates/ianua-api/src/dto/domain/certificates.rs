//! Domain certificate bodies: a certificate the tenant uploads, and what a
//! caller is shown of the one a domain serves. The private key goes in
//! once and never comes back.

use ianua_app::use_cases::domain::certificates::UploadRequest;
use ianua_app::use_cases::domain::certificates::detail::CertificateDetail;
use ianua_domain::domains::tenant::custom_domains::certificate::{CertificateSource, Renewal};
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateId, CertificatePem, DomainId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::ApiError;

/// A certificate the tenant brings for one of its verified domains.
///
/// No `Debug`: it carries the private key.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UploadCertificateBody {
    /// The certificate chain, leaf first, PEM-encoded.
    pub certificate_pem: String,
    /// The leaf's private key, PEM-encoded. Sealed when stored, and never
    /// answered or recorded.
    pub private_key_pem: String,
}

impl UploadCertificateBody {
    /// The upload of this certificate for `domain_id`.
    ///
    /// # Errors
    ///
    /// `ApiError` (422) when the chain is not PEM.
    pub(crate) fn upload_for(self, domain_id: DomainId) -> Result<UploadRequest, ApiError> {
        Ok(UploadRequest {
            domain_id,
            certificate_pem: CertificatePem::new(self.certificate_pem)
                .map_err(ApiError::validation)?,
            private_key_pem: Secret::new(self.private_key_pem),
        })
    }
}

/// The certificate a domain serves: where it came from, who renews it and
/// when it runs out. Never its key.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CertificateResponse {
    /// The certificate's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: CertificateId,
    /// The domain it serves.
    #[schema(value_type = String, format = Uuid)]
    pub domain_id: DomainId,
    /// `Acme` (issued for the platform) or `Uploaded` (brought by the
    /// tenant).
    pub source: &'static str,
    /// Who renews it before it runs out: `ByPlatform` or `ByTenant`.
    pub renewal: &'static str,
    /// Who issued an uploaded certificate, as its issuer field reads.
    /// Absent for one issued through ACME.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Every name an uploaded certificate is for. Empty for one issued
    /// through ACME, which names only the domain.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subject_names: Vec<String>,
    /// When it was issued, or starts being valid for an uploaded one.
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    /// When it stops being valid.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// Whole days until it runs out, or 0 once it has.
    pub days_until_expiry: u32,
}

impl From<CertificateDetail> for CertificateResponse {
    fn from(detail: CertificateDetail) -> Self {
        let (issuer, subject_names) = uploaded(&detail.source);
        Self {
            id: detail.id,
            domain_id: detail.domain_id,
            source: source_name(&detail.source),
            renewal: renewal_name(detail.renewal),
            issuer,
            subject_names,
            issued_at: detail.issued_at,
            expires_at: detail.expires_at,
            days_until_expiry: detail.days_until_expiry,
        }
    }
}

/// The issuer and names an uploaded certificate says it has; nothing for
/// one issued through ACME.
fn uploaded(source: &CertificateSource) -> (Option<String>, Vec<String>) {
    let CertificateSource::Uploaded(details) = source else {
        return (None, Vec::new());
    };
    let names = details
        .subject_names()
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect();
    (Some(details.issuer().as_str().to_owned()), names)
}

/// Where a certificate came from, by the name the dashboard reads.
fn source_name(source: &CertificateSource) -> &'static str {
    match source {
        CertificateSource::Acme => "Acme",
        CertificateSource::Uploaded(_) => "Uploaded",
    }
}

/// Who renews a certificate, by the name the dashboard reads.
fn renewal_name(renewal: Renewal) -> &'static str {
    match renewal {
        Renewal::ByPlatform => "ByPlatform",
        Renewal::ByTenant => "ByTenant",
    }
}
