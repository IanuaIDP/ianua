//! A certificate as its row holds it: read back into the bundle, its key
//! opened by the store, and written out from it, its key sealed.

use ianua_domain::domains::tenant::custom_domains::certificate::{
    CertificateBundle, CertificateBundleRow, CertificateSource,
};
use ianua_domain::domains::tenant::custom_domains::uploaded_certificate::{
    CertificateIssuer, UploadedDetails,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    CertificateId, CertificatePem, DomainId, DomainName, SealedSecret, TenantId,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const CERTIFICATE: Stored = Stored("certificate");

/// The word a certificate the platform issued is stored with.
const ISSUED: &str = "acme";

/// The word a certificate its tenant uploaded is stored with.
const UPLOADED: &str = "uploaded";

/// A certificate as it is read, with its tenant, its key still sealed. The
/// store's checked queries fill it, and so do the gateway's, which serve
/// every tenant's certificates.
pub(crate) struct CertificateRecord {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) domain_id: Uuid,
    pub(crate) certificate_pem: String,
    pub(crate) private_key: String,
    pub(crate) issued_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) source: String,
    pub(crate) issuer: Option<String>,
    pub(crate) subject_names: Option<Vec<String>>,
}

impl CertificateRecord {
    /// The tenant whose domain the certificate serves.
    pub(crate) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }

    /// The private key as it is stored, sealed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the stored value is not a
    /// sealed secret.
    pub(crate) fn sealed_key(&self) -> Result<SealedSecret, DomainError> {
        CERTIFICATE.value("private key", SealedSecret::new(self.private_key.as_str()))
    }

    /// The bundle the record holds, with `private_key` opened from it,
    /// rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, the source is unknown, or the row breaks a rule the
    /// bundle keeps.
    pub(crate) fn into_bundle(self, private_key: Secret) -> Result<CertificateBundle, DomainError> {
        let source = source_from(
            &self.source,
            self.issuer,
            self.subject_names,
            self.expires_at,
        )?;
        CertificateBundle::reconstitute(CertificateBundleRow {
            id: CertificateId::from_uuid(self.id),
            domain_id: DomainId::from_uuid(self.domain_id),
            certificate_pem: CERTIFICATE
                .value("chain", CertificatePem::new(self.certificate_pem))?,
            private_key_pem: private_key,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            source,
        })
    }
}

/// Where a stored certificate came from, from its columns.
fn source_from(
    source: &str,
    issuer: Option<String>,
    subject_names: Option<Vec<String>>,
    expires_at: OffsetDateTime,
) -> Result<CertificateSource, DomainError> {
    match (source, issuer, subject_names) {
        (ISSUED, None, None) => Ok(CertificateSource::Acme),
        (UPLOADED, Some(issuer), Some(names)) => {
            uploaded(issuer, names, expires_at).map(CertificateSource::Uploaded)
        }
        _ => Err(DomainError::corrupt_row(
            CERTIFICATE.0,
            "a source whose details do not fit it",
        )),
    }
}

/// What a stored upload says about itself.
fn uploaded(
    issuer: String,
    names: Vec<String>,
    not_after: OffsetDateTime,
) -> Result<UploadedDetails, DomainError> {
    let names = names
        .into_iter()
        .map(|name| CERTIFICATE.value("subject name", DomainName::new(name)))
        .collect::<Result<Vec<_>, _>>()?;
    let issuer = CERTIFICATE.value("issuer", CertificateIssuer::new(issuer))?;
    UploadedDetails::stored(issuer, names, not_after)
}

/// A certificate's columns, as they are written, its key already sealed.
pub(super) struct CertificateColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) domain_id: &'a Uuid,
    pub(super) certificate_pem: &'a str,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) source: &'static str,
    pub(super) issuer: Option<&'a str>,
    pub(super) subject_names: Option<Vec<String>>,
}

impl<'a> CertificateColumns<'a> {
    /// The columns `bundle` is written to, but its key.
    pub(super) fn of(bundle: &'a CertificateBundle) -> Self {
        let uploaded = match bundle.source() {
            CertificateSource::Acme => None,
            CertificateSource::Uploaded(details) => Some(details),
        };
        Self {
            id: bundle.id().as_uuid(),
            domain_id: bundle.domain_id().as_uuid(),
            certificate_pem: bundle.certificate_pem().as_str(),
            issued_at: bundle.issued_at(),
            expires_at: bundle.expires_at(),
            source: uploaded.map_or(ISSUED, |_| UPLOADED),
            issuer: uploaded.map(|details| details.issuer().as_str()),
            subject_names: uploaded.map(|details| {
                details
                    .subject_names()
                    .iter()
                    .map(|name| name.as_str().to_owned())
                    .collect()
            }),
        }
    }
}
