//! An LDAP client certificate as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::authentication::ldap_certificate::{
    LdapClientCertificate, LdapClientCertificateRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CertificateFingerprint, Label, LdapCertificateId, Revocation, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const CERTIFICATE: Stored = Stored("LDAP client certificate");

/// A certificate as it is read. The store's checked queries fill it.
pub(super) struct CertificateRecord {
    pub(super) id: Uuid,
    pub(super) user_id: Uuid,
    pub(super) fingerprint: String,
    pub(super) device_label: String,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) revoked_at: Option<OffsetDateTime>,
}

impl CertificateRecord {
    /// The certificate the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules or the row breaks a rule the certificate keeps.
    pub(super) fn into_certificate(
        self,
    ) -> Result<LdapClientCertificate<ResolvedTenant>, DomainError> {
        LdapClientCertificate::reconstitute(LdapClientCertificateRow {
            id: LdapCertificateId::from_uuid(self.id),
            user_id: UserId::from_uuid(self.user_id),
            fingerprint: CERTIFICATE.value(
                "fingerprint",
                CertificateFingerprint::parse(&self.fingerprint),
            )?,
            device_label: CERTIFICATE.value(
                "device label",
                Label::new("device_label", self.device_label),
            )?,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revocation: Revocation::from_stored(self.revoked_at),
        })
    }
}

/// A certificate's columns, as they are written.
pub(super) struct CertificateColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) user_id: &'a Uuid,
    pub(super) fingerprint: String,
    pub(super) device_label: &'a str,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: OffsetDateTime,
    pub(super) revoked_at: Option<OffsetDateTime>,
}

impl<'a> CertificateColumns<'a> {
    /// The columns `certificate` is written to.
    pub(super) fn of(certificate: &'a LdapClientCertificate<ResolvedTenant>) -> Self {
        Self {
            id: certificate.id().as_uuid(),
            user_id: certificate.user_id().as_uuid(),
            fingerprint: certificate.fingerprint().to_string(),
            device_label: certificate.device_label().as_str(),
            issued_at: certificate.issued_at(),
            expires_at: certificate.expires_at(),
            revoked_at: certificate.revoked_at(),
        }
    }
}
