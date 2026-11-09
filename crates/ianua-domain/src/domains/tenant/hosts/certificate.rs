//! A certificate covering one tenant address and its direct children.

use time::OffsetDateTime;

use crate::domains::tenant::custom_domains::uploaded_certificate::ParsedCertificate;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::shared::security::secret::Secret;
use crate::types::{CertificateId, CertificatePem, DomainName, TenantId};

/// A platform certificate's stored fields. Private keys stay redacted and
/// adapters seal them at rest, bound to this certificate's identifier.
pub struct PlatformCertificateRow {
    /// The certificate identifier used to bind its sealed key.
    pub id: CertificateId,
    /// The tenant holding this address.
    pub tenant_id: TenantId,
    /// The tenant address covered along with its one-label wildcard.
    pub root: DomainName,
    /// The authority's certificate chain.
    pub certificate_pem: CertificatePem,
    /// The opened private key.
    pub private_key_pem: Secret,
    /// The certificate's actual beginning of validity.
    pub issued_at: OffsetDateTime,
    /// The certificate's actual end of validity.
    pub expires_at: OffsetDateTime,
}

/// A certificate for one platform address and its wildcard. It is separate
/// from customer domain registrations and cannot be transferred between them.
#[derive(Debug)]
pub struct PlatformCertificate {
    id: CertificateId,
    tenant_id: TenantId,
    root: DomainName,
    certificate_pem: CertificatePem,
    private_key_pem: Secret,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl PlatformCertificate {
    /// Accepts an authority's certificate only when its parsed names cover
    /// the root and wildcard exactly and its validity includes now. The
    /// parser has already checked the key belongs to the certificate.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` for wrong names, dates or a
    /// malformed stored shape.
    pub fn issued(
        mut row: PlatformCertificateRow,
        parsed: &ParsedCertificate,
    ) -> Result<Self, DomainError> {
        let wildcard =
            DomainName::new(format!("*.{}", row.root.as_str())).map_err(DomainError::infra)?;
        let now = crate::shared::clock::now();
        if parsed.subject_names.len() != 2
            || !parsed.subject_names.contains(&row.root)
            || !parsed.subject_names.contains(&wildcard)
            || parsed.not_before > now
            || parsed.not_after <= now
        {
            return Err(DomainError::infra_msg(
                "the issued platform certificate does not cover its names and current time",
            ));
        }
        row.issued_at = parsed.not_before;
        row.expires_at = parsed.not_after;
        Self::reconstitute(row)
    }

    /// Reads a certificate after checking its address and validity interval.
    /// The issuing adapter also checks that its SANs cover the requested pair
    /// and that the private key matches before storing it.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` for a wildcard root, an address
    /// too long for its wildcard or an empty validity interval.
    pub fn reconstitute(row: PlatformCertificateRow) -> Result<Self, DomainError> {
        RowCheck::of("platform certificate")
            .holds(!row.root.is_wildcard(), "a wildcard root")
            .holds(
                DomainName::new(format!("*.{}", row.root.as_str())).is_ok(),
                "an overlong wildcard",
            )
            .holds(row.issued_at < row.expires_at, "an empty validity interval")
            .finish()?;
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            root: row.root,
            certificate_pem: row.certificate_pem,
            private_key_pem: row.private_key_pem,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
        })
    }

    /// The certificate identifier, independent of its tenant's identifier.
    #[must_use]
    pub fn id(&self) -> &CertificateId {
        &self.id
    }

    /// The tenant whose address the certificate serves.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The address covered together with its direct children.
    #[must_use]
    pub fn root(&self) -> &DomainName {
        &self.root
    }

    /// The public certificate chain.
    #[must_use]
    pub fn certificate_pem(&self) -> &CertificatePem {
        &self.certificate_pem
    }

    /// The opened, redacted private key.
    #[must_use]
    pub fn private_key_pem(&self) -> &Secret {
        &self.private_key_pem
    }

    /// The actual beginning of certificate validity.
    #[must_use]
    pub fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    /// The actual end of certificate validity.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::clock;
    use crate::shared::model::row_check::refused_as_corrupt;

    /// A certificate row with a redacted test key and a nonempty interval.
    fn row() -> PlatformCertificateRow {
        PlatformCertificateRow {
            id: CertificateId::new(),
            tenant_id: TenantId::new(),
            root: DomainName::new("k7f3q9.apps.example.com").unwrap(),
            certificate_pem: CertificatePem::new(
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            )
            .unwrap(),
            private_key_pem: Secret::new("private test material"),
            issued_at: clock::now(),
            expires_at: clock::now() + time::Duration::days(90),
        }
    }

    /// Stored certificates with a wildcard root or an empty validity
    /// interval are rejected as corrupt.
    #[test]
    fn corrupt_certificate_rows_are_refused() {
        let mut wildcard = row();
        wildcard.root = DomainName::new("*.example.com").unwrap();
        assert!(refused_as_corrupt(&PlatformCertificate::reconstitute(
            wildcard
        )));
        let mut expired = row();
        expired.expires_at = expired.issued_at;
        assert!(refused_as_corrupt(&PlatformCertificate::reconstitute(
            expired
        )));
    }

    /// A loaded certificate preserves its ownership and never prints its key.
    #[test]
    fn a_certificate_preserves_ownership_and_redacts_its_key() {
        let row = row();
        let owner = row.tenant_id;
        let certificate = PlatformCertificate::reconstitute(row).unwrap();
        assert_eq!(certificate.tenant_id(), &owner);
        assert!(!format!("{certificate:?}").contains("private test material"));
    }
}
