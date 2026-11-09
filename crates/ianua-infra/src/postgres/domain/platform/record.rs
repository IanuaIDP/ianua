//! Checked reconstruction of certificate orders and issued platform pairs.

use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::domain::{
    PlatformCertificateOrder, PlatformCertificateTarget, certificate_key_place,
};
use ianua_domain::domains::tenant::hosts::{
    PlatformCertificate, PlatformCertificateRow, ReadableAddress,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateId, CertificatePem, DomainName, SealedSecret, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const PLATFORM: Stored = Stored("platform certificate");

/// Parallel columns for reconciling desired certificate roots in one write.
pub(super) struct TargetColumns<'a> {
    pub(super) roots: Vec<&'a str>,
    pub(super) tenants: Vec<Uuid>,
    pub(super) readable: Vec<bool>,
}

impl<'a> TargetColumns<'a> {
    /// Keeps each root aligned with its owning tenant and consent requirement.
    pub(super) fn of(targets: &'a [PlatformCertificateTarget]) -> Self {
        Self {
            roots: targets.iter().map(|target| target.root.as_str()).collect(),
            tenants: targets
                .iter()
                .map(|target| *target.tenant_id.as_uuid())
                .collect(),
            readable: targets
                .iter()
                .map(|target| target.readable == ReadableAddress::On)
                .collect(),
        }
    }
}

/// One claimed address, still in database representation.
pub(super) struct OrderRecord {
    pub(super) root: String,
    pub(super) tenant_id: Uuid,
    pub(super) readable: bool,
}

impl OrderRecord {
    /// Validates the address and binds it to this attempt's lease.
    pub(super) fn into_order(
        self,
        id: CertificateId,
    ) -> Result<PlatformCertificateOrder, DomainError> {
        Ok(PlatformCertificateOrder {
            id,
            target: PlatformCertificateTarget {
                root: PLATFORM.value("root", DomainName::new(self.root))?,
                tenant_id: TenantId::from_uuid(self.tenant_id),
                readable: if self.readable {
                    ReadableAddress::On
                } else {
                    ReadableAddress::Off
                },
            },
        })
    }
}

/// A current platform pair, whose private key remains sealed until read.
pub(crate) struct CertificateRecord {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) root: String,
    pub(crate) certificate_pem: String,
    pub(crate) private_key: String,
    pub(crate) issued_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
}

impl CertificateRecord {
    /// Opens the key only at the certificate it was sealed for and checks stored invariants.
    pub(crate) async fn opened(
        self,
        encryptor: &dyn SecretEncryptor,
    ) -> Result<PlatformCertificate, DomainError> {
        let id = CertificateId::from_uuid(self.id);
        let sealed = PLATFORM.value("private key", SealedSecret::new(self.private_key))?;
        let plain = encryptor
            .decrypt(&sealed, &certificate_key_place(&id))
            .await?;
        let key = String::from_utf8(plain)
            .map_err(|_| DomainError::corrupt_row(PLATFORM.0, "a private key that is not text"))?;
        PlatformCertificate::reconstitute(PlatformCertificateRow {
            id,
            tenant_id: TenantId::from_uuid(self.tenant_id),
            root: PLATFORM.value("root", DomainName::new(self.root))?,
            certificate_pem: PLATFORM.value("chain", CertificatePem::new(self.certificate_pem))?,
            private_key_pem: Secret::new(key),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        })
    }
}
