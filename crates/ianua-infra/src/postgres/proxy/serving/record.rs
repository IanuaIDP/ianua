//! What the gateway serves as its rows hold it: a tenant with its
//! organization's slug, and a domain that serves, read back through the
//! domain's rules.

use ianua_app::ports::proxy::HostedTenant;
use ianua_domain::domains::tenant::custom_domains::verification_status::TlsStatus;
use ianua_domain::domains::tenant::hosts::{PlatformLabel, ReadableAddress};
use ianua_domain::domains::tenant::status::TenantStatus;
use ianua_domain::shared::config::SlugLimits;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainId, DomainName, TenantId, TenantSlug};
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const TENANT: Stored = Stored("tenant");

const DOMAIN: Stored = Stored("registered domain");

/// A tenant as the gateway reads it. The store's checked queries fill it.
pub(super) struct HostedRecord {
    pub(super) id: Uuid,
    pub(super) slug: String,
    pub(super) status: String,
    pub(super) organization_slug: String,
    pub(super) platform_label: String,
    pub(super) readable_address: bool,
}

impl HostedRecord {
    /// Identifies the boundary whose custom domains the gateway must load.
    pub(super) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.id)
    }

    /// The tenant as the gateway serves it on `domains`, or `None` when it
    /// is closed to requests.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the status is unknown or
    /// a slug no longer passes its rules.
    pub(super) fn into_hosted(
        self,
        domains: Vec<DomainName>,
        limits: &SlugLimits,
    ) -> Result<Option<HostedTenant>, DomainError> {
        let status: TenantStatus = TENANT.choice(&self.status)?;
        if !status.is_open() {
            return Ok(None);
        }
        Ok(Some(HostedTenant {
            tenant_id: TenantId::from_uuid(self.id),
            platform_label: TENANT
                .value("platform label", PlatformLabel::new(self.platform_label))?,
            readable_address: if self.readable_address {
                ReadableAddress::On
            } else {
                ReadableAddress::Off
            },
            organization_slug: TENANT.value(
                "organization slug",
                TenantSlug::new(self.organization_slug, limits),
            )?,
            slug: TENANT.value("slug", TenantSlug::new(self.slug, limits))?,
            domains,
        }))
    }
}

/// A domain that serves, as the gateway reads it. The store's checked
/// queries fill it.
pub(super) struct ServingRecord {
    pub(super) tenant_id: Uuid,
    pub(super) id: Uuid,
    pub(super) domain: String,
    pub(super) tls_status: String,
}

/// Whether a serving domain is answered with a certificate of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Certified {
    /// Its certificate is active, and served for it.
    Yes,
    /// It needs none.
    No,
}

/// A domain that serves, whose tenant it is, and whether a certificate of
/// its own answers it.
#[derive(Debug, Clone)]
pub(super) struct ServingDomain {
    pub(super) tenant: TenantId,
    pub(super) id: DomainId,
    pub(super) name: DomainName,
    pub(super) certified: Certified,
}

impl ServingRecord {
    /// The tenant whose domain it is.
    pub(super) fn tenant(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }

    /// The domain the record holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the name no longer passes
    /// its rules, the certificate status is unknown, or the query let in a
    /// domain that does not serve.
    pub(super) fn into_serving(self) -> Result<ServingDomain, DomainError> {
        let status: TlsStatus = DOMAIN.choice(&self.tls_status)?;
        let certified = match status {
            TlsStatus::Active => Certified::Yes,
            TlsStatus::NotRequired => Certified::No,
            TlsStatus::Provisioning | TlsStatus::Expired | TlsStatus::NoCertificate => {
                return Err(DomainError::corrupt_row(
                    DOMAIN.0,
                    "a domain without its certificate read as serving",
                ));
            }
        };
        Ok(ServingDomain {
            tenant: TenantId::from_uuid(self.tenant_id),
            id: DomainId::from_uuid(self.id),
            name: DOMAIN.value("domain", DomainName::new(self.domain))?,
            certified,
        })
    }
}
