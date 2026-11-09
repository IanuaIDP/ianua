//! What the gateway serves across every tenant: the names it answers on,
//! and the certificates it answers them with.
//!
//! The gateway learns a request's tenant from the host it was sent to, and
//! picks the certificate from the name the client asked for, so both are
//! read for every tenant at once and held in memory. They are read only:
//! the gateway's database role reads these and changes none of them.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::certificate::CertificateBundle;
use ianua_domain::domains::tenant::hosts::{PlatformCertificate, PlatformLabel, ReadableAddress};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{CertificateId, CertificatePem, DomainName, TenantId, TenantSlug};

/// A tenant the gateway answers for, and every name it answers on.
///
/// Besides the names listed, the gateway answers a tenant on the
/// subdomains of its own base domain it builds from these: one from the
/// organization's and the tenant's slugs, and one from the tenant's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedTenant {
    /// The owner of these gateway hostnames.
    pub tenant_id: TenantId,
    /// The tenant's permanent random platform label.
    pub platform_label: PlatformLabel,
    /// Whether the readable platform name is enabled.
    pub readable_address: ReadableAddress,
    /// The slug of the organization the tenant belongs to.
    pub organization_slug: TenantSlug,
    /// The tenant's own slug.
    pub slug: TenantSlug,
    /// The tenant's own domains that serve: proved, and with an active
    /// certificate where one is needed. Its primary domain is among them.
    /// A wildcard is listed as such, `*.acme.com`.
    pub domains: Vec<DomainName>,
}

/// Dyn-safe port for the names every tenant is served on.
///
/// Not [`TenantScoped`](crate::ports::TenantScoped): the gateway resolves
/// a request's tenant from its host before it knows the tenant, so it holds
/// every tenant's names at once.
#[async_trait]
pub trait CrossTenantHosts: Send + Sync {
    /// Every tenant the gateway serves now: each one open to requests in
    /// its name (`TenantStatus::is_open`), with its serving domains. A
    /// tenant suspended, archived or deleted is left out, so its names stop
    /// resolving.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the tenants cannot be
    /// read, or the read does not answer within its timeout.
    async fn all(&self) -> Result<Vec<HostedTenant>, DomainError>;

    /// The tenant `tenant_id` as [`all`](Self::all) would list it, or
    /// `None` when it is not served now: gone, or closed to requests. Read
    /// when one tenant changes, so the gateway need not read them all.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the tenant cannot be read,
    /// or the read does not answer within its timeout.
    async fn find(&self, tenant_id: &TenantId) -> Result<Option<HostedTenant>, DomainError>;
}

/// The certificate a domain is served with, and whose domain it is.
///
/// Holds the certificate's private key, opened. Its `Debug` is the
/// bundle's, which never shows the key.
#[derive(Debug)]
pub struct ServedCertificate {
    /// The tenant the domain belongs to.
    pub tenant_id: TenantId,
    /// The name the certificate is served for, as the client asks for it.
    pub domain: DomainName,
    /// The certificate chain and its private key.
    pub bundle: ServedBundle,
}

/// Certificate material from a customer registration or a platform-owned pair.
#[derive(Debug)]
pub enum ServedBundle {
    /// A certificate attached to a proved customer domain.
    Custom(CertificateBundle),
    /// A root and wildcard share one pair without duplicating the private key.
    Platform(Arc<PlatformCertificate>),
}

impl ServedBundle {
    /// The identifier binding the private key at rest.
    #[must_use]
    pub fn id(&self) -> &CertificateId {
        match self {
            Self::Custom(cert) => cert.id(),
            Self::Platform(cert) => cert.id(),
        }
    }

    /// The certificate chain offered during the handshake.
    #[must_use]
    pub fn certificate_pem(&self) -> &CertificatePem {
        match self {
            Self::Custom(cert) => cert.certificate_pem(),
            Self::Platform(cert) => cert.certificate_pem(),
        }
    }

    /// The opened key, whose debug representation remains redacted.
    #[must_use]
    pub fn private_key_pem(&self) -> &Secret {
        match self {
            Self::Custom(cert) => cert.private_key_pem(),
            Self::Platform(cert) => cert.private_key_pem(),
        }
    }
}

impl From<CertificateBundle> for ServedBundle {
    /// Preserves the existing customer-domain certificate ownership.
    fn from(bundle: CertificateBundle) -> Self {
        Self::Custom(bundle)
    }
}

/// Dyn-safe port for the certificates every tenant's domains are served
/// with.
///
/// Not [`TenantScoped`](crate::ports::TenantScoped): the gateway picks a
/// certificate during the handshake, before any request names a tenant.
#[async_trait]
pub trait CrossTenantServedCertificates: Send + Sync {
    /// The current certificate of every domain that serves: proved, with
    /// an active certificate, the newest saved for it. Each private key
    /// comes back opened.
    ///
    /// The whole set, so the gateway can drop what is no longer in it: a
    /// removed domain is in no answer, and only comparing what it holds
    /// against the whole set stops it serving that domain's certificate.
    /// A certificate whose key does not open is left out and logged by the
    /// adapter, never served half-read.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the certificates cannot
    /// be read, or the read does not answer within its timeout.
    async fn current(&self) -> Result<Vec<ServedCertificate>, DomainError>;
}
