//! Resolve host ownership from current tenant state for route writes.

use std::sync::Arc;

use ianua_domain::domains::tenant::hosts::{PlatformAddressing, PlatformHostParts, PlatformHosts};
use ianua_domain::types::DomainName;

use crate::error::AppError;
use crate::ports::organization::OrganizationStore;
use crate::ports::tenant::TenantStore;
use crate::services::lookup::{existing_organization, existing_tenant};
use crate::tenancy::ScopedTenant;

/// The platform's namespace and how the gateway serves its tenant labels.
#[derive(Clone)]
pub struct PlatformAddressSettings {
    /// The reserved apps domain.
    pub base: DomainName,
    /// The configured certificate-compatible address shape.
    pub shape: PlatformAddressing,
}

/// Current tenant and organization facts behind platform host ownership.
pub struct PlatformAddresses {
    tenants: Arc<dyn TenantStore>,
    organizations: Arc<dyn OrganizationStore>,
    settings: PlatformAddressSettings,
}

impl PlatformAddresses {
    /// Reads current ownership through the ordinary stores; no caller-supplied label is trusted.
    #[must_use]
    pub fn new(
        tenants: Arc<dyn TenantStore>,
        organizations: Arc<dyn OrganizationStore>,
        settings: PlatformAddressSettings,
    ) -> Self {
        Self {
            tenants,
            organizations,
            settings,
        }
    }

    /// The roots the tenant currently serves, including its explicit readable consent.
    ///
    /// # Errors
    ///
    /// Returns not found for missing tenant or organization, and internal on store failure.
    pub(crate) async fn owned(
        &self,
        tenant: &ScopedTenant,
    ) -> Result<OwnedPlatformAddresses, AppError> {
        let tenant = existing_tenant(self.tenants.as_ref(), tenant).await?;
        let organization =
            existing_organization(self.organizations.as_ref(), tenant.organization_id()).await?;
        let shape = if tenant.status().is_open() {
            self.settings.shape
        } else {
            PlatformAddressing::Disabled
        };
        let hosts = PlatformHosts::under(
            &self.settings.base,
            PlatformHostParts {
                label: tenant.platform_label(),
                organization_slug: organization.slug(),
                tenant_slug: tenant.slug(),
                readable: tenant.readable_address(),
            },
            shape,
        );
        Ok(OwnedPlatformAddresses {
            settings: self.settings.clone(),
            hosts,
        })
    }
}

/// A tenant's current platform names within the reserved namespace.
pub(crate) struct OwnedPlatformAddresses {
    settings: PlatformAddressSettings,
    hosts: PlatformHosts,
}

impl OwnedPlatformAddresses {
    /// Answers only for platform names; custom names remain the registration store's concern.
    #[must_use]
    pub(crate) fn owns(&self, host: &DomainName) -> Option<bool> {
        let base = self.settings.base.as_str();
        if host.as_str() != base && !host.as_str().ends_with(&format!(".{base}")) {
            return None;
        }
        Some(self.hosts.serves(host, self.settings.shape))
    }
}
