//! The address and name a tenant's mail goes out from, as the tenant's
//! branding and the domain its address is on stand now.
//!
//! The mailer and the test sends read the sender the same way, so a test
//! through the tenant's own provider goes out from the address its real
//! mail will: a provider that only sends from verified addresses passes the
//! test exactly when it will send the mail.

use std::sync::Arc;

use ianua_domain::domains::branding::config::{MailSender, TenantBranding};
use ianua_domain::domains::tenant::custom_domains::registered_domain::RegisteredDomain;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, Label};

use crate::ports::branding::BrandingStore;
use crate::ports::domain::RegisteredDomainStore;
use crate::tenancy::ScopedTenant;

/// A tenant's branding and the domain its sender address is on, read for
/// one mail.
pub(crate) struct SentAs {
    branding: Option<TenantBranding<ResolvedTenant>>,
    domain: Option<RegisteredDomain<ResolvedTenant>>,
}

impl SentAs {
    /// The address the mail goes out from: the tenant's own while its
    /// domain still allows it, the platform's otherwise.
    #[must_use]
    pub(crate) fn sender(&self) -> MailSender<'_> {
        match (&self.branding, &self.domain) {
            (Some(branding), Some(domain)) => branding.sender_on(domain),
            _ => MailSender::Platform,
        }
    }

    /// The name the mail goes out under, when the tenant set one.
    #[must_use]
    pub(crate) fn sender_name(&self) -> Option<&Label> {
        self.branding
            .as_ref()
            .and_then(TenantBranding::email_from_name)
    }
}

/// Reads what a tenant's mail is sent as.
pub(crate) struct TenantSenders {
    branding: Arc<dyn BrandingStore>,
    domains: Arc<dyn RegisteredDomainStore>,
}

impl TenantSenders {
    /// Senders read from `branding` and checked against `domains`.
    #[must_use]
    pub(crate) fn new(
        branding: Arc<dyn BrandingStore>,
        domains: Arc<dyn RegisteredDomainStore>,
    ) -> Self {
        Self { branding, domains }
    }

    /// What `tenant`'s mail is sent as now.
    ///
    /// # Errors
    ///
    /// Returns `DomainError` when the branding or the domain cannot be read.
    pub(crate) async fn of(&self, tenant: &ScopedTenant) -> Result<SentAs, DomainError> {
        let branding = self.branding.find(tenant).await?;
        let domain = self.sender_domain(tenant, branding.as_ref()).await?;
        Ok(SentAs { branding, domain })
    }

    /// The tenant's registration of the domain its sender address is on,
    /// when it set an address and still holds that domain.
    async fn sender_domain(
        &self,
        tenant: &ScopedTenant,
        branding: Option<&TenantBranding<ResolvedTenant>>,
    ) -> Result<Option<RegisteredDomain<ResolvedTenant>>, DomainError> {
        let Some(address) = branding.and_then(TenantBranding::email_from_address) else {
            return Ok(None);
        };
        let Ok(name) = DomainName::new(address.domain()) else {
            return Ok(None);
        };
        self.domains.find_by_tenant_and_name(tenant, &name).await
    }
}
