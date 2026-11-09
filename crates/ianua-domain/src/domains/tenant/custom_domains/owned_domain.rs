//! A domain a tenant proved it owns, ready to stand as its primary domain
//! or to be bound to an identity provider connection.

use crate::types::{DomainName, TenantId};

/// Proof that one tenant holds a domain whose DNS proof stands right now.
///
/// Only [`RegisteredDomain::owned_by`] makes one, from a verified
/// registration read through the tenant's own store. Two things need it.
/// The data plane sends a tenant's primary domain to it, and an identity
/// provider connection vouches for addresses at the domains bound to it. A
/// name the tenant only typed in must never stand in either place.
///
/// [`RegisteredDomain::owned_by`]: crate::domains::tenant::custom_domains::registered_domain::RegisteredDomain::owned_by
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedDomain {
    tenant: TenantId,
    domain: DomainName,
}

impl OwnedDomain {
    /// The proof that `tenant` holds `domain`, once the registration has
    /// checked it.
    pub(crate) fn new(tenant: TenantId, domain: DomainName) -> Self {
        Self { tenant, domain }
    }

    /// The tenant that proved it.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The domain it proved.
    #[must_use]
    pub fn domain(&self) -> &DomainName {
        &self.domain
    }

    /// The domain, giving up the proof.
    #[must_use]
    pub fn into_domain(self) -> DomainName {
        self.domain
    }
}
