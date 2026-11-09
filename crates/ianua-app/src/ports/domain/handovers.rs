//! Domains one tenant offered to another, waiting to be accepted.

use async_trait::async_trait;
use ianua_domain::domains::tenant::custom_domains::handover_offer::HandoverOffer;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, TenantId};

/// Dyn-safe port for the offers that hand a domain between two tenants of
/// one organization.
///
/// Not [`TenantScoped`](crate::ports::TenantScoped): an offer belongs to
/// both tenants. The giving tenant writes it, and the receiving tenant reads
/// and spends it. An offer is known by its giving tenant and its domain, so
/// a domain is offered to one tenant at a time.
#[async_trait]
pub trait HandoverOfferStore: Send + Sync {
    /// Saves `offer`, replacing the giving tenant's earlier offer of the same
    /// domain. An accepted offer is kept, spent, so it is never accepted
    /// twice.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn save(&self, offer: &HandoverOffer) -> Result<(), DomainError>;

    /// The offer of `domain` by the tenant `from`, if it made one.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on lookup failure, or when the
    /// stored offer breaks a rule it keeps.
    async fn find(
        &self,
        from: &TenantId,
        domain: &DomainName,
    ) -> Result<Option<HandoverOffer>, DomainError>;
}
