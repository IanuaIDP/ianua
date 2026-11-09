//! Log shipping: the places a tenant's request records go, and sending them
//! there.

use async_trait::async_trait;
use ianua_domain::domains::proxy::log_shipping::{LogDestination, LogFormat, LogShippingTarget};
use ianua_domain::domains::proxy::observation::RequestObservation;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::LogShippingTargetId;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for the places a tenant ships its request records to.
#[async_trait]
pub trait LogShippingStore: Send + Sync + TenantScoped {
    /// Finds a target by id.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        target_id: &LogShippingTargetId,
    ) -> Result<Option<LogShippingTarget<ResolvedTenant>>, DomainError>;

    /// Every target in the tenant, by name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<LogShippingTarget<ResolvedTenant>>, DomainError>;

    /// Inserts or updates a target.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Conflict` when another target in the tenant has
    /// its name, `DomainError::Infrastructure` on persistence failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        target: &LogShippingTarget<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Removes a target.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` on persistence failure.
    async fn delete(
        &self,
        tenant_id: &ScopedTenant,
        target_id: &LogShippingTargetId,
    ) -> Result<(), DomainError>;
}

/// One batch of records for one target, with what the shipper signs in to
/// it with.
///
/// No `Debug`: it carries the target's credential, opened.
pub struct Shipment<'a> {
    /// Where the records go.
    pub destination: &'a LogDestination,
    /// The opened API key, token or access key, when the target has one.
    pub credential: Option<&'a Secret>,
    /// The shape each record is written in.
    pub format: LogFormat,
    /// The records, already narrowed to the ones the target takes.
    pub records: &'a [RequestObservation],
}

/// Dyn-safe port for sending a batch of request records to a tenant's log
/// destination.
///
/// The destination is the tenant's, on the public internet. The adapter
/// resolves its host again and refuses private, loopback and link-local
/// addresses before it connects, since a public name can point inward after
/// it was saved. It must give up after a bounded time, so a slow destination
/// holds no worker, and it never logs the credential or puts it in an error.
#[async_trait]
pub trait LogShipper: Send + Sync {
    /// Sends `shipment`'s records to its destination.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when the destination resolves to an
    ///   address shipping may not reach.
    /// - `DomainError::Infrastructure` when it cannot be reached, does not
    ///   answer in time, or refuses the batch.
    async fn ship(&self, shipment: Shipment<'_>) -> Result<(), DomainError>;
}
