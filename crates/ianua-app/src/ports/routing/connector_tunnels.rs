//! What the gateway reads and notes of a tenant's connectors: the enrolled
//! ones it lets links in for, and when it last saw each link.

use async_trait::async_trait;
use ianua_domain::domains::routing::connector::tunnel::ConnectorTunnel;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ConnectorId;
use time::OffsetDateTime;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port reading the connectors a gateway may let a link in for.
///
/// It reads what a link is judged by and nothing more: never an enrollment
/// code's digest, and never a connector still awaiting its agent.
#[async_trait]
pub trait ConnectorTunnelStore: Send + Sync + TenantScoped {
    /// Every enrolled connector of the tenant, revoked ones included, so
    /// the gateway can close their links.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn enrolled(&self, tenant_id: &ScopedTenant)
    -> Result<Vec<ConnectorTunnel>, DomainError>;
}

/// Dyn-safe port noting when the gateway last saw a connector's link.
#[async_trait]
pub trait ConnectorSightings: Send + Sync + TenantScoped {
    /// Notes that a link of `connector` was open at `at`. A later sighting
    /// already noted is kept, and a connector not enrolled is left alone.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn record(
        &self,
        tenant_id: &ScopedTenant,
        connector: &ConnectorId,
        at: OffsetDateTime,
    ) -> Result<(), DomainError>;
}
