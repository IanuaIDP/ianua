//! Private-network connectors, and the one-time codes they enroll with.

use async_trait::async_trait;
use ianua_domain::domains::routing::connector::PrivateConnector;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{ConnectorId, TokenHash};

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port keeping a tenant's private-network connectors.
#[async_trait]
pub trait ConnectorStore: Send + Sync + TenantScoped {
    /// One connector.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or the row does not load.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &ConnectorId,
    ) -> Result<Option<PrivateConnector<ResolvedTenant>>, DomainError>;

    /// The connector still awaiting enrollment whose code hashes to
    /// `code_hash`, if any. An enrolled connector's spent code matches
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or the row does not load.
    async fn find_awaiting_by_code(
        &self,
        tenant_id: &ScopedTenant,
        code_hash: &TokenHash,
    ) -> Result<Option<PrivateConnector<ResolvedTenant>>, DomainError>;

    /// Every connector of the tenant, by name.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read
    /// or a row does not load.
    async fn list(
        &self,
        tenant_id: &ScopedTenant,
    ) -> Result<Vec<PrivateConnector<ResolvedTenant>>, DomainError>;

    /// Saves a new or changed connector.
    ///
    /// # Errors
    ///
    /// - `DomainError::Conflict` when another connector of the tenant has
    ///   the name.
    /// - `DomainError::Infrastructure` when the store cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        connector: &PrivateConnector<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// Deletes the connector `id`, the one [`PrivateConnector::delete`]
    /// allowed.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be
    /// written.
    async fn delete(&self, tenant_id: &ScopedTenant, id: &ConnectorId) -> Result<(), DomainError>;
}

/// Dyn-safe port making and hashing the one-time codes connectors enroll
/// with.
///
/// The hash is keyed, an HMAC under a key the server holds and the database
/// does not, and the same for the same code every time, so a presented code
/// is found by hashing it again and a copied table cannot be searched
/// offline.
#[async_trait]
pub trait ConnectorCodeGenerator: Send + Sync {
    /// A new random enrollment code and its hash. The code is shown once,
    /// to the admin who created the connector, and never kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the randomness source
    /// fails.
    async fn generate(&self) -> Result<(Secret, TokenHash), DomainError>;

    /// The hash of a code a connector presented, under the same key
    /// [`generate`](Self::generate) hashed with.
    fn hash_presented(&self, presented: &Secret) -> TokenHash;
}
