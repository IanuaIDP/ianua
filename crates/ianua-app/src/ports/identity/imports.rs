//! Imports of accounts from another system: the records sent, and how far
//! the worker has got with them.

use async_trait::async_trait;
use ianua_domain::domains::identity::account::import::run::UserImport;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::UserImportId;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for keeping imports and their progress.
///
/// An import holds up to ten thousand records, password hashes included,
/// so the store keeps them where only the worker and the tenant's admins
/// read them, and never writes a record's hash anywhere else.
#[async_trait]
pub trait UserImportStore: Send + Sync + TenantScoped {
    /// Saves a new import, or the progress of one, whole: its state, its
    /// counts and the records it refused. Inside a unit of work it is kept
    /// or dropped with the accounts the chunk opened.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the import cannot be written.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        import: &UserImport<ResolvedTenant>,
    ) -> Result<(), DomainError>;

    /// The import with `id`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the import cannot be read, or its row is
    /// corrupt.
    async fn find_by_id(
        &self,
        tenant_id: &ScopedTenant,
        id: &UserImportId,
    ) -> Result<Option<UserImport<ResolvedTenant>>, DomainError>;
}
