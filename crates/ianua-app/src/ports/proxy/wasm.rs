//! WASM stage module storage.

use async_trait::async_trait;
use ianua_domain::domains::proxy::stages::stage::ModuleRef;
use ianua_domain::shared::errors::DomainError;

use crate::ports::TenantScoped;
use crate::tenancy::ScopedTenant;

/// Dyn-safe port for storing and retrieving tenant-uploaded WASM stage
/// modules.
///
/// Content-addressed: `module_ref` is a `sha256:<hex>` digest the store
/// computes on `save`, not a caller-supplied identifier. A given ref's
/// bytes are therefore immutable, which is what lets the proxy's
/// compiled-module cache never need invalidation.
#[async_trait]
pub trait WasmModuleStore: Send + Sync + TenantScoped {
    /// Stores `bytecode`, returning its content-addressed ref
    /// (`sha256:<hex>`). Idempotent: re-uploading identical bytes
    /// returns the same ref without creating a duplicate row.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] if `bytecode` exceeds the
    /// platform's maximum module size, or [`DomainError::Infrastructure`]
    /// on a storage failure.
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        bytecode: &[u8],
    ) -> Result<ModuleRef, DomainError>;

    /// Loads a module's raw bytecode by its content-addressed ref.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] on a storage failure.
    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        module_ref: &ModuleRef,
    ) -> Result<Option<Vec<u8>>, DomainError>;
}
