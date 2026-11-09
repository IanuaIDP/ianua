//! The WASM modules a tenant uploads for its stages, kept as tenant rows
//! and found by the SHA-256 of their bytes.
//!
//! The store makes the reference itself, `sha256:<hex>`, so a reference's
//! bytes can never change and uploading the same bytes again keeps the one
//! row there is.

mod record;

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::proxy::WasmModuleStore;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::proxy::stages::stage::ModuleRef;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use sha2::{Digest as _, Sha256};

use self::record::ModuleRecord;
use crate::postgres::foundation::pool::Databases;
use crate::postgres::foundation::security::RowScope;
use crate::postgres::foundation::unit::scoped;

/// The Postgres store of WASM stage modules.
pub struct PgWasmModuleStore {
    databases: Arc<Databases>,
    max_bytes: usize,
}

impl PgWasmModuleStore {
    /// A store keeping modules of at most `max_bytes` in `databases`.
    #[must_use]
    pub fn new(databases: Arc<Databases>, max_bytes: usize) -> Self {
        Self {
            databases,
            max_bytes,
        }
    }
}

/// The reference of the module `bytecode` is: the SHA-256 of its bytes.
fn reference_of(bytecode: &[u8]) -> Result<ModuleRef, DomainError> {
    let digest: String = Sha256::digest(bytecode)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(ModuleRef::new(format!("sha256:{digest}"))?)
}

impl TenantScoped for PgWasmModuleStore {}

#[async_trait]
impl WasmModuleStore for PgWasmModuleStore {
    async fn save(
        &self,
        tenant_id: &ScopedTenant,
        bytecode: &[u8],
    ) -> Result<ModuleRef, DomainError> {
        if bytecode.len() > self.max_bytes {
            return Err(DomainError::invalid(message!(
                "infra-a-module-may-be-at-most",
                format!("a module may be at most {} bytes", self.max_bytes)
            )));
        }
        let module_ref = reference_of(bytecode)?;
        let uploaded_at = clock::now();
        scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file!(
                    "queries/wasm_modules/save.sql",
                    tenant_id.as_uuid(),
                    module_ref.as_str(),
                    bytecode,
                    uploaded_at
                )
                .execute(connection)
                .await?;
                Ok(())
            },
        )
        .await?;
        Ok(module_ref)
    }

    async fn find(
        &self,
        tenant_id: &ScopedTenant,
        module_ref: &ModuleRef,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        let record = scoped(
            &self.databases,
            RowScope::from(tenant_id),
            async |connection| {
                sqlx::query_file_as!(
                    ModuleRecord,
                    "queries/wasm_modules/by_ref.sql",
                    tenant_id.as_uuid(),
                    module_ref.as_str()
                )
                .fetch_optional(connection)
                .await
            },
        )
        .await?;
        Ok(record.map(ModuleRecord::into_bytecode))
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::TestDb;

    const MODULE: &[u8] = b"\0asm\x01\0\0\0";

    struct Fixture {
        _db: TestDb,
        tenant: ScopedTenant,
        store: PgWasmModuleStore,
    }

    /// A fresh database, a tenant, and a store taking modules of at most a
    /// kilobyte.
    async fn fixture() -> Fixture {
        let db = TestDb::fresh().await;
        let store = PgWasmModuleStore::new(Arc::clone(&db.databases), 1_024);
        Fixture {
            _db: db,
            tenant: ScopedTenant::for_background(TenantId::new()),
            store,
        }
    }

    /// An uploaded module is found by the reference the store made, the
    /// SHA-256 of its bytes, with those bytes.
    #[tokio::test]
    async fn an_uploaded_module_is_found_by_its_digest() {
        let db = fixture().await;

        let module_ref = db.store.save(&db.tenant, MODULE).await.unwrap();

        assert!(module_ref.as_str().starts_with("sha256:"));
        assert_eq!(module_ref.as_str().len(), 71);
        let found = db.store.find(&db.tenant, &module_ref).await.unwrap();
        assert_eq!(found.as_deref(), Some(MODULE));
    }

    /// The same bytes uploaded twice give the same reference, once kept.
    #[tokio::test]
    async fn the_same_bytes_give_the_same_reference() {
        let db = fixture().await;

        let first = db.store.save(&db.tenant, MODULE).await.unwrap();
        let again = db.store.save(&db.tenant, MODULE).await.unwrap();

        assert_eq!(first, again);
    }

    /// Saving a two-kilobyte module to a one-kilobyte store returns a
    /// validation error.
    #[tokio::test]
    async fn a_module_too_large_is_refused() {
        let db = fixture().await;

        let saved = db.store.save(&db.tenant, &[0; 2_048]).await;

        assert!(matches!(saved, Err(DomainError::Validation(_))));
    }

    /// Looking up an uploaded module's reference from another tenant
    /// returns nothing.
    #[tokio::test]
    async fn another_tenant_finds_no_module() {
        let db = fixture().await;
        let module_ref = db.store.save(&db.tenant, MODULE).await.unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let found = db.store.find(&other, &module_ref).await.unwrap();

        assert!(found.is_none());
    }
}
