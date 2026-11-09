//! A deleted tenant's files, removed by its teardown: its logo and its
//! people's data exports. Its audit log exports stay; they are kept and
//! removed with the trail they copy.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::tenant::TenantFilePurger;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;

use crate::files::store::FileStore;

/// Removes a deleted tenant's files from a file store.
pub struct FileTenantFilePurger {
    store: Arc<dyn FileStore>,
}

impl FileTenantFilePurger {
    /// A purger of the tenants' files in `store`.
    #[must_use]
    pub fn new(store: Arc<dyn FileStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl TenantFilePurger for FileTenantFilePurger {
    async fn purge(&self, tenant_id: &TenantId) -> Result<(), DomainError> {
        self.store.delete_tenant(tenant_id).await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::DataExportId;

    use super::*;
    use crate::files::disk::DiskFileStore;
    use crate::files::store::FileName;

    /// Purging a tenant twice removes its logo and data export without failing
    /// the retry.
    #[tokio::test]
    async fn a_purged_tenants_logo_and_exports_are_gone() {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn FileStore> = Arc::new(DiskFileStore::new(dir.path()));
        let acme = TenantId::new();
        let files = [
            FileName::logo(&acme),
            FileName::data_export(&acme, &DataExportId::new()),
        ];
        for name in &files {
            store.put(name, b"bytes").await.unwrap();
        }
        let purger = FileTenantFilePurger::new(Arc::clone(&store));

        purger.purge(&acme).await.unwrap();
        purger.purge(&acme).await.unwrap();

        for name in &files {
            assert!(store.open(name).await.unwrap().is_none());
        }
    }
}
