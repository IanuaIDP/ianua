//! The files people's data exports are kept in, as the builder wrote
//! them: downloaded once per link while the export's window lasts, by the
//! person alone since only they are handed a link, and removed when the
//! window ends.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::identity::DataExportFiles;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DataExportId, HttpsUrl};
use time::OffsetDateTime;

use crate::files::links::{FileLinks, LinkedFile};
use crate::files::store::{FileName, FileStore};

/// People's data export files in a file store.
pub struct FileDataExportFiles {
    store: Arc<dyn FileStore>,
    links: FileLinks,
}

impl FileDataExportFiles {
    /// Export files kept in `store`, downloaded by the links `links`
    /// makes.
    #[must_use]
    pub fn new(store: Arc<dyn FileStore>, links: FileLinks) -> Self {
        Self { store, links }
    }
}

#[async_trait]
impl DataExportFiles for FileDataExportFiles {
    async fn download_link(
        &self,
        tenant_id: &ScopedTenant,
        id: &DataExportId,
        available_until: OffsetDateTime,
    ) -> Result<HttpsUrl, DomainError> {
        self.store
            .open(&FileName::data_export(tenant_id, id))
            .await?
            .ok_or_else(|| DomainError::infra_msg("the data export's file is gone"))?;
        let file = LinkedFile::DataExport {
            tenant: **tenant_id,
            id: *id,
        };
        self.links.link(file, clock::now(), available_until)
    }

    async fn delete(&self, tenant_id: &ScopedTenant, id: &DataExportId) -> Result<(), DomainError> {
        self.store
            .delete(&FileName::data_export(tenant_id, id))
            .await
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::crypto::keys::tests::test_root;
    use crate::files::disk::DiskFileStore;

    struct Fixture {
        _dir: tempfile::TempDir,
        store: Arc<DiskFileStore>,
        files: FileDataExportFiles,
        tenant: ScopedTenant,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DiskFileStore::new(dir.path()));
        let links = FileLinks::new(
            &test_root(),
            HttpsUrl::new("https://files.ianua.test/downloads").unwrap(),
        );
        Fixture {
            _dir: dir,
            files: FileDataExportFiles::new(store.clone(), links),
            store,
            tenant: ScopedTenant::for_background(TenantId::new()),
        }
    }

    fn in_a_week() -> OffsetDateTime {
        clock::now().saturating_add(time::Duration::days(7))
    }

    /// Ann's built export gets a link to its file; once deleted it gets
    /// none, and deleting it again succeeds.
    #[tokio::test]
    async fn a_built_export_is_linked_until_deleted() {
        let fixture = fixture();
        let id = DataExportId::new();
        fixture
            .store
            .put(&FileName::data_export(&fixture.tenant, &id), b"{}")
            .await
            .unwrap();

        let link = fixture
            .files
            .download_link(&fixture.tenant, &id, in_a_week())
            .await
            .unwrap();
        fixture.files.delete(&fixture.tenant, &id).await.unwrap();
        fixture.files.delete(&fixture.tenant, &id).await.unwrap();
        let gone = fixture
            .files
            .download_link(&fixture.tenant, &id, in_a_week())
            .await;

        assert!(
            link.as_str()
                .starts_with("https://files.ianua.test/downloads/")
        );
        assert!(matches!(gone, Err(DomainError::Infrastructure(_))));
    }

    /// A data-export link exposes neither an address marker nor the export's
    /// plain UUID.
    #[tokio::test]
    async fn a_link_names_no_person() {
        let fixture = fixture();
        let id = DataExportId::new();
        fixture
            .store
            .put(&FileName::data_export(&fixture.tenant, &id), b"{}")
            .await
            .unwrap();

        let link = fixture
            .files
            .download_link(&fixture.tenant, &id, in_a_week())
            .await
            .unwrap();

        assert!(!link.as_str().contains('@'));
        assert!(!link.as_str().contains(&id.to_string()));
    }

    /// An export stored under one tenant cannot be linked from another tenant.
    #[tokio::test]
    async fn another_tenants_export_has_no_link() {
        let fixture = fixture();
        let id = DataExportId::new();
        fixture
            .store
            .put(&FileName::data_export(&fixture.tenant, &id), b"{}")
            .await
            .unwrap();
        let other = ScopedTenant::for_background(TenantId::new());

        let link = fixture.files.download_link(&other, &id, in_a_week()).await;

        assert!(matches!(link, Err(DomainError::Infrastructure(_))));
    }
}
