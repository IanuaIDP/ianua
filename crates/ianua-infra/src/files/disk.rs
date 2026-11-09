//! The file store in a directory of this node, which the server
//! configures.
//!
//! Each file sits in a folder of its own, `<kind>/<ids>/<word>`, so
//! removing a file removes everything an attempt at it left. A file is
//! written to a part with a random name in that folder, flushed to the
//! disk, and renamed over the file's own name, so it appears whole or not
//! at all. Starting a file again clears the parts earlier attempts left.
//! Files and folders are made open to the platform's own user alone.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use tokio::fs;
use tokio::io::AsyncWriteExt as _;

use crate::files::store::{FileName, FileStore, FileUpload, StoredFile};

/// How long one call to the disk may take before it is given up on.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// The ending of a part being written.
const PART_ENDING: &str = ".part";

/// Who may read and write a kept file: the platform's own user alone, as
/// exports hold people's data and the node may have other users.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Who may open a folder of the store: the platform's own user alone.
#[cfg(unix)]
const FOLDER_MODE: u32 = 0o700;

/// The file store in one directory of this node.
#[derive(Debug, Clone)]
pub struct DiskFileStore {
    root: PathBuf,
}

impl DiskFileStore {
    /// A store keeping its files under `root`, which is made when the
    /// first file is written.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The folder `name` and its parts sit in.
    fn folder_of(&self, name: &FileName) -> PathBuf {
        name.folder()
            .into_iter()
            .fold(self.root.clone(), |path, part| path.join(part))
    }
}

#[async_trait]
impl FileStore for DiskFileStore {
    async fn create(&self, name: &FileName) -> Result<Box<dyn FileUpload>, DomainError> {
        let folder = self.folder_of(name);
        bounded(private_folders().create(&folder)).await?;
        bounded(clear_parts(&folder)).await?;
        let part = folder.join(format!("{:016x}{PART_ENDING}", rand::random::<u64>()));
        let file = bounded(private_part().open(&part)).await?;
        Ok(Box::new(DiskUpload {
            file,
            part,
            target: folder.join(name.leaf()),
        }))
    }

    async fn open(&self, name: &FileName) -> Result<Option<StoredFile>, DomainError> {
        let path = self.folder_of(name).join(name.leaf());
        let Some(file) = bounded(absent_as_none(fs::File::open(path))).await? else {
            return Ok(None);
        };
        let length = bounded(file.metadata()).await?.len();
        Ok(Some(StoredFile::new(Box::new(file), length)))
    }

    async fn delete(&self, name: &FileName) -> Result<(), DomainError> {
        bounded(absent_as_none(fs::remove_dir_all(self.folder_of(name)))).await?;
        Ok(())
    }

    async fn delete_tenant(&self, tenant: &TenantId) -> Result<(), DomainError> {
        for [kind, key] in FileName::tenant_folders(tenant) {
            let folder = self.root.join(kind).join(key);
            bounded(absent_as_none(fs::remove_dir_all(folder))).await?;
        }
        Ok(())
    }
}

/// A file of a [`DiskFileStore`] being written to its part.
struct DiskUpload {
    file: fs::File,
    part: PathBuf,
    target: PathBuf,
}

#[async_trait]
impl FileUpload for DiskUpload {
    async fn write(&mut self, bytes: &[u8]) -> Result<(), DomainError> {
        bounded(self.file.write_all(bytes)).await
    }

    async fn finish(mut self: Box<Self>) -> Result<(), DomainError> {
        bounded(self.file.flush()).await?;
        bounded(self.file.sync_all()).await?;
        bounded(fs::rename(&self.part, &self.target)).await
    }
}

/// Makes a file's folder and those above it, open to the platform's own
/// user alone.
fn private_folders() -> fs::DirBuilder {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(FOLDER_MODE);
    builder
}

/// Opens a new part, never one already there, readable and writable by
/// the platform's own user alone.
fn private_part() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(FILE_MODE);
    options
}

/// Removes the parts left in `folder` by attempts that never finished.
async fn clear_parts(folder: &Path) -> io::Result<()> {
    let mut entries = fs::read_dir(folder).await?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_name().to_string_lossy().ends_with(PART_ENDING) {
            absent_as_none(fs::remove_file(entry.path())).await?;
        }
    }
    Ok(())
}

/// What `work` gives, with a missing file read as `None`.
async fn absent_as_none<T>(work: impl Future<Output = io::Result<T>>) -> io::Result<Option<T>> {
    match work.await {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// What `work` gives, given up after [`CALL_TIMEOUT`].
async fn bounded<T>(work: impl Future<Output = io::Result<T>>) -> Result<T, DomainError> {
    tokio::time::timeout(CALL_TIMEOUT, work)
        .await
        .map_err(DomainError::infra)?
        .map_err(DomainError::infra)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use ianua_domain::domains::audit::export::filter::AuditExportFormat;
    use ianua_domain::types::{AuditExportId, DataExportId};

    use super::*;

    fn export_name() -> FileName {
        FileName::audit_export(&AuditExportId::new(), AuditExportFormat::Csv)
    }

    async fn read(store: &DiskFileStore, name: &FileName) -> Option<Vec<u8>> {
        let file = store.open(name).await.unwrap()?;
        Some(file.read_within(1024).await.unwrap())
    }

    /// A file written in two parts reads back whole once finished.
    #[tokio::test]
    async fn a_finished_file_reads_back_whole() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskFileStore::new(dir.path());
        let name = export_name();
        let mut upload = store.create(&name).await.unwrap();

        upload.write(b"id,").await.unwrap();
        upload.write(b"event_type\n").await.unwrap();
        upload.finish().await.unwrap();

        assert_eq!(read(&store, &name).await.unwrap(), b"id,event_type\n");
    }

    /// A partial upload remains absent from file reads until it is finished.
    #[tokio::test]
    async fn an_unfinished_file_is_not_there() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskFileStore::new(dir.path());
        let name = export_name();
        let mut upload = store.create(&name).await.unwrap();

        upload.write(b"half").await.unwrap();

        assert!(read(&store, &name).await.is_none());
    }

    /// An attempt cut short leaves a part; the next attempt clears it and
    /// writes the file from the start.
    #[tokio::test]
    async fn a_retry_clears_what_the_failed_attempt_left() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskFileStore::new(dir.path());
        let name = export_name();
        let mut failed = store.create(&name).await.unwrap();
        failed.write(b"cut short").await.unwrap();
        drop(failed);

        store.put(&name, b"whole").await.unwrap();

        let folder = name
            .folder()
            .into_iter()
            .fold(dir.path().to_path_buf(), |path, part| path.join(part));
        let left: Vec<String> = std::fs::read_dir(folder)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(left, vec![name.leaf().to_owned()]);
        assert_eq!(read(&store, &name).await.unwrap(), b"whole");
    }

    /// A stored personal-data export has owner-only file and directory permissions.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_kept_file_is_the_platforms_alone() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskFileStore::new(dir.path());
        let name = FileName::data_export(&TenantId::new(), &DataExportId::new());

        store.put(&name, b"{}").await.unwrap();

        let folder = name
            .folder()
            .into_iter()
            .fold(dir.path().to_path_buf(), |path, part| path.join(part));
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&folder.join(name.leaf())), FILE_MODE);
        assert_eq!(mode(&folder), FOLDER_MODE);
    }

    /// Keeping a file again replaces the one before.
    #[tokio::test]
    async fn a_file_kept_again_replaces_the_one_before() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskFileStore::new(dir.path());
        let name = FileName::logo(&TenantId::new());
        store.put(&name, b"first").await.unwrap();

        store.put(&name, b"second").await.unwrap();

        assert_eq!(read(&store, &name).await.unwrap(), b"second");
    }

    /// A deleted file is gone, and deleting it again succeeds.
    #[tokio::test]
    async fn a_deleted_file_is_gone_and_deleting_again_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskFileStore::new(dir.path());
        let name = export_name();
        store.put(&name, b"rows").await.unwrap();

        store.delete(&name).await.unwrap();
        store.delete(&name).await.unwrap();

        assert!(read(&store, &name).await.is_none());
    }

    /// Repeated tenant deletion removes its logo and data exports while
    /// preserving another tenant's files and audit exports.
    #[tokio::test]
    async fn removing_a_tenants_files_removes_its_logo_and_exports_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskFileStore::new(dir.path());
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let acme_files = [
            FileName::logo(&acme),
            FileName::data_export(&acme, &DataExportId::new()),
        ];
        let kept = [
            FileName::logo(&globex),
            FileName::data_export(&globex, &DataExportId::new()),
            export_name(),
        ];
        for name in acme_files.iter().chain(&kept) {
            store.put(name, b"bytes").await.unwrap();
        }

        store.delete_tenant(&acme).await.unwrap();
        store.delete_tenant(&acme).await.unwrap();

        for name in &acme_files {
            assert!(read(&store, name).await.is_none());
        }
        for name in &kept {
            assert!(read(&store, name).await.is_some());
        }
    }

    /// Reading a 64-byte file with a 63-byte limit returns an infrastructure error.
    #[tokio::test]
    async fn a_file_past_its_bound_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = DiskFileStore::new(dir.path());
        let name = export_name();
        store.put(&name, &[b'x'; 64]).await.unwrap();

        let file = store.open(&name).await.unwrap().unwrap();

        assert!(matches!(
            file.read_within(63).await,
            Err(DomainError::Infrastructure(_))
        ));
    }
}
