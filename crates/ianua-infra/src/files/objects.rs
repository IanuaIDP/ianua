//! The file store in an S3-compatible bucket, which the server configures:
//! AWS S3, Cloudflare R2, MinIO, DigitalOcean Spaces, Backblaze B2, Wasabi,
//! or Google Cloud Storage through its XML API and an HMAC key.
//!
//! Each file is one object, keyed `<kind>/<ids>/<word>` as the disk store
//! lays out its folders, so a file's folder and a tenant's folders are
//! prefixes of the keys beneath them. A file is written a part at a time
//! and appears whole or not at all (`uploads`); it is read as it arrives,
//! never more of it than the store said it holds (`reader`). Removing a
//! file removes everything under its folder, and removing a tenant every
//! object under its folders, a page at a time (`removal`).
//!
//! Starting a file aborts the uploads earlier attempts at it left, listed
//! by the file's own key, the one listing MinIO answers as AWS does. The
//! uploads left under a removed folder are aborted where the store lists
//! them by folder; MinIO expires its own after a day, and on any other
//! store a lifecycle rule that aborts unfinished uploads after a day keeps
//! a crash from leaving parts for good.
//!
//! Every call is signed with AWS Signature Version 4 for the configured
//! region and goes through the fixed client with a timeout (`calls`). An
//! error names the store's status and code, never a key, a body or the
//! secret.

mod calls;
mod documents;
mod reader;
mod removal;
mod settings;
mod uploads;

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::TenantId;
use reqwest::Method;

use crate::files::objects::calls::{Bucket, Call, Reading, refusal};
use crate::files::objects::documents::NO_SUCH_KEY;
use crate::files::objects::reader::BodyReader;
use crate::files::objects::removal::{abort_pending, remove_under};
pub use crate::files::objects::settings::{BucketAddressing, ObjectStoreSettings};
use crate::files::objects::uploads::ObjectUpload;
use crate::files::store::{FileName, FileStore, FileUpload, StoredFile};

/// The longest file the store reads back: 4 GiB, past anything the
/// platform writes.
const LONGEST_FILE: u64 = 4_294_967_296;

/// The file store in one S3-compatible bucket.
pub struct ObjectFileStore {
    bucket: Arc<Bucket>,
}

/// Shows nothing of the bucket's key.
impl fmt::Debug for ObjectFileStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectFileStore").finish_non_exhaustive()
    }
}

impl ObjectFileStore {
    /// A store keeping its files in the bucket `settings` names.
    ///
    /// # Errors
    ///
    /// - `DomainError::Validation` when a setting is not one a store takes,
    ///   such as an endpoint in plain HTTP off this machine.
    /// - `DomainError::Infrastructure` when the client cannot be built.
    pub fn new(settings: ObjectStoreSettings) -> Result<Self, DomainError> {
        Ok(Self {
            bucket: Arc::new(Bucket::new(settings.checked()?)?),
        })
    }
}

#[async_trait]
impl FileStore for ObjectFileStore {
    async fn create(&self, name: &FileName) -> Result<Box<dyn FileUpload>, DomainError> {
        let key = key_of(name);
        abort_pending(&self.bucket, &key).await?;
        Ok(Box::new(ObjectUpload::new(Arc::clone(&self.bucket), key)))
    }

    async fn open(&self, name: &FileName) -> Result<Option<StoredFile>, DomainError> {
        let key = key_of(name);
        let call = Call {
            reading: Reading::Streamed,
            ..Call::to(Method::GET, &key, &[])
        };
        let response = self.bucket.send(call).await?;
        if !response.status().is_success() {
            return absent_or_refused(response).await;
        }
        let length = length_of(&response)?;
        let reader = BodyReader::spawn(response, length);
        Ok(Some(StoredFile::new(Box::new(reader), length)))
    }

    async fn delete(&self, name: &FileName) -> Result<(), DomainError> {
        abort_pending(&self.bucket, &key_of(name)).await?;
        remove_under(&self.bucket, &prefix_of(name)).await
    }

    async fn delete_tenant(&self, tenant: &TenantId) -> Result<(), DomainError> {
        for [kind, key] in FileName::tenant_folders(tenant) {
            remove_under(&self.bucket, &format!("{kind}/{key}/")).await?;
        }
        Ok(())
    }
}

/// The object `name` is kept as: its folder's parts and its last word.
fn key_of(name: &FileName) -> String {
    format!("{}{}", prefix_of(name), name.leaf())
}

/// The prefix every key under `name`'s folder starts with.
fn prefix_of(name: &FileName) -> String {
    format!("{}/", name.folder().join("/"))
}

/// `None` when the store answered that the object is not there, or the
/// refusal it answered with otherwise, such as a missing bucket.
async fn absent_or_refused(response: reqwest::Response) -> Result<Option<StoredFile>, DomainError> {
    let refused = refusal(response).await;
    if refused.is_gone(NO_SUCH_KEY) {
        return Ok(None);
    }
    Err(DomainError::infra(refused))
}

/// How long the object `response` answers with is, as the store said.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the store did not say, or
/// the file is longer than [`LONGEST_FILE`].
fn length_of(response: &reqwest::Response) -> Result<u64, DomainError> {
    let Some(length) = response.content_length() else {
        return Err(DomainError::infra_msg(
            "the object store did not say how long the file is",
        ));
    };
    if length > LONGEST_FILE {
        return Err(DomainError::infra_msg(
            "a kept file is longer than it may be",
        ));
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::export::filter::AuditExportFormat;
    use ianua_domain::types::{AuditExportId, DataExportId};

    use super::*;
    use crate::files::objects::uploads::PART_BYTES;
    use crate::test_support::objects::{fresh_settings, pending_uploads};

    fn export_name() -> FileName {
        FileName::audit_export(&AuditExportId::new(), AuditExportFormat::Csv)
    }

    async fn store() -> ObjectFileStore {
        ObjectFileStore::new(fresh_settings().await).unwrap()
    }

    async fn read(store: &ObjectFileStore, name: &FileName, most: u64) -> Option<Vec<u8>> {
        let file = store.open(name).await.unwrap()?;
        Some(file.read_within(most).await.unwrap())
    }

    /// The bytes of a long file, each part's bytes different, so a part
    /// out of order or twice reads back wrong.
    fn long_file() -> Vec<u8> {
        let length = PART_BYTES.saturating_mul(2).saturating_add(1_024);
        (0..length)
            .map(|at| u8::try_from(at.wrapping_mul(31) % 251).unwrap())
            .collect()
    }

    /// A file written in two writes reads back whole once finished, with
    /// its length.
    #[tokio::test]
    async fn a_finished_file_reads_back_whole() {
        let store = store().await;
        let name = export_name();
        let mut upload = store.create(&name).await.unwrap();

        upload.write(b"id,").await.unwrap();
        upload.write(b"event_type\n").await.unwrap();
        upload.finish().await.unwrap();

        let file = store.open(&name).await.unwrap().unwrap();
        assert_eq!(file.length(), 14);
        assert_eq!(file.read_within(1_024).await.unwrap(), b"id,event_type\n");
    }

    /// A file longer than two parts is sent as a multipart upload and
    /// reads back byte for byte.
    #[tokio::test]
    async fn a_file_of_several_parts_reads_back_whole() {
        let store = store().await;
        let name = FileName::data_export(&TenantId::new(), &DataExportId::new());
        let bytes = long_file();
        let mut upload = store.create(&name).await.unwrap();

        for chunk in bytes.chunks(1_000_000) {
            upload.write(chunk).await.unwrap();
        }
        upload.finish().await.unwrap();

        let most = u64::try_from(bytes.len()).unwrap();
        assert_eq!(read(&store, &name, most).await.unwrap(), bytes);
    }

    /// Writing multiple parts without finishing the upload leaves no readable
    /// file under its name.
    #[tokio::test]
    async fn an_unfinished_file_is_not_there() {
        let store = store().await;
        let name = export_name();
        let mut upload = store.create(&name).await.unwrap();

        upload.write(&long_file()).await.unwrap();

        assert!(store.open(&name).await.unwrap().is_none());
        drop(upload);
    }

    /// Dropping a multipart upload eventually removes its pending upload and
    /// leaves no readable file.
    #[tokio::test]
    async fn a_dropped_upload_leaves_nothing() {
        let settings = fresh_settings().await;
        let store = ObjectFileStore::new(settings.clone()).unwrap();
        let name = export_name();
        let mut upload = store.create(&name).await.unwrap();
        upload.write(&long_file()).await.unwrap();
        assert_eq!(pending_uploads(&settings, &key_of(&name)).await, 1);

        drop(upload);

        let mut left = 1;
        for _ in 0..50 {
            left = pending_uploads(&settings, &key_of(&name)).await;
            if left == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(left, 0);
        assert!(store.open(&name).await.unwrap().is_none());
    }

    /// An attempt a crash cut short leaves its upload; the next attempt at
    /// the same file aborts it and writes the file from the start.
    #[tokio::test]
    async fn a_retry_clears_what_the_failed_attempt_left() {
        let settings = fresh_settings().await;
        let store = ObjectFileStore::new(settings.clone()).unwrap();
        let name = export_name();
        let mut failed = store.create(&name).await.unwrap();
        failed.write(&long_file()).await.unwrap();
        std::mem::forget(failed);

        store.put(&name, b"whole").await.unwrap();

        assert_eq!(pending_uploads(&settings, &key_of(&name)).await, 0);
        assert_eq!(read(&store, &name, 1_024).await.unwrap(), b"whole");
    }

    /// Keeping a file again replaces the one before.
    #[tokio::test]
    async fn a_file_kept_again_replaces_the_one_before() {
        let store = store().await;
        let name = FileName::logo(&TenantId::new());
        store.put(&name, b"first").await.unwrap();

        store.put(&name, b"second").await.unwrap();

        assert_eq!(read(&store, &name, 1_024).await.unwrap(), b"second");
    }

    /// A deleted file is gone with both formats of its export, and
    /// deleting it again succeeds.
    #[tokio::test]
    async fn a_deleted_file_is_gone_and_deleting_again_succeeds() {
        let store = store().await;
        let id = AuditExportId::new();
        let csv = FileName::audit_export(&id, AuditExportFormat::Csv);
        let json = FileName::audit_export(&id, AuditExportFormat::Json);
        store.put(&csv, b"rows").await.unwrap();
        store.put(&json, b"[]").await.unwrap();

        store.delete(&csv).await.unwrap();
        store.delete(&csv).await.unwrap();

        assert!(store.open(&csv).await.unwrap().is_none());
        assert!(store.open(&json).await.unwrap().is_none());
    }

    /// Removing a tenant's files twice deletes its logo and data exports while
    /// retaining another tenant's files and the audit export.
    #[tokio::test]
    async fn removing_a_tenants_files_removes_its_files_only() {
        let store = store().await;
        let (acme, globex) = (TenantId::new(), TenantId::new());
        let acme_files = [
            FileName::logo(&acme),
            FileName::data_export(&acme, &DataExportId::new()),
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
            assert!(store.open(name).await.unwrap().is_none());
        }
        for name in &kept {
            assert!(store.open(name).await.unwrap().is_some());
        }
    }

    /// Reading a stored file with a bound below its length fails.
    #[tokio::test]
    async fn a_file_past_its_bound_is_refused() {
        let store = store().await;
        let name = export_name();
        store.put(&name, &[b'x'; 64]).await.unwrap();

        let file = store.open(&name).await.unwrap().unwrap();

        assert!(matches!(
            file.read_within(63).await,
            Err(DomainError::Infrastructure(_))
        ));
    }

    /// Opening a file in a missing bucket fails with its error code and keeps
    /// the store's secret out of the error and its causes.
    #[tokio::test]
    async fn a_missing_bucket_is_a_failure_not_an_empty_store() {
        let mut settings = fresh_settings().await;
        settings.bucket = format!("missing-{}", uuid::Uuid::now_v7().simple());
        let store = ObjectFileStore::new(settings).unwrap();

        let error = store.open(&export_name()).await.unwrap_err();

        let printed = format!("{error:?} {}", ianua_domain::shared::errors::causes(&error));
        assert!(printed.contains("NoSuchBucket"), "{printed}");
        assert!(!printed.contains(crate::test_support::objects::SECRET));
    }

    /// Writing with the wrong signing secret fails with an infrastructure error.
    #[tokio::test]
    async fn a_wrong_secret_is_refused() {
        let mut settings = fresh_settings().await;
        settings.secret_access_key =
            ianua_domain::shared::security::secret::Secret::new("not-the-secret");
        let store = ObjectFileStore::new(settings).unwrap();

        let written = store.put(&export_name(), b"rows").await;

        assert!(matches!(written, Err(DomainError::Infrastructure(_))));
    }
}
