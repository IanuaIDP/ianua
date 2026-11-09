//! The files audit log exports are kept in: written a page at a time by
//! the worker, downloaded once per link while the export's window lasts,
//! and removed when it ends.
//!
//! A CSV file opens with its header and holds one row per record; a JSON
//! file is one array of records. Neither is in the store until the last
//! page is written, so a link never opens half an export, and a try that
//! fails is written again from the start by the next.

use std::sync::Arc;

use async_trait::async_trait;
use ianua_app::ports::audit::{AuditExportFiles, AuditExportUpload, AuditLogEntry};
use ianua_domain::domains::audit::export::filter::AuditExportFormat;
use ianua_domain::domains::audit::export::seal::FileDigest;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AuditExportId, HttpsUrl};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::files::links::{FileLinks, LinkedFile};
use crate::files::records::{CSV_HEADER, csv_rows, json_items};
use crate::files::store::{FileName, FileStore, FileUpload};

/// The formats an export's file may have been written in, in the order
/// a link looks for them.
const FORMATS: [AuditExportFormat; 2] = [AuditExportFormat::Csv, AuditExportFormat::Json];

/// The audit log exports' files in a file store.
pub struct FileAuditExportFiles {
    store: Arc<dyn FileStore>,
    links: FileLinks,
}

impl FileAuditExportFiles {
    /// Export files kept in `store`, downloaded by the links `links`
    /// makes.
    #[must_use]
    pub fn new(store: Arc<dyn FileStore>, links: FileLinks) -> Self {
        Self { store, links }
    }

    /// The format export `id`'s file was written in, once it is whole.
    async fn written_format(&self, id: &AuditExportId) -> Result<AuditExportFormat, DomainError> {
        for format in FORMATS {
            let kept = self.store.open(&FileName::audit_export(id, format)).await?;
            if kept.is_some() {
                return Ok(format);
            }
        }
        Err(DomainError::infra_msg(
            "the audit log export's file is gone",
        ))
    }
}

#[async_trait]
impl AuditExportFiles for FileAuditExportFiles {
    async fn create(
        &self,
        id: &AuditExportId,
        format: AuditExportFormat,
    ) -> Result<Box<dyn AuditExportUpload>, DomainError> {
        let file = self
            .store
            .create(&FileName::audit_export(id, format))
            .await?;
        let mut upload = FileAuditExportUpload {
            file,
            format,
            written: 0,
            digest: Sha256::new(),
        };
        upload.put(opening(format)).await?;
        Ok(Box::new(upload))
    }

    async fn download_link(
        &self,
        id: &AuditExportId,
        available_until: OffsetDateTime,
    ) -> Result<HttpsUrl, DomainError> {
        let format = self.written_format(id).await?;
        let file = LinkedFile::AuditExport { id: *id, format };
        self.links.link(file, clock::now(), available_until)
    }

    async fn delete(&self, id: &AuditExportId) -> Result<(), DomainError> {
        self.store
            .delete(&FileName::audit_export(id, AuditExportFormat::Csv))
            .await
    }
}

/// One audit log export's file being written, a page at a time, with the
/// SHA-256 of every byte written so far. Only
/// [`FileAuditExportFiles::create`] makes one.
pub(crate) struct FileAuditExportUpload {
    file: Box<dyn FileUpload>,
    format: AuditExportFormat,
    written: u64,
    digest: Sha256,
}

impl FileAuditExportUpload {
    /// Writes `text` into the file and into its digest.
    async fn put(&mut self, text: &str) -> Result<(), DomainError> {
        self.digest.update(text.as_bytes());
        self.file.write(text.as_bytes()).await
    }
}

#[async_trait]
impl AuditExportUpload for FileAuditExportUpload {
    async fn append(&mut self, entries: &[AuditLogEntry]) -> Result<(), DomainError> {
        let text = match self.format {
            AuditExportFormat::Csv => csv_rows(entries)?,
            AuditExportFormat::Json => json_items(entries, self.written)?,
        };
        self.put(&text).await?;
        let count = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        self.written = self.written.saturating_add(count);
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<FileDigest, DomainError> {
        self.put(closing(self.format)).await?;
        let digest = FileDigest::from_bytes(&self.digest.finalize())?;
        self.file.finish().await?;
        Ok(digest)
    }
}

/// What a file in `format` starts with.
fn opening(format: AuditExportFormat) -> &'static str {
    match format {
        AuditExportFormat::Csv => CSV_HEADER,
        AuditExportFormat::Json => "[",
    }
}

/// What a file in `format` ends with.
fn closing(format: AuditExportFormat) -> &'static str {
    match format {
        AuditExportFormat::Csv => "",
        AuditExportFormat::Json => "\n]\n",
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::record::AuditTarget;
    use ianua_domain::shared::events::data::EventData;
    use ianua_domain::types::{AuditRecordId, EventType};
    use serde_json::Value;
    use tokio::io::AsyncReadExt as _;

    use super::*;
    use crate::crypto::keys::tests::test_root;
    use crate::files::disk::DiskFileStore;
    use crate::test_support::rows::at;

    struct Fixture {
        _dir: tempfile::TempDir,
        store: Arc<DiskFileStore>,
        files: FileAuditExportFiles,
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
            files: FileAuditExportFiles::new(store.clone(), links),
            store,
        }
    }

    fn entry(seconds: i64) -> AuditLogEntry {
        AuditLogEntry {
            id: AuditRecordId::new(),
            event_type: EventType::parse("authentication.login_failed").unwrap(),
            actor_display: "System".to_owned(),
            tenant_id: None,
            tenant_slug: None,
            tenant_name: None,
            target: AuditTarget::Untargeted,
            ip_address: None,
            payload: EventData::new(),
            acted_through: ianua_domain::domains::audit::builder::ActedThrough::Directly,
            occurred_at: at(seconds),
        }
    }

    async fn written(fixture: &Fixture, id: &AuditExportId, format: AuditExportFormat) -> String {
        let file = fixture
            .store
            .open(&FileName::audit_export(id, format))
            .await
            .unwrap()
            .unwrap();
        let mut text = String::new();
        file.into_reader().read_to_string(&mut text).await.unwrap();
        text
    }

    async fn export(
        fixture: &Fixture,
        format: AuditExportFormat,
        pages: &[usize],
    ) -> AuditExportId {
        let id = AuditExportId::new();
        let mut upload = fixture.files.create(&id, format).await.unwrap();
        for (page, size) in pages.iter().enumerate() {
            let entries: Vec<AuditLogEntry> = (0..*size)
                .map(|n| entry(i64::try_from(page * 10 + n).unwrap()))
                .collect();
            upload.append(&entries).await.unwrap();
        }
        upload.finish().await.unwrap();
        id
    }

    /// An export written in three pages as CSV holds the header and one
    /// row per record.
    #[tokio::test]
    async fn a_csv_export_holds_its_header_and_every_row() {
        let fixture = fixture();

        let id = export(&fixture, AuditExportFormat::Csv, &[2, 2, 1]).await;

        let text = written(&fixture, &id, AuditExportFormat::Csv).await;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], CSV_HEADER.trim_end());
        assert_eq!(lines.len(), 6);
    }

    /// An export written in pages as JSON is one array of every record,
    /// and one with no records is an empty array.
    #[tokio::test]
    async fn a_json_export_is_one_array() {
        let fixture = fixture();

        let full = export(&fixture, AuditExportFormat::Json, &[2, 1]).await;
        let empty = export(&fixture, AuditExportFormat::Json, &[]).await;

        let full: Value =
            serde_json::from_str(&written(&fixture, &full, AuditExportFormat::Json).await).unwrap();
        let empty: Value =
            serde_json::from_str(&written(&fixture, &empty, AuditExportFormat::Json).await)
                .unwrap();
        assert_eq!(full.as_array().unwrap().len(), 3);
        assert_eq!(empty, Value::Array(Vec::new()));
    }

    /// The digest the upload answers is the SHA-256 of the file as it is
    /// downloaded, header and closing included, so an auditor's
    /// `sha256sum` of the file matches the seal.
    #[tokio::test]
    async fn the_digest_is_of_the_whole_file_as_stored() {
        let fixture = fixture();
        let id = AuditExportId::new();
        let mut upload = fixture
            .files
            .create(&id, AuditExportFormat::Json)
            .await
            .unwrap();
        upload.append(&[entry(1), entry(2)]).await.unwrap();

        let digest = upload.finish().await.unwrap();

        let text = written(&fixture, &id, AuditExportFormat::Json).await;
        assert_eq!(digest.as_bytes()[..], Sha256::digest(text.as_bytes())[..]);
    }

    /// A written export gets a link to its file; a deleted one gets none,
    /// and deleting it again succeeds.
    #[tokio::test]
    async fn a_written_export_is_linked_until_deleted() {
        let fixture = fixture();
        let id = export(&fixture, AuditExportFormat::Json, &[1]).await;
        let until = clock::now().saturating_add(time::Duration::days(7));

        let link = fixture.files.download_link(&id, until).await.unwrap();
        fixture.files.delete(&id).await.unwrap();
        fixture.files.delete(&id).await.unwrap();
        let gone = fixture.files.download_link(&id, until).await;

        assert!(
            link.as_str()
                .starts_with("https://files.ianua.test/downloads/")
        );
        assert!(matches!(gone, Err(DomainError::Infrastructure(_))));
    }

    /// An unfinished audit export cannot receive a download link.
    #[tokio::test]
    async fn an_export_still_written_has_no_link() {
        let fixture = fixture();
        let id = AuditExportId::new();
        let mut upload = fixture
            .files
            .create(&id, AuditExportFormat::Csv)
            .await
            .unwrap();
        upload.append(&[entry(1)]).await.unwrap();
        let until = clock::now().saturating_add(time::Duration::days(7));

        let link = fixture.files.download_link(&id, until).await;

        assert!(matches!(link, Err(DomainError::Infrastructure(_))));
    }
}
