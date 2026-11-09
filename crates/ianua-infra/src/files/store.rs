//! The one file store every file adapter writes through, and the names the
//! platform gives its files.
//!
//! A name is made by the platform from what a file holds and the ids it
//! belongs to, never from anything a person typed: a fixed folder for its
//! kind, then hex ids, the tenant's first where the file is a tenant's, and
//! a fixed last word. A tenant's files of each kind sit under one folder,
//! so they go together when the tenant does. No name can climb out of
//! the store or reach another file, so no adapter ever checks a path.
//!
//! A file is written a part at a time and appears whole or not at all, so
//! a reader never sees half of one, and a write cut short by a crash or a
//! timeout is cleared by the next attempt at the same name.

use std::fmt;

use async_trait::async_trait;
use ianua_domain::domains::audit::export::filter::AuditExportFormat;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{AuditExportId, DataExportId, SandboxVersionId, TenantId};
use tokio::io::{AsyncRead, AsyncReadExt as _};

/// Where the platform keeps its files: a directory of this node, or later
/// a bucket in the cloud.
///
/// Each call gives up after a few seconds.
#[async_trait]
pub trait FileStore: Send + Sync {
    /// Starts the file `name`, written a part at a time. Nothing under
    /// `name` changes until the upload is finished, and what an earlier
    /// attempt left half written is cleared first.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the file cannot be
    /// started.
    async fn create(&self, name: &FileName) -> Result<Box<dyn FileUpload>, DomainError>;

    /// The file `name`, to read a part at a time, or `None` when none is
    /// kept.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the store cannot be read.
    async fn open(&self, name: &FileName) -> Result<Option<StoredFile>, DomainError>;

    /// Removes the file `name` with anything half written beside it.
    /// Removing one already gone succeeds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be removed.
    async fn delete(&self, name: &FileName) -> Result<(), DomainError>;

    /// Removes every file `tenant` holds, of every kind kept by tenant.
    /// Removing what is gone already succeeds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be removed.
    async fn delete_tenant(&self, tenant: &TenantId) -> Result<(), DomainError>;

    /// Keeps `bytes` whole as the file `name`, replacing the one before at
    /// once.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the file cannot be kept.
    async fn put(&self, name: &FileName, bytes: &[u8]) -> Result<(), DomainError> {
        let mut upload = self.create(name).await?;
        upload.write(bytes).await?;
        upload.finish().await
    }
}

/// One file being written. It appears under its name only once finished.
#[async_trait]
pub trait FileUpload: Send {
    /// Writes `bytes` after those written before.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when they cannot be written.
    async fn write(&mut self, bytes: &[u8]) -> Result<(), DomainError>;

    /// Makes the file whole under its name, replacing any kept before.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it cannot be finished.
    async fn finish(self: Box<Self>) -> Result<(), DomainError>;
}

/// A kept file, opened to be read a part at a time.
pub struct StoredFile {
    reader: Box<dyn AsyncRead + Send + Unpin>,
    length: u64,
}

impl StoredFile {
    /// The file `length` bytes long that `reader` reads.
    pub(crate) fn new(reader: Box<dyn AsyncRead + Send + Unpin>, length: u64) -> Self {
        Self { reader, length }
    }

    /// How many bytes it holds.
    #[must_use]
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Its reader, for a response that streams it.
    #[must_use]
    pub fn into_reader(self) -> Box<dyn AsyncRead + Send + Unpin> {
        self.reader
    }

    /// The whole file, once it holds at most `most` bytes.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when it is longer or cannot be
    /// read.
    pub(crate) async fn read_within(self, most: u64) -> Result<Vec<u8>, DomainError> {
        if self.length > most {
            return Err(DomainError::infra_msg(
                "a kept file is longer than it may be",
            ));
        }
        let mut bytes = Vec::new();
        self.reader
            .take(most.saturating_add(1))
            .read_to_end(&mut bytes)
            .await
            .map_err(DomainError::infra)?;
        let read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if read > most {
            return Err(DomainError::infra_msg(
                "a kept file is longer than it may be",
            ));
        }
        Ok(bytes)
    }
}

/// Shows the length, never the bytes.
impl fmt::Debug for StoredFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredFile")
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

/// What a file holds, which fixes the folder it is kept in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shelf {
    /// Tenants' logos, served to anyone.
    Logos,
    /// Exports of the audit logs, downloaded by link.
    AuditExports,
    /// Copies of a person's data, downloaded by link.
    DataExports,
    /// The package bundles of sandbox versions, mounted into their runs.
    SandboxBundles,
}

impl Shelf {
    /// The kinds kept under the tenant's id first, removed with it.
    const BY_TENANT: [Self; 3] = [Self::Logos, Self::DataExports, Self::SandboxBundles];

    /// The folder the kind is kept in.
    fn folder(self) -> &'static str {
        match self {
            Self::Logos => "logos",
            Self::AuditExports => "audit-exports",
            Self::DataExports => "data-exports",
            Self::SandboxBundles => "sandbox-bundles",
        }
    }
}

/// The last word of a file's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Leaf {
    /// A tenant's logo, whichever format it is in.
    Logo,
    /// An export written as CSV.
    Csv,
    /// An export written as JSON.
    Json,
    /// A sandbox version's packages, as a gzipped tar.
    Bundle,
}

impl Leaf {
    /// The word itself.
    fn word(self) -> &'static str {
        match self {
            Self::Logo => "logo",
            Self::Csv => "export.csv",
            Self::Json => "export.json",
            Self::Bundle => "bundle.tar.gz",
        }
    }
}

/// The name the platform gives a file: its kind's folder, hex ids, and a
/// fixed last word. It is never made from what a person typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileName {
    shelf: Shelf,
    keys: Vec<String>,
    leaf: Leaf,
}

impl FileName {
    /// The logo of `tenant`. A tenant keeps one, whatever its format.
    pub(crate) fn logo(tenant: &TenantId) -> Self {
        Self {
            shelf: Shelf::Logos,
            keys: vec![hex(tenant.as_uuid())],
            leaf: Leaf::Logo,
        }
    }

    /// The file of audit log export `id`, written as `format`.
    pub(crate) fn audit_export(id: &AuditExportId, format: AuditExportFormat) -> Self {
        let leaf = match format {
            AuditExportFormat::Csv => Leaf::Csv,
            AuditExportFormat::Json => Leaf::Json,
        };
        Self {
            shelf: Shelf::AuditExports,
            keys: vec![hex(id.as_uuid())],
            leaf,
        }
    }

    /// The file of `tenant`'s data export `id`.
    pub(crate) fn data_export(tenant: &TenantId, id: &DataExportId) -> Self {
        Self {
            shelf: Shelf::DataExports,
            keys: vec![hex(tenant.as_uuid()), hex(id.as_uuid())],
            leaf: Leaf::Json,
        }
    }

    /// The package bundle of `tenant`'s sandbox version `version`.
    pub(crate) fn sandbox_bundle(tenant: &TenantId, version: &SandboxVersionId) -> Self {
        Self {
            shelf: Shelf::SandboxBundles,
            keys: vec![hex(tenant.as_uuid()), hex(version.as_uuid())],
            leaf: Leaf::Bundle,
        }
    }

    /// The folder the file and anything half written beside it sit in,
    /// as its path parts.
    pub(crate) fn folder(&self) -> Vec<&str> {
        std::iter::once(self.shelf.folder())
            .chain(self.keys.iter().map(String::as_str))
            .collect()
    }

    /// The folders holding every file `tenant` keeps, each as its path
    /// parts.
    pub(crate) fn tenant_folders(tenant: &TenantId) -> Vec<[String; 2]> {
        Shelf::BY_TENANT
            .iter()
            .map(|shelf| [shelf.folder().to_owned(), hex(tenant.as_uuid())])
            .collect()
    }

    /// The file's own last word.
    pub(crate) fn leaf(&self) -> &'static str {
        self.leaf.word()
    }
}

/// `id` in plain hex, as every name holds it.
fn hex(id: &uuid::Uuid) -> String {
    id.simple().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name is made of the kind's folder, hex ids and a fixed word,
    /// so none holds a separator or a step up.
    #[test]
    fn a_name_holds_only_hex_ids_and_fixed_words() {
        let tenant = TenantId::new();
        let names = [
            FileName::logo(&tenant),
            FileName::audit_export(&AuditExportId::new(), AuditExportFormat::Csv),
            FileName::data_export(&tenant, &DataExportId::new()),
            FileName::sandbox_bundle(&tenant, &SandboxVersionId::new()),
        ];

        for name in &names {
            let parts = name.folder();
            for part in parts.iter().copied().chain([name.leaf()]) {
                assert!(!part.contains('/') && !part.contains(".."), "{part}");
            }
            for key in &parts[1..] {
                assert!(key.chars().all(|c| c.is_ascii_hexdigit()), "{key}");
            }
        }
    }

    /// A tenant's logo and data exports sit under its own folders, so
    /// removing those removes them, and an audit export, kept with the
    /// trail, sits under none of them.
    #[test]
    fn a_tenants_files_sit_under_its_folders() {
        let tenant = TenantId::new();
        let folders = FileName::tenant_folders(&tenant);

        let under = |name: &FileName| {
            let parts = name.folder();
            folders
                .iter()
                .any(|[kind, key]| parts.get(0..2) == Some(&[kind.as_str(), key.as_str()][..]))
        };

        assert!(under(&FileName::logo(&tenant)));
        assert!(under(&FileName::data_export(&tenant, &DataExportId::new())));
        assert!(under(&FileName::sandbox_bundle(
            &tenant,
            &SandboxVersionId::new()
        )));
        assert!(!under(&FileName::audit_export(
            &AuditExportId::new(),
            AuditExportFormat::Csv
        )));
        assert!(!under(&FileName::logo(&TenantId::new())));
    }

    /// Two formats of one audit export share its folder, so removing the
    /// export removes whichever was written.
    #[test]
    fn both_formats_of_an_export_share_a_folder() {
        let id = AuditExportId::new();

        let csv = FileName::audit_export(&id, AuditExportFormat::Csv);
        let json = FileName::audit_export(&id, AuditExportFormat::Json);

        assert_eq!(csv.folder(), json.folder());
        assert_ne!(csv.leaf(), json.leaf());
    }
}
