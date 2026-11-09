//! The links export files are downloaded through: signed by the platform,
//! working for a few minutes and never past the export's window, and good
//! for one download.
//!
//! A link carries which file it opens, when it stops working and a random
//! nonce, sealed with an HMAC under a key derived for file links alone. It
//! names no person and carries no secret of the caller. Opening it checks
//! the seal and the time, then spends the nonce in the shared ledger, so a
//! copied link opens nothing a second time; a ledger that cannot answer
//! refuses the download.

use std::num::NonZeroU32;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::stream;
use ianua_app::ports::authentication::NonceLedger;
use ianua_app::ports::files::{FileBytes, LinkedFiles, OpenedFile};
use ianua_domain::domains::audit::export::filter::AuditExportFormat;
use ianua_domain::message;
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{
    AuditExportId, DataExportId, HttpsUrl, Lifetime, Nonce, TenantId, TokenHash,
};
use rand::RngCore as _;
use rand::rngs::OsRng;
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncRead, AsyncReadExt as _};
use uuid::Uuid;

use crate::crypto::keys::{Purpose, PurposeKey, RootSecret, hmac_sha256};
use crate::files::store::{FileName, FileStore, StoredFile};

/// How long a link works at most.
const LINK_LIFETIME: Duration = Duration::minutes(5);

/// How long a spent link's nonce is remembered: as long as any link works.
const SPENT_FOR: Lifetime = Lifetime::from_secs(NonZeroU32::MIN.saturating_add(299));

/// The shape of a link's payload this release writes and reads.
const VERSION: u8 = 1;

/// The longest token a link may carry; anything longer is refused unread.
const MOST_TOKEN_CHARS: usize = 160;

/// A file a link opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkedFile {
    /// The file of an audit log export, in the format it was written in.
    AuditExport {
        /// The export.
        id: AuditExportId,
        /// The format it was written in.
        format: AuditExportFormat,
    },
    /// The file of a tenant's data export.
    DataExport {
        /// The tenant it was made in.
        tenant: TenantId,
        /// The export.
        id: DataExportId,
    },
}

impl LinkedFile {
    /// The number the payload names the file's kind by.
    fn kind(self) -> u8 {
        match self {
            Self::AuditExport {
                format: AuditExportFormat::Csv,
                ..
            } => 1,
            Self::AuditExport {
                format: AuditExportFormat::Json,
                ..
            } => 2,
            Self::DataExport { .. } => 3,
        }
    }

    /// The tenant and the id the payload carries.
    fn ids(self) -> (Uuid, Uuid) {
        match self {
            Self::AuditExport { id, .. } => (Uuid::nil(), *id.as_uuid()),
            Self::DataExport { tenant, id } => (*tenant.as_uuid(), *id.as_uuid()),
        }
    }

    /// The file a payload names by `kind`, `tenant` and `id`.
    fn from_parts(kind: u8, tenant: Uuid, id: Uuid) -> Option<Self> {
        let audit = |format| Self::AuditExport {
            id: AuditExportId::from_uuid(id),
            format,
        };
        match kind {
            1 => Some(audit(AuditExportFormat::Csv)),
            2 => Some(audit(AuditExportFormat::Json)),
            3 => Some(Self::DataExport {
                tenant: TenantId::from_uuid(tenant),
                id: DataExportId::from_uuid(id),
            }),
            _ => None,
        }
    }

    /// The name the file is kept under.
    fn name(self) -> FileName {
        match self {
            Self::AuditExport { id, format } => FileName::audit_export(&id, format),
            Self::DataExport { tenant, id } => FileName::data_export(&tenant, &id),
        }
    }

    /// The content type it is served with.
    fn content_type(self) -> &'static str {
        match self {
            Self::AuditExport {
                format: AuditExportFormat::Csv,
                ..
            } => "text/csv; charset=utf-8",
            Self::AuditExport {
                format: AuditExportFormat::Json,
                ..
            }
            | Self::DataExport { .. } => "application/json",
        }
    }

    /// The name it is saved as.
    fn saved_as(self) -> String {
        match self {
            Self::AuditExport { id, format } => {
                format!("audit-log-{}.{}", id.as_uuid().simple(), format.as_str())
            }
            Self::DataExport { id, .. } => format!("personal-data-{}.json", id.as_uuid().simple()),
        }
    }
}

/// What a checked link holds.
struct Ticket {
    file: LinkedFile,
    nonce: [u8; 16],
}

/// Makes and checks the links files are downloaded through.
#[derive(Debug, Clone)]
pub struct FileLinks {
    key: PurposeKey,
    served_from: HttpsUrl,
}

impl FileLinks {
    /// Links under `served_from`, the address the download route answers
    /// at, sealed under the key `root` derives for file links.
    #[must_use]
    pub fn new(root: &RootSecret, served_from: HttpsUrl) -> Self {
        Self {
            key: root.derive(Purpose::FileLinks),
            served_from,
        }
    }

    /// A link to `file`, working from `now` for a few minutes and never
    /// past `until`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when `until` has passed, or
    /// no random nonce or address can be made.
    pub(crate) fn link(
        &self,
        file: LinkedFile,
        now: OffsetDateTime,
        until: OffsetDateTime,
    ) -> Result<HttpsUrl, DomainError> {
        let expires = now.saturating_add(LINK_LIFETIME).min(until);
        if expires <= now {
            return Err(DomainError::infra_msg("the file's download window is over"));
        }
        let mut nonce = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(DomainError::infra)?;
        let payload = payload(file, expires, nonce);
        let seal = hmac_sha256(self.key.bytes(), &[&payload]);
        let address = format!(
            "{}/{}.{}",
            self.served_from.as_str().trim_end_matches('/'),
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(seal)
        );
        HttpsUrl::new(address).map_err(DomainError::infra)
    }

    /// What `token` opens, once its seal holds and it still works at
    /// `now`.
    fn checked(&self, token: &str, now: OffsetDateTime) -> Result<Ticket, DomainError> {
        let refused = || {
            DomainError::forbidden(message!(
                "infra-the-download-link-does-not-hold",
                "the download link does not hold"
            ))
        };
        if token.len() > MOST_TOKEN_CHARS {
            return Err(refused());
        }
        let (payload, seal) = token.split_once('.').ok_or_else(refused)?;
        let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|_| refused())?;
        let expected = URL_SAFE_NO_PAD.encode(hmac_sha256(self.key.bytes(), &[&payload]));
        if TokenHash::from_stored(expected) != TokenHash::from_stored(seal.to_owned()) {
            return Err(refused());
        }
        let (ticket, expires) = ticket_of(&payload).ok_or_else(refused)?;
        if expires <= now {
            return Err(refused());
        }
        Ok(ticket)
    }
}

/// The payload of a link to `file` working until `expires`.
fn payload(file: LinkedFile, expires: OffsetDateTime, nonce: [u8; 16]) -> Vec<u8> {
    let (tenant, id) = file.ids();
    let mut bytes = vec![VERSION, file.kind()];
    bytes.extend_from_slice(tenant.as_bytes());
    bytes.extend_from_slice(id.as_bytes());
    bytes.extend_from_slice(&expires.unix_timestamp().to_be_bytes());
    bytes.extend_from_slice(&nonce);
    bytes
}

/// The ticket a payload holds and when it stops working, or `None` when
/// it is not a payload this release writes.
fn ticket_of(bytes: &[u8]) -> Option<(Ticket, OffsetDateTime)> {
    let (&[version, kind], rest) = bytes.split_first_chunk::<2>()?;
    let (tenant, rest) = rest.split_first_chunk::<16>()?;
    let (id, rest) = rest.split_first_chunk::<16>()?;
    let (expires, rest) = rest.split_first_chunk::<8>()?;
    let nonce: [u8; 16] = rest.try_into().ok()?;
    if version != VERSION {
        return None;
    }
    let file = LinkedFile::from_parts(kind, Uuid::from_bytes(*tenant), Uuid::from_bytes(*id))?;
    let expires = OffsetDateTime::from_unix_timestamp(i64::from_be_bytes(*expires)).ok()?;
    Some((Ticket { file, nonce }, expires))
}

/// Opens the files download links name, for the route that serves them.
pub struct FileLinkedFiles {
    links: FileLinks,
    store: Arc<dyn FileStore>,
    spent: Arc<dyn NonceLedger>,
}

impl FileLinkedFiles {
    /// Downloads of the files in `store` by the links `links` makes, each
    /// spent once in `spent`, the ledger every node shares.
    #[must_use]
    pub fn new(links: FileLinks, store: Arc<dyn FileStore>, spent: Arc<dyn NonceLedger>) -> Self {
        Self {
            links,
            store,
            spent,
        }
    }

    /// The file `token` opens, once: the token is the last part of a link
    /// the platform made.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Forbidden` when the link's seal does not hold,
    /// it no longer works, it was used before or the ledger cannot tell, or
    /// its file is gone; `DomainError::Infrastructure` when the file cannot
    /// be read.
    pub async fn open(&self, token: &str) -> Result<Download, DomainError> {
        let ticket = self.links.checked(token, clock::now())?;
        let nonce = Nonce::new(format!(
            "file-link-{}",
            data_encoding::HEXLOWER.encode(&ticket.nonce)
        ))?;
        if !self.spent.spend(&nonce, SPENT_FOR).await {
            return Err(DomainError::forbidden(message!(
                "infra-the-download-link-was-used",
                "the download link was used"
            )));
        }
        let file = self.store.open(&ticket.file.name()).await?.ok_or_else(|| {
            DomainError::forbidden(message!("infra-the-file-is-gone", "the file is gone"))
        })?;
        Ok(Download {
            file,
            linked: ticket.file,
        })
    }
}

/// A file a link opened, to be streamed to the one who holds the link.
#[derive(Debug)]
pub struct Download {
    file: StoredFile,
    linked: LinkedFile,
}

impl Download {
    /// The content type it is served with.
    #[must_use]
    pub fn content_type(&self) -> &'static str {
        self.linked.content_type()
    }

    /// The name it is saved under, which the platform made.
    #[must_use]
    pub fn saved_as(&self) -> String {
        self.linked.saved_as()
    }

    /// How many bytes it holds.
    #[must_use]
    pub fn length(&self) -> u64 {
        self.file.length()
    }

    /// Its reader, for the response that streams it.
    #[must_use]
    pub fn into_reader(self) -> Box<dyn AsyncRead + Send + Unpin> {
        self.file.into_reader()
    }
}

/// How many bytes of a file are read and handed on at once.
const PART_BYTES: usize = 64 * 1024;

/// The bytes `reader` holds, a part at a time.
fn parts_of(reader: Box<dyn AsyncRead + Send + Unpin>) -> FileBytes {
    Box::pin(stream::try_unfold(reader, |mut reader| async move {
        let mut part = vec![0_u8; PART_BYTES];
        let read = reader.read(&mut part).await.map_err(DomainError::infra)?;
        if read == 0 {
            return Ok(None);
        }
        part.truncate(read);
        Ok(Some((part, reader)))
    }))
}

#[async_trait]
impl LinkedFiles for FileLinkedFiles {
    async fn open(&self, link: &Secret) -> Result<OpenedFile, DomainError> {
        let download = Self::open(self, link.expose()).await?;
        Ok(OpenedFile {
            content_type: download.content_type(),
            saved_as: download.saved_as(),
            length: download.length(),
            bytes: parts_of(download.into_reader()),
        })
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use futures_util::TryStreamExt as _;

    use super::*;
    use crate::cache::{CacheNonceLedger, MemoryState};
    use crate::crypto::keys::tests::test_root;
    use crate::files::disk::DiskFileStore;

    /// The ledger the platform spends nonces in, on this process's state.
    fn ledger() -> Arc<dyn NonceLedger> {
        Arc::new(CacheNonceLedger::new(Arc::new(MemoryState::new(64))))
    }

    /// A ledger that cannot answer, as one cut off from its server.
    struct Unreachable;

    #[async_trait]
    impl NonceLedger for Unreachable {
        async fn spend(&self, _: &Nonce, _: Lifetime) -> bool {
            false
        }
    }

    fn links() -> FileLinks {
        FileLinks::new(
            &test_root(),
            HttpsUrl::new("https://files.ianua.test/downloads").unwrap(),
        )
    }

    fn export() -> LinkedFile {
        LinkedFile::AuditExport {
            id: AuditExportId::new(),
            format: AuditExportFormat::Csv,
        }
    }

    async fn downloads_of(
        file: LinkedFile,
        spent: Arc<dyn NonceLedger>,
    ) -> (tempfile::TempDir, FileLinkedFiles) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DiskFileStore::new(dir.path()));
        store.put(&file.name(), b"id,event_type\n").await.unwrap();
        (dir, FileLinkedFiles::new(links(), store, spent))
    }

    fn token_of(link: &HttpsUrl) -> &str {
        link.as_str().rsplit('/').next().unwrap()
    }

    fn in_a_day() -> OffsetDateTime {
        clock::now().saturating_add(Duration::days(1))
    }

    /// A link handed out opens its file once, as a CSV attachment named
    /// by the platform.
    #[tokio::test]
    async fn a_link_opens_its_file_once() {
        let file = export();
        let (_dir, downloads) = downloads_of(file, ledger()).await;
        let link = links().link(file, clock::now(), in_a_day()).unwrap();

        let first = downloads.open(token_of(&link)).await.unwrap();
        let second = downloads.open(token_of(&link)).await;

        assert_eq!(first.content_type(), "text/csv; charset=utf-8");
        assert!(first.saved_as().starts_with("audit-log-"));
        assert_eq!(first.length(), 14);
        assert!(matches!(second, Err(DomainError::Forbidden(_))));
    }

    /// Changing a signed link's file-kind byte makes the download forbidden.
    #[tokio::test]
    async fn a_changed_link_opens_nothing() {
        let file = export();
        let (_dir, downloads) = downloads_of(file, ledger()).await;
        let link = links().link(file, clock::now(), in_a_day()).unwrap();
        let (payload, seal) = token_of(&link).split_once('.').unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        bytes[1] = 3;
        let forged = format!("{}.{seal}", URL_SAFE_NO_PAD.encode(bytes));

        let opened = downloads.open(&forged).await;

        assert!(matches!(opened, Err(DomainError::Forbidden(_))));
    }

    /// A link sealed under another root key cannot open its file.
    #[tokio::test]
    async fn a_link_sealed_under_another_key_opens_nothing() {
        let file = export();
        let (_dir, downloads) = downloads_of(file, ledger()).await;
        let other = FileLinks::new(
            &RootSecret::parse(&"cd".repeat(32)).unwrap(),
            HttpsUrl::new("https://files.ianua.test/downloads").unwrap(),
        );
        let link = other.link(file, clock::now(), in_a_day()).unwrap();

        assert!(matches!(
            downloads.open(token_of(&link)).await,
            Err(DomainError::Forbidden(_))
        ));
    }

    /// An hour-old download link is forbidden even while the export window remains open.
    #[tokio::test]
    async fn an_old_link_no_longer_works() {
        let file = export();
        let (_dir, downloads) = downloads_of(file, ledger()).await;
        let an_hour_ago = clock::now().saturating_sub(Duration::hours(1));
        let link = links().link(file, an_hour_ago, in_a_day()).unwrap();

        assert!(matches!(
            downloads.open(token_of(&link)).await,
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A link never works past the export's own window, however few
    /// minutes are left of it; one asked for after the window is refused.
    #[test]
    fn a_link_never_outlives_the_window() {
        let now = clock::now();
        let ended = now.saturating_sub(Duration::seconds(1));

        let refused = links().link(export(), now, ended);

        assert!(matches!(refused, Err(DomainError::Infrastructure(_))));
    }

    /// A valid download link is forbidden when the nonce ledger cannot authorize spending it.
    #[tokio::test]
    async fn a_ledger_that_cannot_answer_refuses_the_download() {
        let file = export();
        let (_dir, downloads) = downloads_of(file, Arc::new(Unreachable)).await;
        let link = links().link(file, clock::now(), in_a_day()).unwrap();

        assert!(matches!(
            downloads.open(token_of(&link)).await,
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A valid link naming an absent data-export file returns forbidden.
    #[tokio::test]
    async fn a_link_to_a_deleted_file_opens_nothing() {
        let file = LinkedFile::DataExport {
            tenant: TenantId::new(),
            id: DataExportId::new(),
        };
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DiskFileStore::new(dir.path()));
        let downloads = FileLinkedFiles::new(links(), store, ledger());
        let link = links().link(file, clock::now(), in_a_day()).unwrap();

        assert!(matches!(
            downloads.open(token_of(&link)).await,
            Err(DomainError::Forbidden(_))
        ));
    }

    /// A link names no person: its payload holds only the file's kind, the
    /// tenant, the export, the end and a nonce.
    #[test]
    fn a_link_names_only_the_file() {
        let link = links().link(export(), clock::now(), in_a_day()).unwrap();
        let (payload, _) = token_of(&link).split_once('.').unwrap();

        let bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();

        assert_eq!(bytes.len(), 2 + 16 + 16 + 8 + 16);
    }

    /// Through the port, a link hands its file over a part at a time, all
    /// of it, with its type, name and length.
    #[tokio::test]
    async fn the_port_streams_the_whole_file() {
        let file = export();
        let (_dir, downloads) = downloads_of(file, ledger()).await;
        let link = links().link(file, clock::now(), in_a_day()).unwrap();

        let opened = LinkedFiles::open(&downloads, &Secret::new(token_of(&link)))
            .await
            .unwrap();
        let parts: Vec<Vec<u8>> = opened.bytes.try_collect().await.unwrap();

        assert_eq!(parts.concat(), b"id,event_type\n");
        assert_eq!(opened.length, 14);
        assert_eq!(opened.content_type, "text/csv; charset=utf-8");
        assert!(opened.saved_as.starts_with("audit-log-"));
    }

    /// Altering a signed link's tenant bytes makes the port refuse its download.
    #[tokio::test]
    async fn a_link_moved_to_another_tenant_opens_nothing() {
        let file = export();
        let (_dir, downloads) = downloads_of(file, ledger()).await;
        let link = links().link(file, clock::now(), in_a_day()).unwrap();
        let (payload, seal) = token_of(&link).split_once('.').unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        bytes[2..18].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        let moved = format!("{}.{seal}", URL_SAFE_NO_PAD.encode(bytes));

        let opened = LinkedFiles::open(&downloads, &Secret::new(moved)).await;

        assert!(matches!(opened, Err(DomainError::Forbidden(_))));
    }
}
