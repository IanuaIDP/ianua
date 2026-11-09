//! The files the platform hands out by address: export files through the
//! signed links it mailed or showed, tenants' logos, public, and the files
//! the platform itself publishes, the same for everyone.

use std::borrow::Cow;
use std::fmt;
use std::pin::Pin;

use async_trait::async_trait;
use futures_util::Stream;
use ianua_domain::domains::branding::logo::LogoImage;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

/// A file's bytes, a part at a time, so a large file is never held whole
/// in memory.
pub type FileBytes = Pin<Box<dyn Stream<Item = Result<Vec<u8>, DomainError>> + Send>>;

/// A file a download link opened, to be streamed to whoever holds the link.
pub struct OpenedFile {
    /// The content type it is served with.
    pub content_type: &'static str,
    /// The name it is saved under, which the platform made.
    pub saved_as: String,
    /// How many bytes it holds.
    pub length: u64,
    /// The opened file's content, supplied through the storage reader.
    pub bytes: FileBytes,
}

impl fmt::Debug for OpenedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedFile")
            .field("content_type", &self.content_type)
            .field("saved_as", &self.saved_as)
            .field("length", &self.length)
            .finish_non_exhaustive()
    }
}

/// Dyn-safe port opening the files the platform's download links name.
///
/// A link is sealed by the platform, works for a few minutes, names one
/// tenant's file and opens it once. The adapter checks the seal and the
/// time, spends the link in the ledger every node shares, and opens the
/// file without reading it whole.
#[async_trait]
pub trait LinkedFiles: Send + Sync {
    /// The file `link`, the sealed ticket a download link ends in, opens.
    ///
    /// # Errors
    ///
    /// - `DomainError::Forbidden` when the link's seal does not hold, it
    ///   ran out, it was used before or the ledger cannot tell, or its file
    ///   is gone.
    /// - `DomainError::Infrastructure` when the file cannot be read.
    async fn open(&self, link: &Secret) -> Result<OpenedFile, DomainError>;
}

/// Dyn-safe port reading the tenants' logos the public logo address
/// serves.
#[async_trait]
pub trait PublicLogos: Send + Sync {
    /// The logo kept under `key`, the last part of its address, or `None`
    /// when `key` names no tenant's logo.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the logo cannot be read.
    async fn logo_at(&self, key: &str) -> Result<Option<LogoImage>, DomainError>;
}

/// A file the platform publishes at a fixed address, the same for every
/// caller. The set is closed: an address names one of these, never a path,
/// so no request can reach any other file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublishedFile {
    /// The platform's logo at the top of its mail. Mail clients strip
    /// embedded images, so they fetch it by address.
    EmailLogo,
    /// The CloudFormation template a customer runs in their AWS account to
    /// make the role the platform assumes.
    AwsTrustTemplate,
}

/// How long whoever fetched a published file may keep it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishedCaching {
    /// Kept for a week without asking again: it changes only with a build.
    WeekUnchanged,
    /// Kept for an hour, then asked for again, so a corrected file reaches
    /// customers soon after a new build.
    Hour,
}

/// A published file, ready to be served.
#[derive(Clone, PartialEq, Eq)]
pub struct PublishedContent {
    /// The content type it is served with.
    pub content_type: &'static str,
    /// How long it may be kept.
    pub caching: PublishedCaching,
    /// The name a browser saves it under, when it is meant to be saved.
    pub download_name: Option<&'static str>,
    /// The response content, borrowed or owned for publication.
    pub bytes: Cow<'static, [u8]>,
}

impl fmt::Debug for PublishedContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishedContent")
            .field("content_type", &self.content_type)
            .field("caching", &self.caching)
            .field("download_name", &self.download_name)
            .field("length", &self.bytes.len())
            .finish()
    }
}

/// Port reading the files the platform publishes. Each ships with the
/// build, so every one is always there and reading it cannot fail.
pub trait PublishedFiles: Send + Sync {
    /// The content of `file`.
    fn content(&self, file: PublishedFile) -> PublishedContent;
}
