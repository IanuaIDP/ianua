//! Fakes for the files handed out by address: download links that open one
//! known file once, logos kept in memory, and published files answered from
//! memory.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_util::stream;
use ianua_domain::domains::branding::logo::LogoImage;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use crate::ports::files::{
    LinkedFiles, OpenedFile, PublicLogos, PublishedCaching, PublishedContent, PublishedFile,
    PublishedFiles,
};
use crate::test_support::Fake;

/// Download links opening one known file, once; every other token, and
/// the known one again, is refused as a link that does not hold.
#[derive(Default)]
pub struct FakeLinkedFiles {
    files: Mutex<HashMap<String, Vec<u8>>>,
}

impl FakeLinkedFiles {
    /// Links where `token` opens `bytes` once.
    #[must_use]
    pub fn opening(token: &str, bytes: &[u8]) -> Self {
        let files = HashMap::from([(token.to_owned(), bytes.to_vec())]);
        Self {
            files: Mutex::new(files),
        }
    }
}

#[async_trait]
impl LinkedFiles for FakeLinkedFiles {
    async fn open(&self, link: &Secret) -> Result<OpenedFile, DomainError> {
        let bytes = self
            .files
            .lock()
            .unwrap()
            .remove(link.expose())
            .ok_or_else(|| DomainError::forbidden("the download link does not hold"))?;
        let length = u64::try_from(bytes.len()).unwrap();
        let halves: Vec<Result<Vec<u8>, DomainError>> = bytes
            .chunks(bytes.len().div_ceil(2).max(1))
            .map(|part| Ok(part.to_vec()))
            .collect();
        Ok(OpenedFile {
            content_type: "text/csv; charset=utf-8",
            saved_as: "audit-log.csv".to_owned(),
            length,
            bytes: Box::pin(stream::iter(halves)),
        })
    }
}

impl Fake for Arc<dyn LinkedFiles> {
    fn fake() -> Self {
        Arc::new(FakeLinkedFiles::default())
    }
}

/// Logos kept in memory by the key their address ends in.
#[derive(Default)]
pub struct FakePublicLogos {
    logos: HashMap<String, LogoImage>,
}

impl FakePublicLogos {
    /// Logos where `key` serves `logo`.
    #[must_use]
    pub fn serving(key: &str, logo: LogoImage) -> Self {
        Self {
            logos: HashMap::from([(key.to_owned(), logo)]),
        }
    }
}

#[async_trait]
impl PublicLogos for FakePublicLogos {
    async fn logo_at(&self, key: &str) -> Result<Option<LogoImage>, DomainError> {
        Ok(self.logos.get(key).cloned())
    }
}

impl Fake for Arc<dyn PublicLogos> {
    fn fake() -> Self {
        Arc::new(FakePublicLogos::default())
    }
}

/// Published files kept in memory. A file given no content answers a few
/// bytes, kept for a week.
#[derive(Default)]
pub struct FakePublishedFiles {
    files: HashMap<PublishedFile, PublishedContent>,
}

impl FakePublishedFiles {
    /// Published files where `file` answers `content`.
    #[must_use]
    pub fn serving(file: PublishedFile, content: PublishedContent) -> Self {
        Self {
            files: HashMap::from([(file, content)]),
        }
    }
}

impl PublishedFiles for FakePublishedFiles {
    fn content(&self, file: PublishedFile) -> PublishedContent {
        self.files
            .get(&file)
            .cloned()
            .unwrap_or_else(|| PublishedContent {
                content_type: "application/octet-stream",
                caching: PublishedCaching::WeekUnchanged,
                download_name: None,
                bytes: Cow::Borrowed(b"published".as_slice()),
            })
    }
}

impl Fake for Arc<dyn PublishedFiles> {
    fn fake() -> Self {
        Arc::new(FakePublishedFiles::default())
    }
}
