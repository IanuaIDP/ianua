//! Whoever holds a download link the platform made follows it and is
//! handed the export file it names.
//!
//! The link is the whole proof: it carries no caller, only a sealed ticket
//! to one tenant's file that works for a few minutes, once. Every reason a
//! link opens nothing, forged, changed, run out, used or naming a file
//! since deleted, answers alike, so a link says nothing about which files
//! exist.

use std::sync::Arc;

use ianua_domain::message;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;

use crate::error::AppError;
use crate::ports::files::{LinkedFiles, OpenedFile};
use crate::use_case::Query;

/// The longest token a link may carry; anything longer is refused unread.
const MOST_TOKEN_CHARS: usize = 256;

/// The ports [`DownloadUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct DownloadPorts {
    /// Opens the file a link names, once.
    pub files: Arc<dyn LinkedFiles>,
}

/// Opens the file a download link names.
pub struct DownloadUseCase {
    ports: DownloadPorts,
}

impl DownloadUseCase {
    /// A use case opening files through `ports`.
    #[must_use]
    pub fn new(ports: DownloadPorts) -> Self {
        Self { ports }
    }
}

impl Query for DownloadUseCase {
    type Caller = ();
    type Input = Secret;
    type Output = Result<OpenedFile, AppError>;

    /// The file `token` opens, to be streamed.
    ///
    /// # Errors
    ///
    /// - `AppError::NotFound` when the link opens nothing: forged, changed,
    ///   run out, used before, or its file is gone.
    /// - `AppError::Internal` when the file cannot be read.
    async fn execute(&self, (): &(), token: Secret) -> Result<OpenedFile, AppError> {
        let unknown = || {
            AppError::NotFound(message!(
                "files-no-file-at-this-link",
                "no file at this link"
            ))
        };
        if token.expose().is_empty() || token.expose().len() > MOST_TOKEN_CHARS {
            return Err(unknown());
        }
        match self.ports.files.open(&token).await {
            Ok(file) => Ok(file),
            Err(DomainError::Forbidden(_) | DomainError::NotFound) => Err(unknown()),
            Err(error) => Err(AppError::from_domain(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt as _;

    use super::*;
    use crate::test_support::files::FakeLinkedFiles;

    fn downloads(files: FakeLinkedFiles) -> DownloadUseCase {
        DownloadUseCase::new(DownloadPorts {
            files: Arc::new(files),
        })
    }

    /// Olivia follows the link to her audit log export and is handed the
    /// file, a part at a time.
    #[tokio::test]
    async fn a_link_opens_its_file() {
        let use_case = downloads(FakeLinkedFiles::opening("t0ken", b"id,event\n1,x\n"));

        let file = use_case.execute(&(), Secret::new("t0ken")).await.unwrap();

        let parts: Vec<Vec<u8>> = file.bytes.map(Result::unwrap).collect().await;
        assert_eq!(parts.concat(), b"id,event\n1,x\n");
        assert_eq!(file.length, 13);
    }

    /// A forged download token answers not found instead of opening the
    /// file associated with the valid token.
    #[tokio::test]
    async fn a_forged_link_answers_not_found() {
        let use_case = downloads(FakeLinkedFiles::opening("t0ken", b"x"));

        let opened = use_case.execute(&(), Secret::new("forged")).await;

        assert!(matches!(opened, Err(AppError::NotFound(_))));
    }

    /// After a download link opens its file once, using it again answers
    /// not found.
    #[tokio::test]
    async fn a_used_link_answers_not_found() {
        let use_case = downloads(FakeLinkedFiles::opening("t0ken", b"x"));
        use_case.execute(&(), Secret::new("t0ken")).await.unwrap();

        let again = use_case.execute(&(), Secret::new("t0ken")).await;

        assert!(matches!(again, Err(AppError::NotFound(_))));
    }
}
