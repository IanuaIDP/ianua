//! Anyone fetches a file the platform publishes at a fixed address: the
//! logo its mail shows, or the template a customer runs in their AWS
//! account.

use std::sync::Arc;

use crate::ports::files::{PublishedContent, PublishedFile, PublishedFiles};
use crate::use_case::Query;

/// The ports [`ServePublishedUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ServePublishedPorts {
    /// The files the platform publishes.
    pub files: Arc<dyn PublishedFiles>,
}

/// Serves a file the platform publishes.
pub struct ServePublishedUseCase {
    ports: ServePublishedPorts,
}

impl ServePublishedUseCase {
    /// A use case reading published files through `ports`.
    #[must_use]
    pub fn new(ports: ServePublishedPorts) -> Self {
        Self { ports }
    }
}

impl Query for ServePublishedUseCase {
    type Caller = ();
    type Input = PublishedFile;
    type Output = PublishedContent;

    /// The content of `file`. Public: the logo is fetched by mail clients
    /// with no credentials, and someone about to make a role in their own
    /// account may read exactly what it will do before they run it. Neither
    /// holds a secret.
    async fn execute(&self, (): &(), file: PublishedFile) -> PublishedContent {
        self.ports.files.content(file)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::ports::files::PublishedCaching;
    use crate::test_support::files::FakePublishedFiles;

    /// The file asked for is the one answered, with its type, caching and
    /// name as the port gave them.
    #[tokio::test]
    async fn the_file_asked_for_is_answered() {
        let template = PublishedContent {
            content_type: "application/x-yaml; charset=utf-8",
            caching: PublishedCaching::Hour,
            download_name: Some("ianua-connect.yaml"),
            bytes: Cow::Borrowed(b"AWSTemplateFormatVersion".as_slice()),
        };
        let use_case = ServePublishedUseCase::new(ServePublishedPorts {
            files: Arc::new(FakePublishedFiles::serving(
                PublishedFile::AwsTrustTemplate,
                template.clone(),
            )),
        });

        let served = use_case.execute(&(), PublishedFile::AwsTrustTemplate).await;

        assert_eq!(served, template);
    }
}
