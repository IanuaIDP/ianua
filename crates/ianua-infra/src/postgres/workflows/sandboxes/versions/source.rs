//! Where a version's code came from, as its four source columns hold it:
//! all empty for code written in the platform, or the repository file it
//! was imported from and the commit it was read at.

use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::sandbox::source::{
    CodeSource, CommitSha, RepositoryFile, RepositoryName, RepositoryPath,
};
use ianua_domain::shared::errors::DomainError;

use crate::postgres::foundation::stored::Stored;

const VERSION: Stored = Stored("sandbox version");

/// The source columns of a row, as they are read and written.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct SourceColumns {
    pub(super) integration: Option<String>,
    pub(super) repository: Option<String>,
    pub(super) path: Option<String>,
    pub(super) commit: Option<String>,
}

impl SourceColumns {
    /// The columns `source` is written to.
    pub(super) fn of(source: &CodeSource) -> Self {
        let CodeSource::Imported(file) = source else {
            return Self::default();
        };
        Self {
            integration: Some(file.integration.as_str().to_owned()),
            repository: Some(file.repository.as_str().to_owned()),
            path: Some(file.path.as_str().to_owned()),
            commit: Some(file.commit.as_str().to_owned()),
        }
    }

    /// The source the columns hold.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when only some are filled, or
    /// a value no longer passes its rules.
    pub(super) fn into_source(self) -> Result<CodeSource, DomainError> {
        match (self.integration, self.repository, self.path, self.commit) {
            (None, None, None, None) => Ok(CodeSource::Written),
            (Some(integration), Some(repository), Some(path), Some(commit)) => {
                Ok(CodeSource::Imported(RepositoryFile {
                    integration: VERSION
                        .value("source integration", IntegrationKey::new(integration))?,
                    repository: VERSION
                        .value("source repository", RepositoryName::new(repository))?,
                    path: VERSION.value("source path", RepositoryPath::new(path))?,
                    commit: VERSION.value("source commit", CommitSha::new(commit))?,
                }))
            }
            _ => Err(DomainError::corrupt_row(
                VERSION.0,
                "a source its columns hold only part of",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An imported file is written to its four columns and read back as it
    /// was; written code fills none.
    #[test]
    fn a_source_reads_back_from_its_columns() {
        let imported = CodeSource::Imported(RepositoryFile {
            integration: IntegrationKey::new("github").unwrap(),
            repository: RepositoryName::new("acme/web").unwrap(),
            path: RepositoryPath::new("scripts/tidy.py").unwrap(),
            commit: CommitSha::new("a".repeat(40)).unwrap(),
        });

        let read = SourceColumns::of(&imported).into_source().unwrap();

        assert_eq!(read, imported);
        assert_eq!(
            SourceColumns::of(&CodeSource::Written),
            SourceColumns::default()
        );
    }

    /// Reading repository source columns without a commit returns an
    /// infrastructure error.
    #[test]
    fn a_source_with_a_column_missing_is_corrupt() {
        let columns = SourceColumns {
            integration: Some("github".to_owned()),
            repository: Some("acme/web".to_owned()),
            path: Some("scripts/tidy.py".to_owned()),
            commit: None,
        };

        let read = columns.into_source();

        assert!(matches!(read, Err(DomainError::Infrastructure(_))));
    }
}
