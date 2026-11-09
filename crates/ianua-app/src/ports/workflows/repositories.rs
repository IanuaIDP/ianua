//! Repositories ports: reading one file of a company's repository at the
//! exact commit a branch, tag or commit points to now, and pushing files to
//! a branch, through a connected account's credential.
//!
//! Only integrations whose service keeps code offer this; the adapter says
//! which, and refuses the rest before anything is sent.

use async_trait::async_trait;
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::domains::workflows::sandbox::source::{
    CommitSha, GitRef, PushTarget, RepositoryName, RepositoryPath,
};
use ianua_domain::types::{IntegrationAccountId, UntrustedText};

use crate::ports::TenantScoped;
use crate::ports::authentication::SealedAt;
use crate::ports::workflows::Renewal;
use crate::tenancy::ScopedTenant;

/// The connected account a repository call goes through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryAccount {
    /// The account.
    pub id: IntegrationAccountId,
    /// Its credential, sealed for it.
    pub credential: SealedAt,
}

/// One file of a repository, at a branch, tag or commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAt {
    /// The integration of the service keeping the repository.
    pub integration: IntegrationKey,
    /// The source repository containing the requested file.
    pub repository: RepositoryName,
    /// The file.
    pub path: RepositoryPath,
    /// The branch, tag or commit to read it at.
    pub at: GitRef,
}

/// A file as it was read.
#[derive(Debug)]
pub struct FileRead {
    /// Its text.
    pub content: String,
    /// The commit it was read at.
    pub commit: CommitSha,
    /// A credential the service renewed on the way.
    pub renewal: Renewal,
}

/// One file to push, by its name in the target folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedFile {
    /// Its name inside the folder, such as `main.py`.
    pub name: RepositoryPath,
    /// Its text.
    pub content: String,
}

/// Files to push to one folder of a branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    /// Where they go.
    pub target: PushTarget,
    /// The files, written whole, each made or replaced.
    pub files: Vec<PushedFile>,
    /// The commit message.
    pub message: String,
}

/// How a push went.
#[derive(Debug)]
pub struct Pushed {
    /// The commit the last file became.
    pub commit: CommitSha,
    /// A credential the service renewed on the way.
    pub renewal: Renewal,
}

/// Why a repository was not read or pushed to.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryRefusal {
    /// The integration keeps no code repositories here.
    #[error("this integration keeps no code repositories")]
    NotOffered,
    /// The repository, file or branch is not there, or the account cannot
    /// see it.
    #[error("no such repository, file or branch for this account")]
    NotFound,
    /// The service refused, saying why.
    #[error("the service refused: {0}")]
    Refused(UntrustedText),
    /// The service could not be reached or was busy.
    #[error("the service could not be reached: {0}")]
    Unreachable(UntrustedText),
}

/// Dyn-safe port reading and pushing code through a connected account.
#[async_trait]
pub trait CodeRepositories: Send + Sync + TenantScoped {
    /// The file `at` names, read at the commit its ref points to now,
    /// through `account`.
    ///
    /// # Errors
    ///
    /// The [`RepositoryRefusal`] saying why it was not read.
    async fn read(
        &self,
        tenant_id: &ScopedTenant,
        account: &RepositoryAccount,
        at: &FileAt,
    ) -> Result<FileRead, RepositoryRefusal>;

    /// Pushes `push`'s files to its target, through `account`.
    ///
    /// # Errors
    ///
    /// The [`RepositoryRefusal`] saying why nothing, or not everything, was
    /// pushed.
    async fn push(
        &self,
        tenant_id: &ScopedTenant,
        account: &RepositoryAccount,
        push: &Push,
    ) -> Result<Pushed, RepositoryRefusal>;
}
