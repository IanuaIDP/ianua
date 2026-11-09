//! A stand-in for repositories: a file it answers every read with, at one
//! commit, or none, and the pushes it was handed.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ianua_domain::domains::workflows::sandbox::source::CommitSha;

use crate::ports::TenantScoped;
use crate::ports::workflows::{
    CodeRepositories, FileAt, FileRead, Push, Pushed, Renewal, RepositoryAccount, RepositoryRefusal,
};
use crate::tenancy::ScopedTenant;
use crate::test_support::Fake;

/// Repositories holding one file's text, or none.
#[derive(Default)]
pub struct FakeCodeRepositories {
    file: Option<String>,
    read: Mutex<Vec<FileAt>>,
    pushed: Mutex<Vec<Push>>,
}

impl FakeCodeRepositories {
    /// Repositories answering every read with `content`.
    #[must_use]
    pub fn holding(content: &str) -> Self {
        Self {
            file: Some(content.to_owned()),
            ..Self::default()
        }
    }

    /// The commit every read and push comes back at.
    ///
    /// # Panics
    ///
    /// Never: the fixed hash is a valid commit.
    #[must_use]
    pub fn commit() -> CommitSha {
        CommitSha::new("c".repeat(40)).expect("a valid commit")
    }

    /// The files read so far.
    ///
    /// # Panics
    ///
    /// Panics if the lock was poisoned.
    #[must_use]
    pub fn reads(&self) -> Vec<FileAt> {
        self.read.lock().expect("a held list").clone()
    }

    /// The pushes made so far.
    ///
    /// # Panics
    ///
    /// Panics if the lock was poisoned.
    #[must_use]
    pub fn pushes(&self) -> Vec<Push> {
        self.pushed.lock().expect("a held list").clone()
    }
}

impl TenantScoped for FakeCodeRepositories {}

#[async_trait]
impl CodeRepositories for FakeCodeRepositories {
    async fn read(
        &self,
        _: &ScopedTenant,
        _: &RepositoryAccount,
        at: &FileAt,
    ) -> Result<FileRead, RepositoryRefusal> {
        self.read.lock().expect("a held list").push(at.clone());
        let Some(content) = &self.file else {
            return Err(RepositoryRefusal::NotFound);
        };
        Ok(FileRead {
            content: content.clone(),
            commit: Self::commit(),
            renewal: Renewal::Unchanged,
        })
    }

    async fn push(
        &self,
        _: &ScopedTenant,
        _: &RepositoryAccount,
        push: &Push,
    ) -> Result<Pushed, RepositoryRefusal> {
        self.pushed.lock().expect("a held list").push(push.clone());
        Ok(Pushed {
            commit: Self::commit(),
            renewal: Renewal::Unchanged,
        })
    }
}

impl Fake for Arc<dyn CodeRepositories> {
    fn fake() -> Self {
        Arc::new(FakeCodeRepositories::default())
    }
}
