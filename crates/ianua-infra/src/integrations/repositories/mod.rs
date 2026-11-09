//! Reading sandbox code from a company's repository and pushing versions to
//! it, through the installed integration of the service keeping it and an
//! account connected to it. Each service's steps are in a file of its own;
//! an integration with none here keeps no code, and is refused before
//! anything is sent.

mod calls;
mod github;
mod gitlab;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::TenantScoped;
use ianua_app::ports::authentication::SecretEncryptor;
use ianua_app::ports::workflows::{
    CodeRepositories, FileAt, FileRead, Push, Pushed, RepositoryAccount, RepositoryRefusal,
};
use ianua_app::tenancy::ScopedTenant;

use crate::integrations::installed::Installed;
use crate::integrations::repositories::calls::Calls;
use crate::integrations::runner::InstalledActionRunner;

/// Repositories reached through the installed integrations.
///
/// Every call is one of the integration's own steps, made as an action
/// step's call is: the account's credential opened only for it, held to the
/// same time limit, and a credential the service renews kept for the
/// account.
pub struct InstalledCodeRepositories {
    runner: InstalledActionRunner,
}

impl TenantScoped for InstalledCodeRepositories {}

impl InstalledCodeRepositories {
    /// Repositories reached through `installed`, opening credentials with
    /// `encryptor`, each call given up on after `limit`.
    #[must_use]
    pub fn new(
        installed: Arc<Installed>,
        encryptor: Arc<dyn SecretEncryptor>,
        limit: Duration,
    ) -> Self {
        Self {
            runner: InstalledActionRunner::new(installed, encryptor, limit),
        }
    }
}

#[async_trait]
impl CodeRepositories for InstalledCodeRepositories {
    async fn read(
        &self,
        tenant_id: &ScopedTenant,
        account: &RepositoryAccount,
        at: &FileAt,
    ) -> Result<FileRead, RepositoryRefusal> {
        let mut calls = Calls::new(&self.runner, tenant_id, &at.integration, account);
        let (content, commit) = match at.integration.as_str() {
            github::KEY => github::read(&mut calls, at).await?,
            gitlab::KEY => gitlab::read(&mut calls, at).await?,
            _ => return Err(RepositoryRefusal::NotOffered),
        };
        Ok(FileRead {
            content,
            commit,
            renewal: calls.renewal(),
        })
    }

    async fn push(
        &self,
        tenant_id: &ScopedTenant,
        account: &RepositoryAccount,
        push: &Push,
    ) -> Result<Pushed, RepositoryRefusal> {
        let mut calls = Calls::new(&self.runner, tenant_id, &push.target.integration, account);
        let commit = match push.target.integration.as_str() {
            github::KEY => github::push(&mut calls, push).await?,
            gitlab::KEY => gitlab::push(&mut calls, push).await?,
            _ => return Err(RepositoryRefusal::NotOffered),
        };
        Ok(Pushed {
            commit,
            renewal: calls.renewal(),
        })
    }
}
