//! A directory service account as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::authentication::directory_service::account::{
    DirectoryServiceAccount, DirectoryServiceAccountRow,
};
use ianua_domain::domains::authentication::directory_service::scope::{
    BaseDn, ServiceAccountName, ServiceAccountScope,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DirectoryServiceAccountId, TokenHash};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const ACCOUNT: Stored = Stored("directory service account");

/// An account as it is read. The store's checked queries fill it.
pub(super) struct AccountRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) secret_hash: String,
    pub(super) access: String,
    pub(super) base_dns: Vec<String>,
    pub(super) status: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) secret_changed_at: OffsetDateTime,
}

impl AccountRecord {
    /// The account the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the account
    /// keeps.
    pub(super) fn into_account(
        self,
    ) -> Result<DirectoryServiceAccount<ResolvedTenant>, DomainError> {
        let base_dns = self
            .base_dns
            .into_iter()
            .map(|dn| ACCOUNT.value("base DN", BaseDn::new(dn)))
            .collect::<Result<Vec<_>, _>>()?;
        let scope = ServiceAccountScope::new(ACCOUNT.choice(&self.access)?, base_dns)
            .map_err(DomainError::infra)?;
        DirectoryServiceAccount::reconstitute(DirectoryServiceAccountRow {
            id: DirectoryServiceAccountId::from_uuid(self.id),
            name: ACCOUNT.value("name", ServiceAccountName::new(self.name))?,
            secret_hash: TokenHash::from_stored(self.secret_hash),
            scope,
            status: ACCOUNT.choice(&self.status)?,
            created_at: self.created_at,
            secret_changed_at: self.secret_changed_at,
        })
    }
}

/// An account's columns, as they are written.
pub(super) struct AccountColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) secret_hash: &'a str,
    pub(super) access: &'static str,
    pub(super) base_dns: Vec<String>,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) secret_changed_at: OffsetDateTime,
}

impl<'a> AccountColumns<'a> {
    /// The columns `account` is written to.
    pub(super) fn of(account: &'a DirectoryServiceAccount<ResolvedTenant>) -> Self {
        Self {
            id: account.id().as_uuid(),
            name: account.name().as_str(),
            secret_hash: account.secret_hash().as_str(),
            access: account.scope().access().word(),
            base_dns: account
                .scope()
                .base_dns()
                .iter()
                .map(|dn| dn.as_str().to_owned())
                .collect(),
            status: account.status().word(),
            created_at: account.created_at(),
            secret_changed_at: account.secret_changed_at(),
        }
    }
}
