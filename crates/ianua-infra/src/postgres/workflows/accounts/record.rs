//! An integration account as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::workflows::account::{IntegrationAccount, IntegrationAccountRow};
use ianua_domain::domains::workflows::integration::IntegrationKey;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{IntegrationAccountId, Label, SealedSecret};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _};
use crate::postgres::workflows::operation_scope;

const ACCOUNT: Stored = Stored("integration account");

const OWNER: Kept = Kept {
    entity: ACCOUNT.0,
    column: "owner",
    shape: 1,
};

/// An account as it is read. The store's checked queries fill it.
pub(super) struct AccountRecord {
    pub(super) id: Uuid,
    pub(super) integration: String,
    pub(super) name: String,
    pub(super) credential_sealed: String,
    pub(super) owner: Value,
    pub(super) sharing: String,
    pub(super) operations: Option<Vec<String>>,
    pub(super) status: String,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl AccountRecord {
    /// The account the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the account
    /// keeps.
    pub(super) fn into_account(self) -> Result<IntegrationAccount<ResolvedTenant>, DomainError> {
        IntegrationAccount::reconstitute(IntegrationAccountRow {
            id: IntegrationAccountId::from_uuid(self.id),
            integration: ACCOUNT.value("integration", IntegrationKey::new(self.integration))?,
            name: ACCOUNT.value("name", Label::new("name", self.name))?,
            credential: ACCOUNT.value("credential", SealedSecret::new(self.credential_sealed))?,
            owner: OWNER.open(self.owner)?,
            sharing: ACCOUNT.choice(&self.sharing)?,
            scope: operation_scope::read(ACCOUNT, self.operations)?,
            status: ACCOUNT.choice(&self.status)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// An account's columns, as they are written.
pub(super) struct AccountColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) integration: &'a str,
    pub(super) name: &'a str,
    pub(super) credential_sealed: &'a str,
    pub(super) owner: Value,
    pub(super) sharing: &'static str,
    pub(super) operations: Option<Vec<String>>,
    pub(super) status: &'static str,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> AccountColumns<'a> {
    /// The columns `account` is written to. Its credential is written in
    /// the sealed form it already holds.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the owner cannot be
    /// written out.
    pub(super) fn of(account: &'a IntegrationAccount<ResolvedTenant>) -> Result<Self, DomainError> {
        let operations = operation_scope::written(account.scope());
        Ok(Self {
            id: account.id().as_uuid(),
            integration: account.integration().as_str(),
            name: account.name().as_str(),
            credential_sealed: account.credential().as_str(),
            owner: OWNER.seal(account.owner())?,
            sharing: account.sharing().word(),
            operations,
            status: account.status().word(),
            created_at: account.created_at(),
            updated_at: account.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape the JSON column is stored in today. A row written now is
    //! read for years, so when this fails, the domain changed how it writes
    //! a person: raise the column's shape and add the step that reads the
    //! old one, rather than changing the shape pinned here.

    use ianua_domain::types::Human;
    use serde_json::json;

    use super::*;
    use crate::test_support::rows::workflows::ann;

    /// An account's owner is written in the shape pinned here, and reads
    /// back.
    #[test]
    fn the_owner_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "account": {"User": "00000000-0000-0000-0000-000000000a11"},
            "person": "ann@acme.example"
        }});

        assert_eq!(OWNER.seal(&ann()).unwrap(), stored);
        assert_eq!(OWNER.open::<Human>(stored).unwrap(), ann());
    }
}
