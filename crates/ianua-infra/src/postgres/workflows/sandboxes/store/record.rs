//! A sandbox as its row holds it: read back into the aggregate, and written
//! out from it.

use ianua_domain::domains::workflows::sandbox::runtime::Language;
use ianua_domain::domains::workflows::sandbox::{Sandbox, SandboxKind, SandboxRow, SandboxStatus};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{Label, SandboxId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::{Stored, StoredWord as _, stored_words};

const SANDBOX: Stored = Stored("sandbox");

const CREATED_BY: Kept = Kept {
    entity: SANDBOX.0,
    column: "created_by",
    shape: 1,
};

stored_words! {
    Language as "sandbox language" {
        Python => "python",
        JavaScript => "javascript",
    }
}

stored_words! {
    SandboxStatus as "sandbox status" {
        Active => "active",
        Archived => "archived",
    }
}

/// A sandbox as it is read. The store's checked queries fill it.
pub(super) struct SandboxRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) language: Option<String>,
    pub(super) status: String,
    pub(super) latest_version: i32,
    pub(super) created_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl SandboxRecord {
    /// What the sandbox's versions run, from its kind and its language.
    fn sandbox_kind(&self) -> Result<SandboxKind, DomainError> {
        match (self.kind.as_str(), self.language.as_deref()) {
            ("code", Some(language)) => SANDBOX.choice(language).map(SandboxKind::Code),
            ("image", None) => Ok(SandboxKind::OwnImage),
            _ => Err(DomainError::corrupt_row(
                SANDBOX.0,
                "a kind that does not fit its language",
            )),
        }
    }

    /// The sandbox the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a word is unknown, or the row breaks a rule the sandbox
    /// keeps.
    pub(super) fn into_sandbox(self) -> Result<Sandbox<ResolvedTenant>, DomainError> {
        Sandbox::reconstitute(SandboxRow {
            id: SandboxId::from_uuid(self.id),
            kind: self.sandbox_kind()?,
            name: SANDBOX.value("name", Label::new("name", self.name))?,
            status: SANDBOX.choice(&self.status)?,
            latest_version: u32::try_from(self.latest_version)
                .map_err(|_| DomainError::corrupt_row(SANDBOX.0, "a negative version number"))?,
            created_by: CREATED_BY.open(self.created_by)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A sandbox's columns, as they are written.
pub(super) struct SandboxColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) name: &'a str,
    pub(super) kind: &'static str,
    pub(super) language: Option<&'static str>,
    pub(super) status: &'static str,
    pub(super) latest_version: i32,
    pub(super) created_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> SandboxColumns<'a> {
    /// The columns `sandbox` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its maker cannot be
    /// written out, or its latest number does not fit its column.
    pub(super) fn of(sandbox: &'a Sandbox<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: sandbox.id().as_uuid(),
            name: sandbox.name().as_str(),
            kind: sandbox.kind().as_str(),
            language: sandbox.kind().language().map(Language::word),
            status: sandbox.status().word(),
            latest_version: i32::try_from(sandbox.latest_version()).map_err(DomainError::infra)?,
            created_by: CREATED_BY.seal(sandbox.created_by())?,
            created_at: sandbox.created_at(),
            updated_at: sandbox.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use ianua_domain::types::{Human, HumanAccount, PersonKey, UserId};
    use serde_json::json;

    use super::*;

    /// The person who made a sandbox is written as their account and
    /// address, and read back.
    #[test]
    fn the_maker_is_stored_in_their_pinned_shape() {
        let ann = Human::new(
            HumanAccount::User(UserId::from_uuid(Uuid::nil())),
            PersonKey::new("ann@acme.example").unwrap(),
        );
        let stored = json!({"v": 1, "value": {
            "account": {"User": "00000000-0000-0000-0000-000000000000"},
            "person": "ann@acme.example"
        }});

        assert_eq!(CREATED_BY.seal(&ann).unwrap(), stored);
        assert_eq!(CREATED_BY.open::<Human>(stored).unwrap(), ann);
    }
}
