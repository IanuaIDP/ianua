//! A workflow's webhook secret as its row holds it: read back into the
//! aggregate, and written out from it.

use ianua_domain::domains::workflows::triggers::secret::{
    WorkflowTriggerSecret, WorkflowTriggerSecretRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{TokenHash, WorkflowId, WorkflowTriggerId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;

const ISSUED_BY: Kept = Kept {
    entity: "workflow trigger secret",
    column: "issued_by",
    shape: 1,
};

/// A secret as it is read. The store's checked queries fill it.
pub(super) struct TriggerSecretRecord {
    pub(super) id: Uuid,
    pub(super) workflow_id: Uuid,
    pub(super) secret_hash: String,
    pub(super) issued_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) secret_changed_at: OffsetDateTime,
}

impl TriggerSecretRecord {
    /// The secret the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when who issued it does not
    /// read, or the row breaks a rule the secret keeps.
    pub(super) fn into_secret(self) -> Result<WorkflowTriggerSecret<ResolvedTenant>, DomainError> {
        WorkflowTriggerSecret::reconstitute(WorkflowTriggerSecretRow {
            id: WorkflowTriggerId::from_uuid(self.id),
            workflow_id: WorkflowId::from_uuid(self.workflow_id),
            secret_hash: TokenHash::from_stored(self.secret_hash),
            issued_by: ISSUED_BY.open(self.issued_by)?,
            created_at: self.created_at,
            secret_changed_at: self.secret_changed_at,
        })
    }
}

/// A secret's columns, as they are written.
pub(super) struct TriggerSecretColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) workflow_id: &'a Uuid,
    pub(super) secret_hash: &'a str,
    pub(super) issued_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) secret_changed_at: OffsetDateTime,
}

impl<'a> TriggerSecretColumns<'a> {
    /// The columns `secret` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when who issued it cannot be
    /// written out.
    pub(super) fn of(
        secret: &'a WorkflowTriggerSecret<ResolvedTenant>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            id: secret.id().as_uuid(),
            workflow_id: secret.workflow_id().as_uuid(),
            secret_hash: secret.secret_hash().as_str(),
            issued_by: ISSUED_BY.seal(secret.issued_by())?,
            created_at: secret.created_at(),
            secret_changed_at: secret.secret_changed_at(),
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

    /// Who issued a secret is written in the shape pinned here, and reads
    /// back.
    #[test]
    fn who_issued_it_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "account": {"User": "00000000-0000-0000-0000-000000000a11"},
            "person": "ann@acme.example"
        }});

        assert_eq!(ISSUED_BY.seal(&ann()).unwrap(), stored);
        assert_eq!(ISSUED_BY.open::<Human>(stored).unwrap(), ann());
    }
}
