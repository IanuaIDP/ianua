//! A raised view of an operation's risk as its row holds it: read back
//! into the aggregate, and written out from it.

use ianua_domain::domains::workflows::integration::risk_override::{
    OperationRiskOverride, OperationRiskOverrideRow,
};
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationKey};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{ActionClass, DeclaredAction, OperationRiskOverrideId};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;
use crate::postgres::foundation::stored::Stored;

const RISK: Stored = Stored("operation risk override");

const RAISED_BY: Kept = Kept {
    entity: RISK.0,
    column: "raised_by",
    shape: 1,
};

/// An override as it is read. The store's checked queries fill it.
pub(super) struct RiskRecord {
    pub(super) id: Uuid,
    pub(super) integration: String,
    pub(super) operation: String,
    pub(super) effect: Option<String>,
    pub(super) raised_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl RiskRecord {
    /// The override the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a value no longer passes
    /// its rules, a class is unknown, or the row breaks a rule the override
    /// keeps.
    pub(super) fn into_override(
        self,
    ) -> Result<OperationRiskOverride<ResolvedTenant>, DomainError> {
        let class = self
            .effect
            .as_deref()
            .map(ActionClass::from_stored)
            .transpose()?;
        OperationRiskOverride::reconstitute(OperationRiskOverrideRow {
            id: OperationRiskOverrideId::from_uuid(self.id),
            integration: RISK.value("integration", IntegrationKey::new(self.integration))?,
            operation: RISK.value("operation", OperationKey::new(self.operation))?,
            effect: DeclaredAction::from_stored(class),
            raised_by: RAISED_BY.open(self.raised_by)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// An override's columns, as they are written.
pub(super) struct RiskColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) integration: &'a str,
    pub(super) operation: &'a str,
    pub(super) effect: Option<&'static str>,
    pub(super) raised_by: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> RiskColumns<'a> {
    /// The columns `risk` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when who raised it cannot be
    /// written out.
    pub(super) fn of(risk: &'a OperationRiskOverride<ResolvedTenant>) -> Result<Self, DomainError> {
        Ok(Self {
            id: risk.id().as_uuid(),
            integration: risk.integration().as_str(),
            operation: risk.operation().as_str(),
            effect: risk.effect().stored().map(ActionClass::as_str),
            raised_by: RAISED_BY.seal(risk.raised_by())?,
            created_at: risk.created_at(),
            updated_at: risk.updated_at(),
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

    /// Who raised an override is written in the shape pinned here, and
    /// reads back.
    #[test]
    fn who_raised_it_is_stored_in_its_pinned_shape() {
        let stored = json!({"v": 1, "value": {
            "account": {"User": "00000000-0000-0000-0000-000000000a11"},
            "person": "ann@acme.example"
        }});

        assert_eq!(RAISED_BY.seal(&ann()).unwrap(), stored);
        assert_eq!(RAISED_BY.open::<Human>(stored).unwrap(), ann());
    }
}
