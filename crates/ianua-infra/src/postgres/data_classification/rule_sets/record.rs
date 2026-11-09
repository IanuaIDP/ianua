//! A classification rule set as its row holds it: read back into the
//! aggregate, and written out from it. The rules are kept whole, in the
//! order they are evaluated.

use ianua_domain::domains::data_classification::classification::{
    ClassificationRule, ClassificationRuleSet, ClassificationRuleSetRow,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::ClassificationRuleSetId;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::envelope::Kept;

const RULES: Kept = Kept {
    entity: "classification rule set",
    column: "rules",
    shape: 1,
};

/// A rule set as it is read. The store's checked queries fill it.
pub(super) struct RuleSetRecord {
    pub(super) id: Uuid,
    pub(super) rules: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl RuleSetRecord {
    /// The rule set the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when a rule no longer reads,
    /// or the row breaks a rule the set keeps.
    pub(super) fn into_rule_set(
        self,
    ) -> Result<ClassificationRuleSet<ResolvedTenant>, DomainError> {
        ClassificationRuleSet::reconstitute(ClassificationRuleSetRow {
            id: ClassificationRuleSetId::from_uuid(self.id),
            rules: RULES.open::<Vec<ClassificationRule>>(self.rules)?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// A rule set's columns, as they are written.
pub(super) struct RuleSetColumns<'a> {
    pub(super) id: &'a Uuid,
    pub(super) rules: Value,
    pub(super) created_at: OffsetDateTime,
    pub(super) updated_at: OffsetDateTime,
}

impl<'a> RuleSetColumns<'a> {
    /// The columns `rule_set` is written to.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the rules cannot be
    /// written out as JSON.
    pub(super) fn of(
        rule_set: &'a ClassificationRuleSet<ResolvedTenant>,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            id: rule_set.id().as_uuid(),
            rules: RULES.seal(rule_set.rules())?,
            created_at: rule_set.created_at(),
            updated_at: rule_set.updated_at(),
        })
    }
}

#[cfg(test)]
mod tests {
    //! The shape each JSON column is stored in today. A row written now is
    //! read for years, so when one of these fails, the domain changed how
    //! it writes the value: raise the column's shape and add the step that
    //! reads the old one, rather than changing the shape pinned here.

    use serde_json::json;

    use super::*;

    /// The rules are written in the shape pinned here, in their order, and
    /// a row in that shape reads back the same.
    #[test]
    fn the_rules_are_stored_in_their_pinned_shape() {
        let stored = json!({"v": 1, "value": [
            {
                "id": "00000000-0000-0000-0000-000000000007",
                "field_path": "customer.email",
                "level": "Confidential",
                "redaction": "Mask"
            },
            {
                "id": "00000000-0000-0000-0000-000000000008",
                "field_path": "card.number",
                "level": "Restricted",
                "redaction": "Remove"
            }
        ]});

        let read: Vec<ClassificationRule> = RULES.open(stored.clone()).unwrap();

        assert_eq!(read[0].field_path().as_str(), "customer.email");
        assert_eq!(RULES.seal(&read).unwrap(), stored);
    }
}
