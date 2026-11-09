//! A separation rule as its row holds it: read back into the aggregate.

use ianua_domain::domains::authorization::separation::{SeparationRule, SeparationRuleRow};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{Label, RoleId, SeparationRuleId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::Stored;

const SEPARATION_RULE: Stored = Stored("separation rule");

/// A separation rule as it is read. The store's checked queries fill it.
pub(super) struct SeparationRuleRecord {
    pub(super) id: Uuid,
    pub(super) name: String,
    pub(super) first_role_id: Uuid,
    pub(super) second_role_id: Uuid,
    pub(super) created_at: OffsetDateTime,
}

impl SeparationRuleRecord {
    /// The rule the record holds, rebuilt through the domain's checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the name no longer passes
    /// its rules, or the rule keeps a role apart from itself.
    pub(super) fn into_rule(self) -> Result<SeparationRule<ResolvedTenant>, DomainError> {
        SeparationRule::reconstitute(SeparationRuleRow {
            id: SeparationRuleId::from_uuid(self.id),
            name: SEPARATION_RULE.value("name", Label::new("name", self.name))?,
            first: RoleId::from_uuid(self.first_role_id),
            second: RoleId::from_uuid(self.second_role_id),
            created_at: self.created_at,
        })
    }
}
