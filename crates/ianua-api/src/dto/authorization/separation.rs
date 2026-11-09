//! Separation-of-duties bodies: a pair of roles nobody in the tenant holds
//! together.

use ianua_app::use_cases::authorization::separation::AddRuleRequest;
use ianua_domain::domains::authorization::separation::SeparationRule;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{Label, RoleId, SeparationRuleId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::ApiError;

/// A separation-of-duties rule to declare.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AddSeparationRuleBody {
    /// What the rule is called, such as `payments-vs-approvals`.
    pub name: String,
    /// One of the two roles.
    pub first_role_id: Uuid,
    /// The other role, which nobody may hold beside the first.
    pub second_role_id: Uuid,
}

impl TryFrom<AddSeparationRuleBody> for AddRuleRequest {
    type Error = ApiError;

    fn try_from(body: AddSeparationRuleBody) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Label::new("name", body.name).map_err(ApiError::validation)?,
            first: RoleId::from_uuid(body.first_role_id),
            second: RoleId::from_uuid(body.second_role_id),
        })
    }
}

/// A separation-of-duties rule.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SeparationRuleResponse {
    /// The rule's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: SeparationRuleId,
    /// What the rule is called.
    pub name: String,
    /// One of the two roles.
    #[schema(value_type = String, format = Uuid)]
    pub first_role_id: RoleId,
    /// The other role.
    #[schema(value_type = String, format = Uuid)]
    pub second_role_id: RoleId,
    /// When the rule was declared.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<&SeparationRule<ResolvedTenant>> for SeparationRuleResponse {
    fn from(rule: &SeparationRule<ResolvedTenant>) -> Self {
        let (first, second) = rule.roles();
        Self {
            id: *rule.id(),
            name: rule.name().as_str().to_owned(),
            first_role_id: *first,
            second_role_id: *second,
            created_at: rule.created_at(),
        }
    }
}
