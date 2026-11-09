//! Clearance bodies: the rules that clear a tenant's people for
//! confidential or restricted data by an app permission they hold.

use ianua_app::use_cases::authorization::clearance::{AddRuleRequest, ChangeRuleRequest};
use ianua_domain::domains::authorization::clearance::{ClearanceRule, ClearanceRules};
use ianua_domain::domains::authorization::permission::CustomPermission;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// A clearance rule to add: holding `permission` clears for data up to
/// `up_to`.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AddClearanceRuleBody {
    /// The app permission, as `{ "resource", "action" }`.
    #[schema(value_type = Object)]
    pub permission: CustomPermission,
    /// `Confidential` or `Restricted`.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub up_to: DataClassLevel,
}

impl From<AddClearanceRuleBody> for AddRuleRequest {
    fn from(body: AddClearanceRuleBody) -> Self {
        Self {
            permission: body.permission,
            up_to: body.up_to,
        }
    }
}

/// The level a clearance rule clears for.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeClearanceRuleBody {
    /// `Confidential` or `Restricted`.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub up_to: DataClassLevel,
}

impl ChangeClearanceRuleBody {
    /// Clearing holders of `permission` up to the level this body gives.
    #[must_use]
    pub(crate) fn request(&self, permission: CustomPermission) -> ChangeRuleRequest {
        ChangeRuleRequest {
            permission,
            up_to: self.up_to,
        }
    }
}

/// Maps an app permission to the highest data class its holders may access.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ClearanceRuleResponse {
    /// The app permission that clears.
    #[schema(value_type = Object)]
    pub permission: CustomPermission,
    /// The highest data class its holders are cleared for.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub up_to: DataClassLevel,
}

impl From<&ClearanceRule> for ClearanceRuleResponse {
    fn from(rule: &ClearanceRule) -> Self {
        Self {
            permission: rule.permission().clone(),
            up_to: rule.up_to(),
        }
    }
}

/// The tenant's clearance rules.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ClearanceRulesResponse {
    /// Every rule. Empty when nobody wrote one: everyone in the tenant is
    /// then cleared for internal data only, unless a built-in permission
    /// clears them further.
    pub rules: Vec<ClearanceRuleResponse>,
    /// When the rules last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<&ClearanceRules<ResolvedTenant>> for ClearanceRulesResponse {
    fn from(rules: &ClearanceRules<ResolvedTenant>) -> Self {
        Self {
            rules: rules
                .rules()
                .iter()
                .map(ClearanceRuleResponse::from)
                .collect(),
            updated_at: rules.updated_at(),
        }
    }
}
