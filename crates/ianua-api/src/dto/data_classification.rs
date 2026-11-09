//! Data classification bodies: a tenant's field-level sensitivity rules.

use ianua_app::use_cases::data_classification::{
    AddClassificationRuleRequest, ChangeClassificationRuleRequest,
};
use ianua_domain::domains::data_classification::classification::{
    ClassificationRule, ClassificationRuleSet, RedactionStrategy,
};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::{ClassificationRuleId, FieldPath};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;

/// Request body for adding a classification rule.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AddRuleBody {
    /// The dot-notation path of the field, such as `user.ssn`.
    pub field_path: String,
    /// How sensitive the field is: `Public`, `Internal`, `Confidential` or
    /// `Restricted`.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub level: DataClassLevel,
    /// What the proxy does to the field: `Remove`, `Mask` or `Hash`.
    #[schema(schema_with = crate::dto::schemas::redaction_strategy)]
    pub redaction: RedactionStrategy,
}

impl TryFrom<&AddRuleBody> for AddClassificationRuleRequest {
    type Error = ApiError;

    fn try_from(body: &AddRuleBody) -> Result<Self, Self::Error> {
        Ok(Self {
            field_path: FieldPath::new(body.field_path.as_str()).map_err(ApiError::validation)?,
            level: body.level,
            redaction: body.redaction.clone(),
        })
    }
}

/// Request body for changing a classification rule. Both fields are
/// required: the rule says the two together.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeRuleBody {
    /// How sensitive the field is from now on: `Public`, `Internal`,
    /// `Confidential` or `Restricted`.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub level: DataClassLevel,
    /// What the proxy does to the field from now on: `Remove`, `Mask` or
    /// `Hash`.
    #[schema(schema_with = crate::dto::schemas::redaction_strategy)]
    pub redaction: RedactionStrategy,
}

impl ChangeRuleBody {
    /// The change to `rule_id` this body asks for.
    #[must_use]
    pub(crate) fn change_of(
        self,
        rule_id: ClassificationRuleId,
    ) -> ChangeClassificationRuleRequest {
        ChangeClassificationRuleRequest {
            rule_id,
            level: self.level,
            redaction: self.redaction,
        }
    }
}

/// A field's sensitivity and the redaction the proxy applies to it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ClassificationRuleResponse {
    /// Unique identifier, which changing or removing the rule names.
    pub id: Uuid,
    /// The dot-notation path of the field.
    pub field_path: String,
    /// How sensitive the field is.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub level: DataClassLevel,
    /// What the proxy does to the field.
    #[schema(schema_with = crate::dto::schemas::redaction_strategy)]
    pub redaction: RedactionStrategy,
}

impl ClassificationRuleResponse {
    /// The rule `body` added, under `id`.
    #[must_use]
    pub(crate) fn added(id: ClassificationRuleId, body: AddRuleBody) -> Self {
        Self {
            id: *id.as_uuid(),
            field_path: body.field_path,
            level: body.level,
            redaction: body.redaction,
        }
    }
}

impl From<&ClassificationRule> for ClassificationRuleResponse {
    fn from(r: &ClassificationRule) -> Self {
        Self {
            id: *r.id().as_uuid(),
            field_path: r.field_path().as_str().to_owned(),
            level: r.level(),
            redaction: r.redaction().clone(),
        }
    }
}

/// A tenant's classification rule set.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ClassificationResponse {
    /// The rule set, or `null` until the first rule is added.
    pub id: Option<Uuid>,
    /// Every rule, empty when the tenant has classified nothing yet.
    pub rules: Vec<ClassificationRuleResponse>,
}

impl From<Option<ClassificationRuleSet<ResolvedTenant>>> for ClassificationResponse {
    fn from(rule_set: Option<ClassificationRuleSet<ResolvedTenant>>) -> Self {
        let Some(rule_set) = rule_set else {
            return Self {
                id: None,
                rules: Vec::new(),
            };
        };
        Self {
            id: Some(*rule_set.id().as_uuid()),
            rules: rule_set
                .rules()
                .iter()
                .map(ClassificationRuleResponse::from)
                .collect(),
        }
    }
}
