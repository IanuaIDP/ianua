//! The tenant's raised operation risks on the wire.

use ianua_app::use_cases::workflows::catalog::risk_overrides::{
    ChangeRiskRequest, RaiseRiskRequest,
};
use ianua_domain::domains::workflows::integration::risk_override::OperationRiskOverride;
use ianua_domain::domains::workflows::integration::{IntegrationKey, OperationKey};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::aggregate::Aggregate;
use ianua_domain::types::OperationRiskOverrideId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::workflows::data::{declared_action, person_label};
use crate::error::ApiError;

/// One operation the tenant treats as riskier than its integration says.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RiskResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The integration offering the operation.
    pub integration: String,
    /// The catalog action receiving the tenant's stricter classification.
    pub operation: String,
    /// What it counts as: `undeclared` or an action class.
    pub effect: String,
    /// Who raised it, as `<kind>:<uuid>`.
    pub raised_by: String,
    /// When it was raised.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<OperationRiskOverride<ResolvedTenant>> for RiskResponse {
    fn from(risk: OperationRiskOverride<ResolvedTenant>) -> Self {
        Self {
            id: *risk.id().as_uuid(),
            integration: risk.integration().as_str().to_owned(),
            operation: risk.operation().as_str().to_owned(),
            effect: risk.effect().as_str().to_owned(),
            raised_by: person_label(risk.raised_by()),
            created_at: Aggregate::created_at(&risk),
            updated_at: Aggregate::updated_at(&risk),
        }
    }
}

/// Request body for raising an operation's risk.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RaiseRiskBody {
    /// The integration offering it, such as `google-sheets`.
    pub integration: String,
    /// The operation, such as `append-row`.
    pub operation: String,
    /// What it counts as from now on: `undeclared` or a high-risk action
    /// class.
    pub effect: String,
}

impl TryFrom<RaiseRiskBody> for RaiseRiskRequest {
    type Error = ApiError;

    fn try_from(body: RaiseRiskBody) -> Result<Self, ApiError> {
        Ok(Self {
            integration: IntegrationKey::new(body.integration).map_err(ApiError::validation)?,
            operation: OperationKey::new(body.operation).map_err(ApiError::validation)?,
            effect: declared_action(&body.effect)?,
        })
    }
}

/// Request body for changing what a raised operation counts as.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ChangeRiskBody {
    /// What it counts as from now on: `undeclared` or a high-risk action
    /// class.
    pub effect: String,
}

impl ChangeRiskBody {
    /// The change to make to `override_id`.
    ///
    /// # Errors
    ///
    /// - `422` when the effect names no class.
    pub(crate) fn request(
        &self,
        override_id: OperationRiskOverrideId,
    ) -> Result<ChangeRiskRequest, ApiError> {
        Ok(ChangeRiskRequest {
            override_id,
            effect: declared_action(&self.effect)?,
        })
    }
}
