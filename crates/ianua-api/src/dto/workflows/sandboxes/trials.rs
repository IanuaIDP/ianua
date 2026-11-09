//! Sandbox trials on the wire: the body that tries a version on sample
//! input, and a trial with what the code gave back or why it failed.

use ianua_app::use_cases::workflows::sandboxes::trying::{GetTrialRequest, StartTrialRequest};
use ianua_domain::domains::workflows::execution::step::{CodeOutcome, StepFailure};
use ianua_domain::domains::workflows::sandbox::trial::{SandboxTrial, TrialState};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{SandboxId, SandboxTrialId, SandboxVersionId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::workflows::data::{flow_data, json_of, person_label};
use crate::dto::workflows::executions::StepFailureResponse;
use crate::error::ApiError;

/// The read asked for: trial `trial_id` of sandbox `sandbox_id`.
#[must_use]
pub(crate) fn trial_reading(sandbox_id: SandboxId, trial_id: SandboxTrialId) -> GetTrialRequest {
    GetTrialRequest {
        sandbox_id,
        trial_id,
    }
}

/// Request body for trying a sandbox version on sample input.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct StartTrialBody {
    /// What the code is given, as a code step hands it its mapped fields:
    /// any JSON value, usually an object.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub input: Value,
}

impl StartTrialBody {
    /// Trying version `version_id` of `sandbox_id` on this input.
    ///
    /// # Errors
    ///
    /// - `422` when the input is no data a workflow holds.
    pub(crate) fn request(
        self,
        sandbox_id: SandboxId,
        version_id: SandboxVersionId,
    ) -> Result<StartTrialRequest, ApiError> {
        Ok(StartTrialRequest {
            sandbox_id,
            version_id,
            input: flow_data(&self.input)?,
        })
    }
}

/// One trial of a sandbox version.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TrialResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The sandbox whose version it tries.
    pub sandbox_id: Uuid,
    /// The version it tries.
    pub version_id: Uuid,
    /// `running` until a worker ran it, then `succeeded` or `failed`.
    pub status: String,
    /// What the code is given.
    #[schema(value_type = Object)]
    pub input: Value,
    /// What the code gave back, once it succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub output: Option<Value>,
    /// Why it failed, once it failed: `code_raised` with the end of its
    /// error, `code_timed_out`, `code_out_of_memory`,
    /// `code_output_unreadable` or `code_not_run`, as a code step fails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<StepFailureResponse>,
    /// The person who started it, as `<kind>:<uuid>`.
    pub started_by: String,
    /// When it was started.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it last changed: when it ended, once it has.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<SandboxTrial<ResolvedTenant>> for TrialResponse {
    fn from(trial: SandboxTrial<ResolvedTenant>) -> Self {
        let started = Self {
            id: *trial.id().as_uuid(),
            sandbox_id: *trial.sandbox_id().as_uuid(),
            version_id: *trial.version_id().as_uuid(),
            status: "running".to_owned(),
            input: json_of(trial.input()),
            output: None,
            failure: None,
            started_by: person_label(trial.started_by()),
            created_at: trial.created_at(),
            updated_at: trial.updated_at(),
        };
        match trial.state() {
            TrialState::Running => started,
            TrialState::Ended(CodeOutcome::Succeeded(output)) => Self {
                status: "succeeded".to_owned(),
                output: Some(json_of(output)),
                ..started
            },
            TrialState::Ended(CodeOutcome::Failed(failure)) => {
                let failure = StepFailure::from(failure.clone());
                Self {
                    status: "failed".to_owned(),
                    failure: Some(StepFailureResponse::from(&failure)),
                    ..started
                }
            }
        }
    }
}
