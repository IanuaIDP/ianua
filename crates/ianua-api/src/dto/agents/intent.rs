//! Intent bodies: compiling a stated purpose into the scope it implies, and
//! lowering a stopped agent's data mark.

use ianua_app::use_cases::agents::intent::{CompileRequest, CompiledOutcome, ResetExposureRequest};
use ianua_domain::domains::agents::authority::intent::{DriftPolicy, IntentStatement};
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::types::{AgentId, Label};
use serde::{Deserialize, Serialize};

use crate::dto::agents::capabilities::CapabilitySetDto;
use crate::dto::agents::evidence::hex;
use crate::error::ApiError;

/// The longest reason a person may give for lowering a mark.
const MAX_REASON_LENGTH: usize = 300;

/// Request to compile a stated intent into a narrowed scope (dry-run).
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CompileIntentBody {
    /// The natural-language intent the token is for.
    pub intent: String,
    /// The capabilities asked for: the ceiling the intent narrows within.
    #[serde(default)]
    pub requested: CapabilitySetDto,
}

impl CompileIntentBody {
    /// The compilation for agent `agent_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - A validation error for an empty intent or capabilities that are
    ///   not valid.
    pub(crate) fn into_request(self, agent_id: AgentId) -> Result<CompileRequest, ApiError> {
        Ok(CompileRequest {
            agent_id,
            intent: IntentStatement::new(self.intent).map_err(ApiError::validation)?,
            requested: self.requested.to_domain()?,
            drift_policy: DriftPolicy::Off,
        })
    }
}

/// The narrowed scope and the intent's digest.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CompileIntentResponse {
    /// The narrowed capability set, never more than was asked for.
    pub scope: CapabilitySetDto,
    /// Lowercase-hex fingerprint of the intent, for drift monitoring.
    pub digest: String,
}

impl From<CompiledOutcome> for CompileIntentResponse {
    fn from(outcome: CompiledOutcome) -> Self {
        Self {
            scope: CapabilitySetDto::from(&outcome.scope),
            digest: hex(outcome.binding.digest().as_bytes()),
        }
    }
}

/// Request body for lowering a stopped agent's data mark.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ResetExposureBody {
    /// The mark to lower it to: `Public`, `Internal`, `Confidential` or
    /// `Restricted`.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub to: DataClassLevel,
    /// Why, for the record (at most 300 characters).
    pub reason: String,
}

impl ResetExposureBody {
    /// The reset of agent `agent_id` this body asks for.
    ///
    /// # Errors
    ///
    /// - A validation error for an empty or overlong reason.
    pub(crate) fn into_request(self, agent_id: AgentId) -> Result<ResetExposureRequest, ApiError> {
        Ok(ResetExposureRequest {
            agent_id,
            to: self.to,
            reason: Label::with_max_length("reason", self.reason, MAX_REASON_LENGTH)
                .map_err(ApiError::validation)?,
        })
    }
}
