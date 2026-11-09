//! Approval bodies: an action held for a person, opening one by hand, what
//! ianua computed about it for the person deciding, and the answer to the
//! gateway's sealed questions.

use axum::response::{IntoResponse, Response};
use ianua_app::ports::agents::ApprovalWireAnswer;
use ianua_app::services::gateway_relay::{AnswerSeal, RelayReply};
use ianua_app::use_cases::agents::approvals::{Facts, HeldCall, RequestRequest};
use ianua_domain::domains::agents::channels::channel::AgentChannel;
use ianua_domain::domains::agents::execution::tool::AgentTool;
use ianua_domain::domains::agents::oversight::approval::{ApprovalOrigin, ApprovalRequest};
use ianua_domain::domains::agents::oversight::approval_status::ApprovalStatus;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::shared::model::aggregate::Aggregate as _;
use ianua_domain::types::{AgentId, DelegationId, HttpMethod, PrincipalRef, Seconds};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::delegation::UnknownFields;
use crate::dto::agents::principal::OwnerDto;
use crate::error::{ApiError, log_error, status_and_code};
use crate::response::relay::SealedAnswer;

/// An approval status's wire name.
fn status_name(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Expired => "expired",
        ApprovalStatus::Consumed => "consumed",
        ApprovalStatus::Withdrawn => "withdrawn",
    }
}

/// The approval status a wire name names, in any case.
fn status_named(value: &str) -> Result<ApprovalStatus, ApiError> {
    match value.to_ascii_lowercase().as_str() {
        "pending" => Ok(ApprovalStatus::Pending),
        "approved" => Ok(ApprovalStatus::Approved),
        "denied" => Ok(ApprovalStatus::Denied),
        "expired" => Ok(ApprovalStatus::Expired),
        "consumed" => Ok(ApprovalStatus::Consumed),
        "withdrawn" => Ok(ApprovalStatus::Withdrawn),
        _ => Err(ApiError::validation(message!(
            "api-unknown-approval-status-expected-one-of",
            format!(
                "unknown approval status: {value} \
             (expected one of: pending, approved, denied, expired, consumed, withdrawn)"
            )
        ))),
    }
}

/// Query parameters for listing an agent's approvals.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ApprovalQueryParams {
    /// Narrows to one lifecycle state (`pending`, `approved`, `denied`,
    /// `expired`, `consumed`, `withdrawn`). Left out for the full history,
    /// resolved requests included.
    pub status: Option<String>,
}

impl ApprovalQueryParams {
    /// The state to narrow to, if one was asked for.
    ///
    /// # Errors
    ///
    /// - A validation error when `status` names no state.
    pub(crate) fn status(&self) -> Result<Option<ApprovalStatus>, ApiError> {
        self.status.as_deref().map(status_named).transpose()
    }
}

/// Request to open a person's approval for an agent's call.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RequestApprovalBody {
    /// The delegation supplying the authority the call uses.
    pub delegation_id: Uuid,
    /// The HTTP method of the paused call, such as `DELETE`. With the
    /// target it decides how many approvers the request needs.
    pub method: String,
    /// The path of the paused call, with its query, such as `/orders/1`.
    pub target: String,
    /// The decision window in seconds, at most a day.
    pub ttl_seconds: u32,
    /// Fields the body does not know, refused.
    #[serde(flatten)]
    #[schema(ignore)]
    pub unknown: UnknownFields,
}

impl RequestApprovalBody {
    /// The request for agent `agent_id` this body opens.
    ///
    /// # Errors
    ///
    /// - A validation error for an unknown field, or when `method` is not
    ///   an HTTP method.
    pub(crate) fn into_request(self, agent_id: AgentId) -> Result<RequestRequest, ApiError> {
        self.unknown.ensure_none()?;
        let method = HttpMethod::parse(&self.method).ok_or_else(|| {
            ApiError::validation(message!(
                "api-unknown-method",
                format!("unknown method: {}", self.method)
            ))
        })?;
        Ok(RequestRequest {
            agent_id,
            delegation_id: DelegationId::from_uuid(self.delegation_id),
            method,
            target: self.target,
            ttl_seconds: Seconds::new(self.ttl_seconds),
        })
    }
}

/// An action held for a person's approval.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalResponse {
    /// Approval identifier.
    pub id: Uuid,
    /// The agent whose action is paused.
    pub agent_id: Uuid,
    /// The delegation supplying the authority. `null` for a request a run
    /// raised while calling tools directly, which uses no delegation.
    pub delegation_id: Option<Uuid>,
    /// The run that paused and raised this request. `null` for one opened
    /// by hand against a delegation.
    pub run_id: Option<Uuid>,
    /// The action class held (`read`, `write`, `delete`, `configure`,
    /// `communicate`, `financial`, `admin`). `null` when no single class
    /// was declared.
    pub purpose: Option<String>,
    /// The tool the run is holding, when a run raised this request.
    pub pending_tool: Option<String>,
    /// The arguments that tool was called with, verbatim, so an approver
    /// sees exactly what they sign off.
    pub pending_arguments: Option<String>,
    /// The call held.
    pub action: String,
    /// Status (`pending`, `approved`, `denied`, `expired`, `consumed`,
    /// `withdrawn`).
    pub status: String,
    /// Who opened the request, or started the run that raised it. They are
    /// refused as its approver: an approval is a second pair of eyes.
    pub requested_by: OwnerDto,
    /// Who decided, once a decision was made. `null` while pending, and for
    /// a request that lapsed undecided.
    pub decided_by: Option<OwnerDto>,
    /// When that decision was made. Set exactly when `decided_by` is.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub decided_at: Option<OffsetDateTime>,
    /// When the request was opened.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the decision window closes.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    /// How many different people must approve: two for a delete,
    /// configuration, financial or admin action, or one whose class is
    /// unknown; one otherwise. Each of the two also answers a fresh second
    /// factor.
    pub approvers_needed: u8,
    /// Who gave the first of two approvals, while the second is awaited.
    pub first_approved_by: Option<OwnerDto>,
    /// When that first approval was given.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub first_approved_at: Option<OffsetDateTime>,
}

impl From<&ApprovalRequest<ResolvedTenant>> for ApprovalResponse {
    fn from(approval: &ApprovalRequest<ResolvedTenant>) -> Self {
        let first = approval.first_approval();
        Self {
            id: *approval.id().as_uuid(),
            agent_id: *approval.agent_id().as_uuid(),
            delegation_id: approval.delegation_id().delegation().map(|d| *d.as_uuid()),
            run_id: approval.run_id().map(|r| *r.as_uuid()),
            purpose: approval
                .action_class()
                .stored()
                .map(|class| class.as_str().to_owned()),
            pending_tool: approval.pending_call().map(|c| c.tool().to_owned()),
            pending_arguments: approval.pending_call().map(|c| c.arguments().to_owned()),
            action: approval.action().as_str().to_owned(),
            status: status_name(approval.status()).to_owned(),
            requested_by: OwnerDto::from_principal(&requester(approval.origin())),
            decided_by: approval
                .decided_by()
                .map(|by| OwnerDto::from_principal(&by)),
            decided_at: approval.decided_at(),
            created_at: approval.created_at(),
            expires_at: approval.expires_at(),
            approvers_needed: approval.approvers_needed(),
            first_approved_by: first.map(|f| OwnerDto::from_human(&f.by)),
            first_approved_at: first.map(|f| f.at),
        }
    }
}

/// Who asked for the approval: whoever opened it, or started the run that
/// raised it.
fn requester(origin: &ApprovalOrigin) -> PrincipalRef {
    match origin {
        ApprovalOrigin::Opened(initiator) => initiator.principal(),
        ApprovalOrigin::Run(run) => run.started_by().principal(),
    }
}

/// The call a run is holding.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct HeldCallDto {
    /// The tool the model asked for.
    pub tool: String,
    /// Its arguments, verbatim: exactly what will run.
    pub arguments: String,
    /// Whether the arguments carry invisible characters (bidirectional
    /// overrides, zero-width or tag characters). They are shown, not
    /// removed: removing them would misstate what runs.
    pub arguments_hide_characters: bool,
    /// The HTTP method the registered tool calls, when it is registered.
    pub method: Option<String>,
    /// The path the registered tool calls.
    pub path: Option<String>,
    /// The tool's action class.
    pub action_class: Option<String>,
    /// The most sensitive data the tool handles.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub data_class: Option<DataClassLevel>,
}

impl From<&HeldCall> for HeldCallDto {
    fn from(call: &HeldCall) -> Self {
        let tool = call.registered.as_ref();
        Self {
            tool: call.tool.clone(),
            arguments: call.arguments.clone(),
            arguments_hide_characters: call.arguments_hide_characters,
            method: tool.map(|t| t.method().as_str().to_owned()),
            path: tool.map(|t| t.path().as_str().to_owned()),
            action_class: tool.map(|t| t.action_class().as_str().to_owned()),
            data_class: tool.map(AgentTool::classification),
        }
    }
}

/// A channel into the agent.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ChannelInDto {
    /// The channel.
    pub id: Uuid,
    /// The agent it carries from.
    pub sender_agent_id: Uuid,
    /// `topics` or `resource`.
    pub scope_kind: String,
    /// The topic pattern or resource.
    pub scope: String,
    /// The most sensitive data it may carry.
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub max_class: DataClassLevel,
}

impl From<&AgentChannel<ResolvedTenant>> for ChannelInDto {
    fn from(channel: &AgentChannel<ResolvedTenant>) -> Self {
        Self {
            id: *channel.id().as_uuid(),
            sender_agent_id: *channel.sender().as_uuid(),
            scope_kind: channel.scope().kind().to_owned(),
            scope: channel.scope().as_str().to_owned(),
            max_class: channel.max_class(),
        }
    }
}

/// What ianua computed about a paused action, then the agent's own claim.
///
/// Read the facts first. The claim is the agent's summary of what it wants
/// to do, written by a model: it can say anything.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalFactsResponse {
    /// The request being decided.
    pub approval: ApprovalResponse,
    /// The exact call a run is holding, when a run raised the request.
    pub call: Option<HeldCallDto>,
    /// The most sensitive data the agent has touched (`Public` to
    /// `Restricted`).
    #[schema(schema_with = crate::dto::schemas::data_class_level)]
    pub agent_exposure: DataClassLevel,
    /// Whom the agent acts for, nearest first.
    pub on_behalf_of: Vec<OwnerDto>,
    /// Requests and messages refused to the agent in the recent window.
    pub recent_refusals: u64,
    /// Times the agent drifted from its declared intent in the recent
    /// window.
    pub recent_drifts: u64,
    /// Times the agent met another agent at one path in the recent window.
    pub recent_meetings: u64,
    /// Open channels other agents' data could have reached it through.
    pub channels_in: Vec<ChannelInDto>,
    /// The agent's own summary, invisible characters stripped. A claim, not
    /// a fact.
    pub agent_claim: String,
}

impl From<&Facts> for ApprovalFactsResponse {
    fn from(facts: &Facts) -> Self {
        Self {
            approval: ApprovalResponse::from(&facts.approval),
            call: facts.call.as_ref().map(HeldCallDto::from),
            agent_exposure: facts.exposure,
            on_behalf_of: facts
                .on_behalf_of
                .iter()
                .map(OwnerDto::from_principal)
                .collect(),
            recent_refusals: facts.recent.refusals,
            recent_drifts: facts.recent.drifts,
            recent_meetings: facts.recent.meetings,
            channels_in: facts.channels_in.iter().map(ChannelInDto::from).collect(),
            agent_claim: facts.agent_claim.clone(),
        }
    }
}

/// The answer to a question the gateway relayed about an approval.
///
/// Always `200` with a typed answer, sealed for the question it answers.
/// Every error, an unsealed, stale or repeated question included, is
/// answered as a refusal, which the gateway refuses the action on; why is
/// in the API's own log, never on the wire. A question that never opened
/// gets its refusal unsealed, which the gateway takes for no answer and
/// refuses the action on all the same.
pub(crate) struct RelayedApprovalAnswer {
    answer: ApprovalWireAnswer,
    seal: Option<AnswerSeal>,
}

impl From<RelayReply<ApprovalWireAnswer>> for RelayedApprovalAnswer {
    fn from(reply: RelayReply<ApprovalWireAnswer>) -> Self {
        let answer = reply.answer.unwrap_or_else(|refused| {
            let (status, _) = status_and_code(&refused);
            log_error(&refused, status);
            ApprovalWireAnswer::Refused
        });
        Self {
            answer,
            seal: reply.seal,
        }
    }
}

impl IntoResponse for RelayedApprovalAnswer {
    fn into_response(self) -> Response {
        SealedAnswer::new(self.answer, self.seal).into_response()
    }
}

#[cfg(test)]
mod tests {
    use ianua_app::error::AppError;

    use super::*;

    /// Unauthenticated, missing and forbidden relay results all map to the
    /// same refused answer.
    #[test]
    fn every_error_is_answered_as_a_refusal() {
        for error in [
            AppError::Unauthenticated,
            AppError::NotFound("delegation".to_owned().into()),
            AppError::Forbidden("revoked".to_owned().into()),
        ] {
            let relayed = RelayedApprovalAnswer::from(RelayReply {
                answer: Err(error),
                seal: None,
            });

            assert!(matches!(relayed.answer, ApprovalWireAnswer::Refused));
        }
    }

    /// The request `body` opens, for a new agent.
    fn opened(body: serde_json::Value) -> Result<RequestRequest, ApiError> {
        let body: RequestApprovalBody = serde_json::from_value(body).unwrap();
        body.into_request(AgentId::new())
    }

    /// Ann opens an approval for the exact call her agent waits on.
    #[test]
    fn an_approval_naming_known_fields_is_opened() {
        let result = opened(serde_json::json!({
            "delegation_id": Uuid::now_v7(),
            "method": "GET",
            "target": "/reports/weekly",
            "ttl_seconds": 900
        }));

        assert!(result.is_ok_and(|request| request.target == "/reports/weekly"));
    }

    /// An unsupported approver-count field causes deserialization to fail.
    #[test]
    fn an_approval_naming_an_unknown_field_is_refused() {
        let result = opened(serde_json::json!({
            "delegation_id": Uuid::now_v7(),
            "method": "GET",
            "target": "/reports/weekly",
            "ttl_seconds": 900,
            "approvers_needed": 2
        }));

        assert!(result.is_err());
    }
}
