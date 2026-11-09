//! Review bodies: assigning a reviewer agent, its assignments, and what it
//! reads and answers at the review desk.

use ianua_app::context::AgentAssertion;
use ianua_app::use_cases::agents::reviews::desk::ReviewRequest;
use ianua_app::use_cases::agents::reviews::{
    AssignReviewerRequest, ReadEvidenceRequest, SubmitVerdictRequest,
};
use ianua_domain::domains::agents::oversight::review::{
    CitedEvidence, ReviewAssignment, VerdictKind, VerdictNote, VerdictParams,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::AgentId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::dto::agents::evidence::EvidenceParams;
use crate::dto::agents::principal::OwnerDto;
use crate::error::ApiError;

/// Request body for assigning a reviewer to an agent.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct AssignReviewerBody {
    /// The agent that will review the one in the path.
    pub reviewer_agent_id: Uuid,
}

impl AssignReviewerBody {
    /// The assignment of this reviewer to `reviewed`.
    #[must_use]
    pub(crate) fn reviewing(&self, reviewed: AgentId) -> AssignReviewerRequest {
        AssignReviewerRequest {
            reviewer: AgentId::from_uuid(self.reviewer_agent_id),
            reviewed,
        }
    }
}

/// Who oversees an agent and when that oversight began or ended.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewAssignmentResponse {
    /// The assignment.
    pub id: Uuid,
    /// The reviewing agent.
    pub reviewer_agent_id: Uuid,
    /// The actor whose activity the reviewer oversees.
    pub reviewed_agent_id: Uuid,
    /// The person who assigned it.
    pub assigned_by: OwnerDto,
    /// When.
    #[serde(with = "time::serde::rfc3339")]
    pub assigned_at: OffsetDateTime,
    /// When a person ended it, if they did.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub ended_at: Option<OffsetDateTime>,
}

impl From<&ReviewAssignment<ResolvedTenant>> for ReviewAssignmentResponse {
    fn from(assignment: &ReviewAssignment<ResolvedTenant>) -> Self {
        Self {
            id: *assignment.id().as_uuid(),
            reviewer_agent_id: *assignment.reviewer().as_uuid(),
            reviewed_agent_id: *assignment.reviewed().as_uuid(),
            assigned_by: OwnerDto::from_principal(assignment.assigned_by()),
            assigned_at: assignment.assigned_at(),
            ended_at: assignment.ended_at(),
        }
    }
}

impl EvidenceParams {
    /// The page of `reviewed`'s evidence the reviewer `reviewer` asks for.
    #[must_use]
    pub(crate) fn for_reviewer(
        &self,
        reviewer: AgentAssertion,
        reviewed: AgentId,
    ) -> ReadEvidenceRequest {
        ReadEvidenceRequest {
            review: ReviewRequest { reviewer, reviewed },
            after_seq: self.after_seq,
            limit: self.limit,
        }
    }
}

/// A reviewer's verdict.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct VerdictBody {
    /// `concern` or `containment_requested`.
    pub kind: String,
    /// What the reviewer concluded, in its own words.
    pub note: String,
    /// The evidence records (`seq`) the verdict rests on, at least one.
    pub cited_seqs: Vec<i64>,
}

impl VerdictBody {
    /// The verdict `reviewer` gives about `reviewed`.
    ///
    /// # Errors
    ///
    /// - A validation error for an unknown kind, an empty or overlong note,
    ///   or no cited record.
    pub(crate) fn into_request(
        self,
        reviewer: AgentAssertion,
        reviewed: AgentId,
    ) -> Result<SubmitVerdictRequest, ApiError> {
        Ok(SubmitVerdictRequest {
            review: ReviewRequest { reviewer, reviewed },
            verdict: VerdictParams {
                kind: VerdictKind::parse(&self.kind).map_err(ApiError::validation)?,
                cited: CitedEvidence::new(self.cited_seqs).map_err(ApiError::validation)?,
                note: VerdictNote::new(self.note).map_err(ApiError::validation)?,
            },
        })
    }
}
