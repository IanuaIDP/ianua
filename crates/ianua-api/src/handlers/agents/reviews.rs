//! Agent review handlers: people assign reviewer agents and end their
//! assignments; reviewer agents read the evidence of the agent they review
//! and give advisory verdicts.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::agents::reviews::EndRequest;
use ianua_assembly::agents::AgentState;

use crate::dto::agents::evidence::{EvidencePageResponse, EvidenceParams};
use crate::dto::agents::reviews::{AssignReviewerBody, ReviewAssignmentResponse, VerdictBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::agents::ReviewerAgent;
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::agents::{AgentPath, AgentReviewPath};
use crate::extractors::query::Query;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/reviewers",
    tag = "Agents",
    request_body = AssignReviewerBody,
    responses(
        (status = 201, description = "Assigned", body = ReviewAssignmentResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or the reviewer holds capabilities", body = ErrorBody),
        (status = 404, description = "An agent was not found", body = ErrorBody),
        (status = 422, description = "The two agents are not independent", body = ErrorBody)
    )
)]
/// Assign a reviewer to an agent
///
/// Sets `reviewer_agent_id` to watch the agent in the path. Refused
/// (`422`) unless the two answer to different people (the owners and every
/// person in the lineage of their live delegations differ) and share no
/// delegation; refused (`403`) while the reviewer holds any capability. A
/// reviewer reads evidence and does nothing else, and from now on cannot be
/// granted capabilities. Records `agents.reviewer_assigned`. Requires a say
/// over both agents: `Agents(Update)`, since their owners differ.
pub(crate) async fn assign_reviewer(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
    Json(body): Json<AssignReviewerBody>,
) -> Result<Created<ReviewAssignmentResponse>, ApiError> {
    let assignment = agents
        .reviews
        .assign
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.reviewing(path.agent()),
        )
        .await?;
    Ok(Created(ReviewAssignmentResponse::from(&assignment)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/reviews",
    tag = "Agents",
    responses(
        (status = 200, description = "Success", body = Vec<ReviewAssignmentResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Agent not found", body = ErrorBody)
    )
)]
/// List an agent's review assignments
///
/// Every assignment where the agent reviews or is reviewed, newest first,
/// ended ones included. Requires the agent's owner or `Agents(View)`.
pub(crate) async fn list_reviews(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentPath>,
) -> Result<Json<Vec<ReviewAssignmentResponse>>, ApiError> {
    let reviews = agents
        .reviews
        .list
        .execute(&tenant.caller, path.agent())
        .await?;
    Ok(Json(
        reviews.iter().map(ReviewAssignmentResponse::from).collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/{id}/reviews/{assignment_id}/end",
    tag = "Agents",
    responses(
        (status = 204, description = "Ended"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 422, description = "Already ended", body = ErrorBody)
    )
)]
/// End a review assignment
///
/// The reviewer loses access to the agent's evidence on its next request.
/// Records `agents.review_ended`. Requires the reviewed agent's owner or
/// `Agents(Delegate)`.
pub(crate) async fn end_review(
    State(agents): State<AgentState>,
    tenant: TenantCaller,
    Path(path): Path<AgentReviewPath>,
) -> Result<NoContent, ApiError> {
    agents
        .reviews
        .end
        .execute(
            &tenant.caller,
            &tenant.auditor,
            EndRequest {
                reviewed: path.reviewed(),
                assignment_id: path.assignment(),
            },
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/review-desk/{id}/evidence",
    tag = "Agents",
    params(
        EvidenceParams,
        ("ianua-agent-id" = String, Header, description = "The reviewer agent's id"),
        ("ianua-agent-assertion" = String, Header, description = "The assertion the reviewer's key signed")
    ),
    responses(
        (status = 200, description = "Success", body = EvidencePageResponse),
        (status = 401, description = "No reviewer or assertion named", body = ErrorBody),
        (status = 403, description = "Assertion refused, not assigned, or no longer independent", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Read evidence as a reviewer agent
///
/// The reviewer names itself in the `Ianua-Agent-Id` header and signs in
/// with an assertion its own key signed, in the `Ianua-Agent-Assertion`
/// header; each assertion is spent on use. Every request checks again that
/// a person's assignment stands, the reviewer holds no capability, and the
/// two agents still answer to different people. Rate limited per address.
pub(crate) async fn review_desk_evidence(
    State(agents): State<AgentState>,
    reviewer: ReviewerAgent,
    Path(path): Path<AgentPath>,
    Query(params): Query<EvidenceParams>,
) -> Result<Json<EvidencePageResponse>, ApiError> {
    let page = agents
        .reviews
        .read_evidence
        .execute(
            &reviewer.tenant,
            params.for_reviewer(reviewer.reviewer, path.agent()),
        )
        .await?;
    Ok(Json(EvidencePageResponse::from(page)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/agents/review-desk/{id}/verdicts",
    tag = "Agents",
    request_body = VerdictBody,
    params(
        ("ianua-agent-id" = String, Header, description = "The reviewer agent's id"),
        ("ianua-agent-assertion" = String, Header, description = "The assertion the reviewer's key signed")
    ),
    responses(
        (status = 204, description = "Recorded for a person to act on"),
        (status = 401, description = "No reviewer or assertion named", body = ErrorBody),
        (status = 403, description = "Assertion refused, not assigned, or no longer independent", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Invalid verdict, or it cites records not the agent's", body = ErrorBody),
        (status = 429, description = "Too many requests", body = ErrorBody)
    )
)]
/// Give a verdict as a reviewer agent
///
/// Advisory only: a `concern` or a `containment_requested`, with a note and
/// the `seq` of at least one evidence record of the reviewed agent it rests
/// on. The verdict is recorded for a person; the reviewer acts on nothing.
/// Signed in as at the review desk's evidence. Records
/// `agents.review_verdict`.
pub(crate) async fn review_desk_verdict(
    State(agents): State<AgentState>,
    reviewer: ReviewerAgent,
    Path(path): Path<AgentPath>,
    Json(body): Json<VerdictBody>,
) -> Result<NoContent, ApiError> {
    agents
        .reviews
        .submit_verdict
        .execute(
            &reviewer.tenant,
            &reviewer.auditor,
            body.into_request(reviewer.reviewer, path.agent())?,
        )
        .await?;
    Ok(NoContent)
}
