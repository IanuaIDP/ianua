//! Live workflow streams: one run as its steps start and end, and a
//! workflow's draft as people change it.

use axum::extract::{Path, State};
use axum::response::Response;
use ianua_app::ports::realtime::{draft_subject, run_subject};
use ianua_app::use_case::Query as _;
use ianua_app::use_cases::workflows::definitions::{GetWorkflowRequest, WhichVersion};

use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::paths::workflows::{ExecutionPath, WorkflowPath};
use crate::extractors::realtime::Handshake;
use crate::state::streams::WorkflowStreamState;
use crate::ws::{Admission, DraftWatch, ExecutionWatch, SubjectSubscription, stream_subject};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/ws/workflows/executions/{execution_id}",
    tag = "Real-time",
    responses(
        (status = 101, description = "WebSocket upgrade: live moments of one workflow run"),
        (status = 400, description = "Not a WebSocket handshake"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such execution", body = ErrorBody),
        (status = 429, description = "Too many open streams", body = ErrorBody)
    )
)]
/// Workflow run stream (WebSocket)
///
/// Upgrades to a WebSocket and streams what happens in one run, real or a
/// test, as it happens: it starting, each step starting, succeeding,
/// failing, standing in, being skipped or approved, and how it ended. On
/// connect the server sends a `{ "type": "connected", "subject" }` frame,
/// then one `run_moment` frame per moment. A frame names steps, never
/// data: the run is read again for what the caller may see. The stream
/// asks again from time to time whether the caller may still read the run
/// and closes (`1008`) when not. Requires the right to view workflows.
pub(crate) async fn run_ws(
    State(WorkflowStreamState {
        realtime,
        gates,
        workflows,
    }): State<WorkflowStreamState>,
    tenant: TenantCaller,
    Path(path): Path<ExecutionPath>,
    handshake: Handshake,
) -> Result<Response, ApiError> {
    let execution_id = path.execution();
    workflows
        .get_execution
        .execute(&tenant.caller, execution_id)
        .await?;
    let permit = gates.streams.claim_for(tenant.caller.identity())?;
    let subject = run_subject(&tenant.caller.tenant_id(), &execution_id);
    let watch = ExecutionWatch::new(workflows.get_execution, tenant.caller, execution_id);
    let (live, timing) = (realtime.live, gates.timing);
    Ok(handshake.accept(move |socket| async move {
        let _permit = permit;
        let subscription = SubjectSubscription::new(live, subject);
        stream_subject(socket, subscription, Admission::everything(watch), timing).await;
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/ws/workflows/{workflow_id}/draft",
    tag = "Real-time",
    responses(
        (status = 101, description = "WebSocket upgrade: live changes to one workflow's draft"),
        (status = 400, description = "Not a WebSocket handshake"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such workflow", body = ErrorBody),
        (status = 429, description = "Too many open streams", body = ErrorBody)
    )
)]
/// Workflow draft stream (WebSocket)
///
/// Upgrades to a WebSocket and streams each change someone makes to the
/// workflow's draft: renamed, steps replaced, trigger, run limit,
/// description or failure alert changed. On connect the server sends a
/// `{ "type": "connected", "subject" }` frame, then one `draft_changed`
/// frame per change, naming its `event_type`, so the builder reads the
/// draft again instead of working on a stale copy. Moving steps on the
/// canvas records nothing and sends nothing. The stream closes (`1008`)
/// once the caller may no longer read the workflow. Requires the right to
/// view workflows.
pub(crate) async fn draft_ws(
    State(WorkflowStreamState {
        realtime,
        gates,
        workflows,
    }): State<WorkflowStreamState>,
    tenant: TenantCaller,
    Path(path): Path<WorkflowPath>,
    handshake: Handshake,
) -> Result<Response, ApiError> {
    let workflow_id = path.workflow();
    let request = GetWorkflowRequest {
        workflow_id,
        version: WhichVersion::Latest,
    };
    workflows
        .get_workflow
        .execute(&tenant.caller, request)
        .await?;
    let permit = gates.streams.claim_for(tenant.caller.identity())?;
    let subject = draft_subject(&tenant.caller.tenant_id(), &workflow_id);
    let watch = DraftWatch::new(workflows.get_workflow, tenant.caller, workflow_id);
    let (live, timing) = (realtime.live, gates.timing);
    Ok(handshake.accept(move |socket| async move {
        let _permit = permit;
        let subscription = SubjectSubscription::new(live, subject);
        stream_subject(socket, subscription, Admission::everything(watch), timing).await;
    }))
}
