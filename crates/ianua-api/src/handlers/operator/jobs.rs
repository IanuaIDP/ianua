//! Job handlers: the jobs the platform gave up on, for operators to look
//! into and retry.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::operator::OperatorState;

use crate::dto::operator::DeadJobResponse;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::Operator;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::operator::DeadJobPath;
use crate::response::{NoContent, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/operators/dead-jobs",
    tag = "Operators",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<DeadJobResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List dead jobs
///
/// Returns the jobs that used up their tries, across every tenant, newest
/// first and paginated. Each entry carries the job's `id`, its
/// `job_type`, the `tenant_id` it worked for (`null` for the platform's
/// own work), how many `attempts` it made, the `reason` its last run
/// failed, `created_at` and `last_attempted_at`. A job's payload is never
/// shown: only its handler reads it, and it may name what only its tenant
/// should see. Read-only. Requires an operator's own key.
pub(crate) async fn list_dead_jobs(
    State(operators): State<OperatorState>,
    operator: Operator,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<DeadJobResponse>>, ApiError> {
    let page = operators
        .list_dead_jobs
        .execute(&operator.caller, pagination)
        .await?;
    Ok(Json(PageResponse::from_page(page, DeadJobResponse::from)))
}

#[utoipa::path(
    post,
    path = "/api/v1/operators/dead-jobs/{id}/retry",
    tag = "Operators",
    responses(
        (status = 204, description = "Back on the queue"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "Not found", body = ErrorBody),
        (status = 409, description = "Not dead, retried meanwhile, or the same work waits", body = ErrorBody)
    )
)]
/// Retry a dead job
///
/// Gives a job that used up its tries one more attempt, due at once, once
/// whatever made it fail is put right. It keeps the attempts it made and
/// why the last one failed; should the new attempt fail too, it is dead
/// again. Returns `404` for a job the queue does not hold, and `409` for a
/// job that is not dead (waiting, running, done, or retried by someone
/// else meanwhile) or whose same work, queued again under its key, waits
/// or runs already. Of two operators retrying one job at once, one puts it
/// back. Records `operator.dead_job_retried`, naming the operator, the
/// job, its kind, its tenant and how often it ran, never its payload.
/// Requires an operator's own key.
pub(crate) async fn retry_dead_job(
    State(operators): State<OperatorState>,
    operator: Operator,
    Path(path): Path<DeadJobPath>,
) -> Result<NoContent, ApiError> {
    operators
        .retry_dead_job
        .execute(&operator.caller, &operator.auditor, path.job())
        .await?;
    Ok(NoContent)
}
