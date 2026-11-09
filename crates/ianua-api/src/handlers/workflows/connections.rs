//! Account connection handlers: connecting an integration account by
//! signing in at its service, begun and finished with the person's
//! session, and the service's answer at the platform's one callback.

use axum::extract::{Path, State};
use ianua_app::use_case::Command as _;
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::accounts::AccountResponse;
use crate::dto::workflows::accounts::connections::{
    BeginConnectionBody, CallbackParams, ConnectionBegunResponse, FinishConnectionBody, landing,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::workflows::ConnectionPath;
use crate::extractors::query::Query;
use crate::extractors::workflows::ServiceReturn;
use crate::response::{Created, Found};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/accounts/connections",
    tag = "Workflows",
    request_body = BeginConnectionBody,
    responses(
        (status = 201, description = "Begun", body = ConnectionBegunResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 422, description = "Validation error, or the integration cannot be connected by signing in here", body = ErrorBody)
    )
)]
/// Begin connecting an account by signing in
///
/// Starts a caller-owned `integration` account connection, returning `connection_id`
/// and browser `address`. The service returns to `/api/v1/integrations/callback`,
/// then `/integrations/connected` receives the connection and one-time code to finish.
/// `name`, `sharing` and `operations` match credential-based connections.
/// Services with several spaces expose `sign_in_asks_for`, such as Azure DevOps `organization`;
/// `place` names it, such as `contoso`, and each organization is
/// connected as an account of its own.
///
/// `422` for absent service sign-in or deployment app registration (`connecting: credential`),
/// or missing/unexpected `place`. Expires after ten minutes without completion.
/// Records `workflows.account_connection_started`.
/// Requires the right to connect accounts.
pub(crate) async fn begin_connection(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Json(body): Json<BeginConnectionBody>,
) -> Result<Created<ConnectionBegunResponse>, ApiError> {
    let begun = workflows
        .begin_connection
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(ConnectionBegunResponse::from(begun)))
}

#[utoipa::path(
    get,
    path = "/api/v1/integrations/callback",
    tag = "Workflows",
    params(CallbackParams),
    responses(
        (status = 302, description = "On to the dashboard, with the connection and its one-time code, or why it cannot be finished")
    )
)]
/// Take a service's answer to a sign-in
///
/// Where every integration's service sends the browser back after a
/// person signed in there to connect an account. The `state` finds the
/// connection, and the service's `code` is swapped for a credential at
/// once, kept sealed. The browser is sent on to the dashboard's
/// `/integrations/connected` page with `connection` and a one-time `code`
/// after the `#`, never the credential; the dashboard finishes the
/// connection with the person's session. When it cannot be taken the page
/// is told `error`: `declined` at the service, `unknown` for a `state` no
/// connection has, `expired` for one that ran out or was answered already,
/// `unreachable` when the service did not answer, or `refused` when it
/// refused the code. Public.
pub(crate) async fn answer_connection(
    State(workflows): State<WorkflowState>,
    service: ServiceReturn,
    Query(params): Query<CallbackParams>,
) -> Found {
    let Some(request) = params.answer() else {
        return Found(landing(&workflows.app_base_url, None));
    };
    let answered = workflows
        .answer_connection
        .execute(&(), &service.auditor, request)
        .await;
    Found(landing(&workflows.app_base_url, Some(answered)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/accounts/connections/{connection_id}/finish",
    tag = "Workflows",
    request_body = FinishConnectionBody,
    responses(
        (status = 201, description = "Connected", body = AccountResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, a wrong code, or not the person who began it", body = ErrorBody),
        (status = 404, description = "No such connection", body = ErrorBody),
        (status = 409, description = "It ran out, the service has not answered, or it was finished already", body = ErrorBody),
        (status = 422, description = "The integration's service refused the credential", body = ErrorBody),
        (status = 502, description = "The integration's service could not be asked whether the credential works", body = ErrorBody)
    )
)]
/// Finish connecting an account
///
/// Finishes the connection the service answered, with the one-time `code`
/// the browser brought back to the dashboard, and connects the account it
/// was begun for, owned by the caller. The credential the service issued
/// is tried first, as when connecting with a credential.
///
/// Only the person who began it may: anyone else is refused with `403`,
/// the connection is spent and the refusal recorded, so a link sent to
/// someone else never lands their account in another tenant. Records
/// `workflows.account_connected`, or `workflows.account_connection_refused`.
/// Requires the right to connect accounts.
pub(crate) async fn finish_connection(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<ConnectionPath>,
    Json(body): Json<FinishConnectionBody>,
) -> Result<Created<AccountResponse>, ApiError> {
    let account = workflows
        .finish_connection
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.finishing(path.connection()),
        )
        .await?;
    Ok(Created(AccountResponse::from(account)))
}
