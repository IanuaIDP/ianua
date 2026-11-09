//! Integration account handlers: the tenant's accounts that workflow
//! actions call integrations through.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::workflows::WorkflowState;

use crate::dto::workflows::accounts::{AccountResponse, ChangeAccountBody, ConnectAccountBody};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::workflows::AccountPath;
use crate::response::{Created, PageResponse};

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/accounts",
    tag = "Workflows",
    params(PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<AccountResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List integration accounts
///
/// Returns the tenant's integration accounts, oldest first, paginated. Each
/// entry names its `integration`, its `owner`, who it is shared with
/// (`sharing`), the `operations` it may be used for (`null` for every one)
/// and its `status`. A credential is never returned. Requires the right to
/// view workflows.
pub(crate) async fn list_accounts(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<AccountResponse>>, ApiError> {
    let page = workflows
        .list_accounts
        .execute(&tenant.caller, pagination)
        .await?;
    Ok(Json(PageResponse::from_page(page, AccountResponse::from)))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/accounts",
    tag = "Workflows",
    request_body = ConnectAccountBody,
    responses(
        (status = 201, description = "Connected", body = AccountResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such integration is installed", body = ErrorBody),
        (status = 422, description = "Validation error, or the integration's service refused the credential", body = ErrorBody),
        (status = 502, description = "The integration's service could not be asked whether the credential works", body = ErrorBody)
    )
)]
/// Connect an integration account
///
/// Connects an account of an installed `integration` for the caller, who
/// owns it. The `credential` is sealed before it is kept and never shown
/// again. `sharing` is `owner_only` (the default) or `tenant`; `operations`
/// limits it to some of the integration's operations. `404` when no such
/// integration is installed.
///
/// Checks connection rights before asking the integration's service to verify the
/// credential. Refusal (`422`) or unavailability (`502`) saves nothing. The HTTP
/// request integration has no service to ask and stores credentials unchecked.
///
/// Records `workflows.account_connected`. Requires the right to connect
/// accounts.
pub(crate) async fn connect_account(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Json(body): Json<ConnectAccountBody>,
) -> Result<Created<AccountResponse>, ApiError> {
    let account = workflows
        .connect_account
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(AccountResponse::from(account)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/workflows/accounts/{account_id}",
    tag = "Workflows",
    request_body = ChangeAccountBody,
    responses(
        (status = 200, description = "Changed", body = AccountResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such account", body = ErrorBody),
        (status = 422, description = "Validation error, already in that state, or the integration's service refused a replacement credential", body = ErrorBody),
        (status = 502, description = "The integration's service could not be asked whether a replacement credential works", body = ErrorBody)
    )
)]
/// Change an integration account
///
/// Makes one change, named by `change`: `enable`, `disable`,
/// `replace_credential` (with `credential`), `share_with_tenant`,
/// `keep_to_owner`, `limit_to` (with `operations`, `null` for every one) or
/// `rename` (with `name`). Answers the account as saved. `422` when it is
/// already enabled or disabled. A replacement credential is tried as
/// connecting tries one, once the caller is known to be the owner: `422`
/// when the service refuses it and `502` when it cannot be asked, the
/// account keeping the credential it had. Records `workflows.account_enabled`,
/// `workflows.account_disabled` or `workflows.account_changed`. Requires being its owner, or the right to connect accounts for changes
/// that are not the owner's alone.
pub(crate) async fn change_account(
    State(workflows): State<WorkflowState>,
    tenant: TenantCaller,
    Path(path): Path<AccountPath>,
    Json(body): Json<ChangeAccountBody>,
) -> Result<Json<AccountResponse>, ApiError> {
    let account = workflows
        .change_account
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.request(path.account())?,
        )
        .await?;
    Ok(Json(AccountResponse::from(account)))
}
