//! Egress policy handlers: where a service that agents can reach may itself
//! go.

use axum::extract::{Path, State};
use ianua_app::use_case::{Command as _, Query as _};
use ianua_assembly::routing::RoutingState;

use crate::dto::routing::egress::{
    CreateEgressPolicyBody, EgressPolicyResponse, UpdateEgressPolicyBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::paths::routing::EgressPolicyPath;
use crate::response::{Created, NoContent};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/egress-policies",
    tag = "Routing",
    request_body = CreateEgressPolicyBody,
    responses(
        (status = 201, description = "Created", body = EgressPolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or at the plan's limit", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 409, description = "The service already has a policy", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Give a service a way out
///
/// The egress gateway lets the service, identified by its client
/// certificate, reach exactly these hosts and ports and nothing else. A
/// service with no policy reaches nothing. Wildcards are refused: over a
/// public suffix they would be the whole internet. Records
/// `routing.egress_policy_created`. Requires `Routing(Create)`.
pub(crate) async fn create_egress_policy(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Json(body): Json<CreateEgressPolicyBody>,
) -> Result<Created<EgressPolicyResponse>, ApiError> {
    let policy = routing
        .create_egress_policy
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(EgressPolicyResponse::from(&policy)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/egress-policies",
    tag = "Routing",
    responses(
        (status = 200, description = "Success", body = Vec<EgressPolicyResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List egress policies
///
/// Every egress policy of the tenant: the service each is for, where it may
/// go and its data ceiling. Read-only. Requires `Routing(View)`.
pub(crate) async fn list_egress_policies(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<EgressPolicyResponse>>, ApiError> {
    let policies = routing
        .list_egress_policies
        .execute(&tenant.caller, ())
        .await?;
    Ok(Json(
        policies.iter().map(EgressPolicyResponse::from).collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/egress-policies/{id}",
    tag = "Routing",
    responses(
        (status = 200, description = "Success", body = EgressPolicyResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such egress policy", body = ErrorBody)
    )
)]
/// Get an egress policy
///
/// One egress policy by `id`. Read-only. Requires `Routing(View)`.
pub(crate) async fn get_egress_policy(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<EgressPolicyPath>,
) -> Result<Json<EgressPolicyResponse>, ApiError> {
    let policy = routing
        .get_egress_policy
        .execute(&tenant.caller, path.policy())
        .await?;
    Ok(Json(EgressPolicyResponse::from(&policy)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/egress-policies/{id}",
    tag = "Routing",
    request_body = UpdateEgressPolicyBody,
    responses(
        (status = 204, description = "Updated"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such egress policy", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Change where a service may go
///
/// Renames the policy, or replaces its destination list or data ceiling; an
/// omitted field is left as it is. Records `routing.egress_policy_updated`.
/// Requires `Routing(Update)`.
pub(crate) async fn update_egress_policy(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<EgressPolicyPath>,
    Json(body): Json<UpdateEgressPolicyBody>,
) -> Result<NoContent, ApiError> {
    routing
        .update_egress_policy
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.policy())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/egress-policies/{id}",
    tag = "Routing",
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such egress policy", body = ErrorBody)
    )
)]
/// Take away a service's way out
///
/// The service reaches nothing from its next connection on. Records
/// `routing.egress_policy_deleted`. Requires `Routing(Delete)`.
pub(crate) async fn delete_egress_policy(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<EgressPolicyPath>,
) -> Result<NoContent, ApiError> {
    routing
        .delete_egress_policy
        .execute(&tenant.caller, &tenant.auditor, path.policy())
        .await?;
    Ok(NoContent)
}
