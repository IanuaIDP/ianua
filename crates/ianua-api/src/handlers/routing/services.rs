//! Service handlers: the backends a tenant's routes forward to, and how
//! people sign in on the hosts they are served on.

use axum::extract::{Path, State};
use ianua_app::ports::routing::ServiceSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::routing::services::{ChangeTlsRequest, ListRequest};
use ianua_assembly::routing::RoutingState;
use ianua_domain::types::Setting;

use crate::dto::routing::services::{
    ChangeServiceTlsBody, CreateServiceBody, CreateServiceResponse, ServiceHealthResponse,
    ServiceResponse, UpdateServiceBody,
};
use crate::dto::routing::sign_in::AppSignInBody;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::routing::ServicePath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/services",
    tag = "Routing",
    request_body = CreateServiceBody,
    responses(
        (status = 201, description = "Created", body = CreateServiceResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or at the plan's service limit", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 409, description = "Another service has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create a service
///
/// Defines a backend that routes forward to: an `upstream` (a URL, or weighted
/// backends for a canary), and how its backends are probed. Checked against
/// the tenant plan's service limit. An upstream naming a private or loopback
/// address is refused: a service is an instruction for the proxy to connect
/// somewhere on the tenant's behalf. Records `routing.service_created`.
/// Requires `Routing(Create)`.
pub(crate) async fn create_service(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Json(body): Json<CreateServiceBody>,
) -> Result<Created<CreateServiceResponse>, ApiError> {
    let id = routing
        .create_service
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(id.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/services",
    tag = "Routing",
    params(SortQuery<ServiceSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<ServiceResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List services
///
/// Returns this tenant's services, sortable and paginated. Read-only.
/// Requires `Routing(View)`.
pub(crate) async fn list_services(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<ServiceSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<ServiceResponse>>, ApiError> {
    let request = ListRequest {
        sort,
        page: pagination,
    };
    let page = routing
        .list_services
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(page, ServiceResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/services/{id}",
    tag = "Routing",
    responses(
        (status = 200, description = "Success", body = ServiceResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such service", body = ErrorBody)
    )
)]
/// Get a service
///
/// Returns one service by `id`: its upstream, probe settings, sign-in and
/// lifecycle status. Read-only. Requires `Routing(View)`.
pub(crate) async fn get_service(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ServicePath>,
) -> Result<Json<ServiceResponse>, ApiError> {
    let service = routing
        .get_service
        .execute(&tenant.caller, path.service())
        .await?;
    Ok(Json(ServiceResponse::from(service)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/services/{id}/health",
    tag = "Routing",
    responses(
        (status = 200, description = "Success", body = ServiceHealthResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such service", body = ErrorBody)
    )
)]
/// Get a service's live backend health
///
/// Returns how the service's backends are probed and what the gateway's
/// probes last saw: each backend `up` or `down`, and when. `state` is
/// `reported` with the backends, `unknown` when the service is probed but
/// no gateway reported in the last few probe intervals (never read that as
/// healthy), or `not_probed` when probing is off and every backend gets
/// traffic. Read-only. Requires `Routing(View)`.
pub(crate) async fn get_service_health(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ServicePath>,
) -> Result<Json<ServiceHealthResponse>, ApiError> {
    let health = routing
        .service_health
        .execute(&tenant.caller, path.service())
        .await?;
    Ok(Json(ServiceHealthResponse::from(health)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/services/{id}",
    tag = "Routing",
    request_body = UpdateServiceBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such service", body = ErrorBody),
        (status = 409, description = "Another service has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update a service
///
/// Partial update: send `name`, `upstream` and/or `health_check` to change
/// just those. Every route pointing at this service forwards differently from
/// here on, which is the point of a service existing.
///
/// Returns `422` if the new upstream targets a private address, or if dropping
/// its pinned JWT audience would leave a route that requires authentication
/// accepting tokens minted for any of the tenant's clients. Records
/// `routing.service_updated`. Requires `Routing(Update)`.
pub(crate) async fn update_service(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ServicePath>,
    Json(body): Json<UpdateServiceBody>,
) -> Result<NoContent, ApiError> {
    routing
        .update_service
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.service())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/services/{id}",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such service", body = ErrorBody),
        (status = 409, description = "Routes still forward to it", body = ErrorBody)
    )
)]
/// Delete a service
///
/// Permanently removes a service. Refused with `409` while any route still
/// forwards to it: move or delete those first. Records
/// `routing.service_deleted`. Requires `Routing(Delete)`.
pub(crate) async fn delete_service(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ServicePath>,
) -> Result<NoContent, ApiError> {
    routing
        .delete_service
        .execute(&tenant.caller, &tenant.auditor, path.service())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/services/{id}/tls",
    tag = "Routing",
    request_body = ChangeServiceTlsBody,
    responses(
        (status = 204, description = "Saved"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such service", body = ErrorBody),
        (status = 422, description = "Validation error, a wildcard server name, or a backend reached over plain http", body = ErrorBody)
    )
)]
/// Set a service's upstream TLS
///
/// Replaces how the gateway opens TLS to the service's upstream: the CA
/// bundle its certificate must chain to (`ca_certificates`, the public
/// roots when omitted), the client certificate and key presented when the
/// upstream asks for one, and the server name sent as SNI. Verification is
/// never switched off. The private key is sealed before it is stored, is
/// never answered back and is in no audit record. Every backend must be
/// reached over `https://`. Records `routing.service_updated`. Requires
/// `Routing(Update)`.
pub(crate) async fn change_service_tls(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ServicePath>,
    Json(body): Json<ChangeServiceTlsBody>,
) -> Result<NoContent, ApiError> {
    routing
        .change_service_tls
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.service())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/services/{id}/tls",
    tag = "Routing",
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such service", body = ErrorBody)
    )
)]
/// Remove a service's upstream TLS
///
/// Drops the service's own TLS settings: the gateway checks the upstream
/// against the public roots again, presents no client certificate and
/// sends the address's own host as SNI. The stored client key goes with
/// them. Records `routing.service_updated`. Requires `Routing(Update)`.
pub(crate) async fn remove_service_tls(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ServicePath>,
) -> Result<NoContent, ApiError> {
    routing
        .change_service_tls
        .execute(
            &tenant.caller,
            &tenant.auditor,
            ChangeTlsRequest {
                service_id: path.service(),
                tls: Setting::Unset,
            },
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/services/{id}/app-sign-in",
    tag = "Routing",
    request_body = AppSignInBody,
    responses(
        (status = 204, description = "Saved"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such service, or no such service to accept", body = ErrorBody),
        (status = 409, description = "Another service already signs people in on one of the hosts", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Set a service's app sign-in
///
/// Replaces how people sign in on the service's hosts: its own app sign-in
/// (`app_sign_in`, `null` to turn it off), or another service's that it
/// accepts instead (`accepts_app_sign_in_of`, with the `delivery` by which
/// that sign-in reaches it). Each host must be a verified domain of the
/// tenant that a route of this service answers on, and no sign-in path may
/// be a route's own path there. Returns `409` if another service already
/// signs people in, or sets its own cookie, on one of the hosts. Records
/// `routing.app_sign_in_changed`. Requires `Routing(Update)`.
pub(crate) async fn configure_app_sign_in(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<ServicePath>,
    Json(body): Json<AppSignInBody>,
) -> Result<NoContent, ApiError> {
    routing
        .configure_app_sign_in
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.service())?,
        )
        .await?;
    Ok(NoContent)
}
