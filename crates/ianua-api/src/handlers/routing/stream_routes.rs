//! Stream route handlers: the ports a tenant listens on below HTTP.

use axum::extract::{Path, State};
use ianua_app::ports::routing::StreamRouteSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::routing::stream_routes::{
    ListRequest, SetStatusRequest, SetStreamWorkflowUseRequest, StreamWorkflowChange, Transition,
};
use ianua_assembly::routing::RoutingState;

use crate::dto::routing::stream_routes::{
    CreateStreamRouteBody, CreateStreamRouteResponse, StreamRouteResponse, UpdateStreamRouteBody,
};
use crate::dto::routing::stream_workflows::OpenStreamRouteToWorkflowsBody;
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::pagination::{PaginationParams, Paging};
use crate::extractors::paths::routing::StreamRoutePath;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/stream-routes",
    tag = "Routing",
    request_body = CreateStreamRouteBody,
    responses(
        (status = 201, description = "Created", body = CreateStreamRouteResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or at the plan's stream-route limit", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 409, description = "Port already claimed", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Open a port
///
/// Forwards a TCP, TLS or UDP port after deciding access, within the plan's stream-route limit.
///
/// `mutual_tls` requires `tls_terminate`; passthrough hides the certificate,
/// and plain TCP/UDP carries none.
///
/// `access` selects policy-admitted holders, signed-in `tunnel` clients or named consumers.
/// Tunnel policy is checked on each connection and refuses errors. Public ports cannot
/// identify callers and accept only any-holder access. Unknown tenant consumers give `404`.
///
/// Returns `409` if the port is already claimed. A listening port belongs to
/// the deployment, not to a tenant, so another tenant may already hold it.
/// Records `routing.stream_route_created`. Requires `Routing(Create)`.
pub(crate) async fn create_stream_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Json(body): Json<CreateStreamRouteBody>,
) -> Result<Created<CreateStreamRouteResponse>, ApiError> {
    let id = routing
        .create_stream_route
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(id.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/stream-routes",
    tag = "Routing",
    params(SortQuery<StreamRouteSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<StreamRouteResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody)
    )
)]
/// List stream routes
///
/// Returns this tenant's ports, sortable and paginated. Read-only. Requires
/// `Routing(View)`.
pub(crate) async fn list_stream_routes(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    SortQuery(sort): SortQuery<StreamRouteSortField>,
    Paging(pagination): Paging,
) -> Result<Json<PageResponse<StreamRouteResponse>>, ApiError> {
    let request = ListRequest {
        sort,
        page: pagination,
    };
    let page = routing
        .list_stream_routes
        .execute(&tenant.caller, request)
        .await?;
    Ok(Json(PageResponse::from_page(
        page,
        StreamRouteResponse::from,
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/stream-routes/{id}",
    tag = "Routing",
    responses(
        (status = 200, description = "Success", body = StreamRouteResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such stream route", body = ErrorBody)
    )
)]
/// Get a stream route
///
/// Returns one port by `id`. Read-only. Requires `Routing(View)`.
pub(crate) async fn get_stream_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<StreamRoutePath>,
) -> Result<Json<StreamRouteResponse>, ApiError> {
    let route = routing
        .get_stream_route
        .execute(&tenant.caller, path.stream_route())
        .await?;
    Ok(Json(StreamRouteResponse::from(route)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/stream-routes/{id}",
    tag = "Routing",
    request_body = UpdateStreamRouteBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such stream route", body = ErrorBody),
        (status = 409, description = "Another stream route has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update a stream route
///
/// Partial update of the name, server names, policy, access, backends or
/// timeouts. A new policy and access are judged together.
/// The protocol and the port are not changeable: either is a different socket
/// on a different listener, so create a new route and delete this one.
///
/// Returns `422` if a new policy asks for an identity the route's protocol
/// cannot carry, or a backend targets a private address. Records
/// `routing.stream_route_updated`. Requires `Routing(Update)`.
pub(crate) async fn update_stream_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<StreamRoutePath>,
    Json(body): Json<UpdateStreamRouteBody>,
) -> Result<NoContent, ApiError> {
    routing
        .update_stream_route
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.stream_route())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/stream-routes/{id}",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such stream route", body = ErrorBody)
    )
)]
/// Delete a stream route
///
/// Closes the port and releases it for any tenant to claim. Records
/// `routing.stream_route_deleted`. Requires `Routing(Delete)`.
pub(crate) async fn delete_stream_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<StreamRoutePath>,
) -> Result<NoContent, ApiError> {
    routing
        .delete_stream_route
        .execute(&tenant.caller, &tenant.auditor, path.stream_route())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/stream-routes/{id}/activate",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such stream route", body = ErrorBody),
        (status = 422, description = "Already active", body = ErrorBody)
    )
)]
/// Activate a stream route
///
/// The port starts accepting again. Records
/// `routing.stream_route_activated`. Requires `Routing(Update)`.
pub(crate) async fn activate_stream_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<StreamRoutePath>,
) -> Result<NoContent, ApiError> {
    let request = SetStatusRequest {
        stream_route_id: path.stream_route(),
        transition: Transition::Activate,
    };
    routing
        .set_stream_route_status
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/stream-routes/{id}/disable",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such stream route", body = ErrorBody),
        (status = 422, description = "Already disabled", body = ErrorBody)
    )
)]
/// Disable a stream route
///
/// The port stops accepting. Established streams are left alone, and the port
/// stays reserved for this tenant, so taking one out of service briefly does
/// not risk losing it to somebody else. Records
/// `routing.stream_route_disabled`. Requires `Routing(Update)`.
pub(crate) async fn disable_stream_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<StreamRoutePath>,
) -> Result<NoContent, ApiError> {
    let request = SetStatusRequest {
        stream_route_id: path.stream_route(),
        transition: Transition::Disable,
    };
    routing
        .set_stream_route_status
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/stream-routes/{id}/open-to-workflows",
    tag = "Routing",
    request_body = OpenStreamRouteToWorkflowsBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such stream route", body = ErrorBody),
        (status = 422, description = "Already open to workflows, a route that lets no people in, or an invalid login", body = ErrorBody)
    )
)]
/// Open a stream route to workflows
///
/// Lets the tenant's workflows reach the system behind the stream route
/// with a Protected data step, as the person each run acts for, signing in
/// with the login given here. The route's own access still decides every
/// connection, exactly as it would for that person through the signed-in
/// tunnel, so only a route that lets people in can be opened. What a step
/// may do once through is what the login may do, decided by the system
/// itself. The password is kept sealed for this route and never shown.
///
/// **State.** `closed -> open`. Returns `404` if the stream route does not
/// exist, or `422` if it is open already: close it first to change the
/// login. Records `routing.stream_route_opened_to_workflows`, naming the
/// login's user. Requires `Routing(Update)`.
pub(crate) async fn open_stream_route_to_workflows(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<StreamRoutePath>,
    Json(body): Json<OpenStreamRouteToWorkflowsBody>,
) -> Result<NoContent, ApiError> {
    let request = body.into_request(path.stream_route())?;
    routing
        .set_stream_route_workflow_use
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/stream-routes/{id}/close-to-workflows",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such stream route", body = ErrorBody),
        (status = 422, description = "Already closed to workflows", body = ErrorBody)
    )
)]
/// Close a stream route to workflows
///
/// Stops the tenant's workflows reaching the stream route and forgets the
/// login kept for them: from the next connection on, every Protected data
/// step reaching it is refused at the gateway.
///
/// **State.** `open -> closed`. Returns `404` if the stream route does not
/// exist, or `422` if it is closed already. Records
/// `routing.stream_route_closed_to_workflows`. Requires `Routing(Update)`.
pub(crate) async fn close_stream_route_to_workflows(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<StreamRoutePath>,
) -> Result<NoContent, ApiError> {
    let request = SetStreamWorkflowUseRequest {
        stream_route_id: path.stream_route(),
        change: StreamWorkflowChange::Close,
    };
    routing
        .set_stream_route_workflow_use
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}
