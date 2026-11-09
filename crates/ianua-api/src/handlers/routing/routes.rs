//! Route handlers: a tenant's proxy routes, and the traffic each served.

use axum::extract::{Path, State};
use ianua_app::ports::routing::RouteSortField;
use ianua_app::use_case::{Command as _, Query as _};
use ianua_app::use_cases::routing::routes::{
    AttackChange, SetAttackModeRequest, SetWorkflowUseRequest,
};
use ianua_assembly::routing::RoutingState;
use ianua_domain::domains::routing::route::WorkflowUse;

use crate::dto::routing::routes::{
    AttackModeResponse, CreateRouteBody, CreateRouteResponse, OpenableAppResponse,
    RouteConditionsBody, RouteFilterParams, RouteResponse, RouteTrafficListResponse,
    RouteTrafficParams, StartAttackModeBody, UpdateRouteBody,
};
use crate::error::{ApiError, ErrorBody};
use crate::extractors::callers::TenantCaller;
use crate::extractors::json::Json;
use crate::extractors::listing::ListingQuery;
use crate::extractors::metrics_window::MetricsWindowQuery;
use crate::extractors::pagination::PaginationParams;
use crate::extractors::paths::routing::RoutePath;
use crate::extractors::query::Query;
use crate::extractors::sort::SortQuery;
use crate::response::{Created, NoContent, PageResponse};

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes",
    tag = "Routing",
    request_body = CreateRouteBody,
    responses(
        (status = 201, description = "Created", body = CreateRouteResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden, or at the plan's route limit", body = ErrorBody),
        (status = 404, description = "No such tenant, service or pipeline", body = ErrorBody),
        (status = 409, description = "Another route has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Create a proxy route
///
/// Defines a route that maps a `path_pattern` (and HTTP `methods`) to a
/// `service`, evaluated against an authorization `policy`, with a
/// `priority` (higher wins on overlap) and a `path_rewrite` saying what
/// path the upstream sees. Created in `Active` status. Checked against the
/// tenant plan's route limit before creation. Returns the new route's `id`.
/// Returns `422` for an invalid name, path pattern or host. Records
/// `routing.route_created`. Requires `Routing(Create)`.
pub(crate) async fn create_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Json(body): Json<CreateRouteBody>,
) -> Result<Created<CreateRouteResponse>, ApiError> {
    let id = routing
        .create_route
        .execute(&tenant.caller, &tenant.auditor, body.try_into()?)
        .await?;
    Ok(Created(id.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes",
    tag = "Routing",
    params(RouteFilterParams, SortQuery<RouteSortField>, PaginationParams),
    responses(
        (status = 200, description = "Success", body = PageResponse<RouteResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// List proxy routes
///
/// Returns this tenant's routes, optionally filtered by `status` (`Active`
/// or `Disabled`), sortable and paginated. Each entry carries the name, path
/// pattern, methods, service, policy, priority and lifecycle status.
/// Read-only. Requires `Routing(View)`.
pub(crate) async fn list_routes(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    ListingQuery {
        query: filter,
        sort,
        page: pagination,
    }: ListingQuery<RouteFilterParams, RouteSortField>,
) -> Result<Json<PageResponse<RouteResponse>>, ApiError> {
    let page = routing
        .list_routes
        .execute(&tenant.caller, filter.listing(sort, pagination))
        .await?;
    Ok(Json(PageResponse::from_page(page, RouteResponse::from)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes/{id}",
    tag = "Routing",
    responses(
        (status = 200, description = "Success", body = RouteResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such route", body = ErrorBody)
    )
)]
/// Get a proxy route
///
/// Returns a single route by `id`. Returns `404` if it does not exist under
/// this tenant. Read-only. Requires `Routing(View)`.
pub(crate) async fn get_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<RoutePath>,
) -> Result<Json<RouteResponse>, ApiError> {
    let route = routing
        .get_route
        .execute(&tenant.caller, path.route())
        .await?;
    Ok(Json(RouteResponse::from(route)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes/{id}",
    tag = "Routing",
    request_body = UpdateRouteBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such route, service or pipeline", body = ErrorBody),
        (status = 409, description = "Another route has the name", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Update a route
///
/// Partial update: send `name`, `path_pattern`, `methods`, `service_id`,
/// `policy`, `priority`, `path_rewrite`, `hosts`, `pipeline_id` or the
/// declarations to change just those; omit any to leave it. This edits
/// configuration only; it does not change `status` (use activate and
/// disable). Returns `404` if the route does not exist, or `422` for an
/// invalid name or path. Records `routing.route_updated`. Requires
/// `Routing(Update)`.
pub(crate) async fn update_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<RoutePath>,
    Json(body): Json<UpdateRouteBody>,
) -> Result<NoContent, ApiError> {
    routing
        .update_route
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.route())?,
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes/{id}",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such route", body = ErrorBody),
        (status = 422, description = "The route is still active", body = ErrorBody)
    )
)]
/// Delete a route
///
/// Permanently removes a route. It must be `Disabled` first: an active route
/// cannot be deleted, since that would cut live traffic. Returns `404` if the
/// route does not exist. Records `routing.route_deleted`. Requires
/// `Routing(Delete)`.
pub(crate) async fn delete_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<RoutePath>,
) -> Result<NoContent, ApiError> {
    routing
        .delete_route
        .execute(&tenant.caller, &tenant.auditor, path.route())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes/{id}/activate",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such route", body = ErrorBody),
        (status = 422, description = "Already active", body = ErrorBody)
    )
)]
/// Activate a route
///
/// Re-enables a `Disabled` route so it accepts traffic again.
///
/// **State.** `Disabled -> Active`. Returns `404` if the route does not
/// exist, or `422` if it is already `Active`. Records
/// `routing.route_activated`. Requires `Routing(Update)`.
pub(crate) async fn activate_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<RoutePath>,
) -> Result<NoContent, ApiError> {
    routing
        .activate_route
        .execute(&tenant.caller, &tenant.auditor, path.route())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes/{id}/disable",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such route", body = ErrorBody),
        (status = 422, description = "Already disabled", body = ErrorBody)
    )
)]
/// Disable a route
///
/// Takes a route out of service: it stops matching and returns `503` to
/// callers until re-enabled. Use this to drain traffic safely before
/// deleting.
///
/// **State.** `Active -> Disabled`. Returns `404` if the route does not
/// exist, or `422` if it is already `Disabled`. Records
/// `routing.route_disabled`. Requires `Routing(Update)`.
pub(crate) async fn disable_route(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<RoutePath>,
) -> Result<NoContent, ApiError> {
    routing
        .disable_route
        .execute(&tenant.caller, &tenant.auditor, path.route())
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes/{id}/open-to-workflows",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such route", body = ErrorBody),
        (status = 422, description = "Already open to workflows", body = ErrorBody)
    )
)]
/// Open a route to workflows
///
/// Lets the tenant's workflows call the route with a Protected apps step,
/// as the person each run acts for. The route's own policy still decides
/// every call, exactly as it would for that person signing in.
///
/// **State.** `closed -> open`. Returns `404` if the route does not exist,
/// or `422` if it is open already. Records
/// `routing.route_opened_to_workflows`. Requires `Routing(Update)`.
pub(crate) async fn open_route_to_workflows(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<RoutePath>,
) -> Result<NoContent, ApiError> {
    let request = SetWorkflowUseRequest {
        route_id: path.route(),
        workflow_use: WorkflowUse::Open,
    };
    routing
        .set_route_workflow_use
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes/{id}/close-to-workflows",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such route", body = ErrorBody),
        (status = 422, description = "Already closed to workflows", body = ErrorBody)
    )
)]
/// Close a route to workflows
///
/// Stops the tenant's workflows calling the route: from the next request
/// on, every Protected apps step's call to it is refused at the gateway.
///
/// **State.** `open -> closed`. Returns `404` if the route does not exist,
/// or `422` if it is closed already. Records
/// `routing.route_closed_to_workflows`. Requires `Routing(Update)`.
pub(crate) async fn close_route_to_workflows(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<RoutePath>,
) -> Result<NoContent, ApiError> {
    let request = SetWorkflowUseRequest {
        route_id: path.route(),
        workflow_use: WorkflowUse::Closed,
    };
    routing
        .set_route_workflow_use
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes/{id}/attack-mode",
    tag = "Routing",
    request_body = StartAttackModeBody,
    responses(
        (status = 200, description = "In attack mode until", body = AttackModeResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such route", body = ErrorBody),
        (status = 422, description = "Minutes outside 5 to 1440", body = ErrorBody)
    )
)]
/// Start attack mode on a route
///
/// Checks every request to the route harder for the minutes given, before
/// its pipeline: an address any tenant's decoys or recon scoring caught is
/// refused, and each address may send 60 requests a minute, refused with
/// `429` past that. It ends on its own; starting it again restarts the
/// time from now.
///
/// Records `routing.route_attack_mode_started`. Requires `Routing(Update)`.
pub(crate) async fn start_route_attack_mode(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<RoutePath>,
    Json(body): Json<StartAttackModeBody>,
) -> Result<Json<AttackModeResponse>, ApiError> {
    let mode = routing
        .set_route_attack_mode
        .execute(&tenant.caller, &tenant.auditor, body.request(path.route())?)
        .await?;
    Ok(Json(AttackModeResponse::from(mode)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes/{id}/attack-mode",
    tag = "Routing",
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such route", body = ErrorBody),
        (status = 422, description = "Not in attack mode", body = ErrorBody)
    )
)]
/// End a route's attack mode
///
/// Ends attack mode before its time; the route is checked as its pipeline
/// says from the next request on.
///
/// Returns `422` when the route is not in attack mode. Records
/// `routing.route_attack_mode_ended`. Requires `Routing(Update)`.
pub(crate) async fn end_route_attack_mode(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<RoutePath>,
) -> Result<NoContent, ApiError> {
    let request = SetAttackModeRequest {
        route_id: path.route(),
        change: AttackChange::End,
    };
    routing
        .set_route_attack_mode
        .execute(&tenant.caller, &tenant.auditor, request)
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/metrics/routes",
    tag = "Routing",
    params(MetricsWindowQuery, RouteTrafficParams),
    responses(
        (status = 200, description = "Per-route traffic", body = RouteTrafficListResponse),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such tenant", body = ErrorBody),
        (status = 422, description = "Validation error", body = ErrorBody)
    )
)]
/// Per-route traffic
///
/// Requests, refusals, upstream failures and latency for each route that
/// served traffic in the `window`, busiest first. A route deleted since is
/// still listed, with a null name: its requests happened, and dropping them
/// would make the totals disagree with the overview. Requests that matched no
/// route are left out; they belong to the tenant, not to a route. Read-only.
/// Requires `Metrics(View)`.
pub(crate) async fn list_route_traffic(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    MetricsWindowQuery(window): MetricsWindowQuery,
    Query(params): Query<RouteTrafficParams>,
) -> Result<Json<RouteTrafficListResponse>, ApiError> {
    let traffic = routing
        .route_traffic
        .execute(&tenant.caller, params.request(window))
        .await?;
    Ok(Json(RouteTrafficListResponse::over(window, traffic)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/routes/{id}/conditions",
    tag = "Routing",
    request_body = RouteConditionsBody,
    responses(
        (status = 204, description = "No content"),
        (status = 401, description = "Unauthenticated", body = ErrorBody),
        (status = 403, description = "Forbidden", body = ErrorBody),
        (status = 404, description = "No such route", body = ErrorBody),
        (status = 422, description = "More than 16 conditions, or one header or cookie named twice", body = ErrorBody)
    )
)]
/// Set a route's request conditions
///
/// Replaces the header and cookie conditions a request must all meet for
/// the route to match it. Two routes on one path can then send requests to
/// two backends by what they carry: a blue/green switch on a header, or a
/// canary pinned by a cookie. A value is matched exactly or by its start,
/// never by a pattern. An empty list matches every request. Records
/// `routing.route_updated`. Requires `Routing(Update)`.
pub(crate) async fn change_route_conditions(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
    Path(path): Path<RoutePath>,
    Json(body): Json<RouteConditionsBody>,
) -> Result<NoContent, ApiError> {
    routing
        .change_route_conditions
        .execute(
            &tenant.caller,
            &tenant.auditor,
            body.into_request(path.route()),
        )
        .await?;
    Ok(NoContent)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/me/apps",
    tag = "Routing",
    responses(
        (status = 200, description = "Success", body = Vec<OpenableAppResponse>),
        (status = 401, description = "Unauthenticated", body = ErrorBody)
    )
)]
/// List the apps I may open
///
/// The caller's start page: each active app whose fixed path a `GET` would
/// be let through by the gateway's own access decision for them now, or
/// let through once they prove more. What only a real request shows, such
/// as their country or device, counts as unknown. Opening an app is
/// decided again by the gateway. Needs a signed-in tenant session.
pub(crate) async fn list_my_apps(
    State(routing): State<RoutingState>,
    tenant: TenantCaller,
) -> Result<Json<Vec<OpenableAppResponse>>, ApiError> {
    let apps = routing.list_openable.execute(&tenant.caller, ()).await?;
    Ok(Json(
        apps.into_iter().map(OpenableAppResponse::from).collect(),
    ))
}
