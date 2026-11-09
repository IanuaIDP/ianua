//! Routing endpoints: a tenant's routes and their traffic, services and
//! their sign-in and upstream TLS, stream routes, egress policies and
//! private-network connectors, with the enrollment their agents call.

use axum::Router;
use utoipa::OpenApi;

use crate::dto::metrics::MetricsWindowResponse;
use crate::dto::routing::connectors::{
    ChangeConnectorScopeBody, ConnectorCertificateResponse, ConnectorEnrollmentView,
    ConnectorResponse, CreateConnectorBody, CreateConnectorResponse, EnrollConnectorBody,
    RenewConnectorBody,
};
use crate::dto::routing::egress::{
    CreateEgressPolicyBody, CreatorKind, CreatorResponse, EgressDestinationBody,
    EgressPolicyResponse, UpdateEgressPolicyBody,
};
use crate::dto::routing::routes::{
    AttackModeResponse, CreateRouteBody, CreateRouteResponse, OpenableAppResponse, PathRewriteBody,
    RouteConditionsBody, RouteResponse, RouteTrafficListResponse, RouteTrafficResponse,
    StartAttackModeBody, UpdateRouteBody,
};
use crate::dto::routing::services::{
    BackendHealthView, ChangeServiceTlsBody, ClientCertificateBody, CreateServiceBody,
    CreateServiceResponse, HealthCheckBody, ServiceHealthResponse, ServiceResponse,
    UpdateServiceBody, UpstreamTlsBody, UpstreamTlsView,
};
use crate::dto::routing::sign_in::{
    AppSignInBody, AppSignInSettings, AppSignInView, SignInAddresses, SignInDeliveryBody,
    SignInPaths, SignedOutBrowsersBody,
};
use crate::dto::routing::stream_routes::{
    CreateStreamRouteBody, CreateStreamRouteResponse, StreamBackendBody, StreamRouteResponse,
    StreamSniBody, StreamTimeoutsBody, UpdateStreamRouteBody,
};
use crate::dto::routing::stream_workflows::{LoginTlsBody, OpenStreamRouteToWorkflowsBody};
use crate::handlers::routing::{connectors, egress, routes, services, stream_routes};
use crate::method::{get, post, put, shared};
use crate::middleware::ip_rate_limit::{ip_rate_limit, per_address};
use crate::state::ApiState;

/// The endpoints a connector's agent enrolls and renews its certificate
/// at, with no session or key, limited per client address.
pub(crate) fn public_routes(state: &ApiState) -> Router<ApiState> {
    let window = state.http.rate.sensitive;
    let limiter = per_address(state, window.max, window.window);
    Router::new()
        .route(
            "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/connectors/enroll",
            post(connectors::enroll_connector),
        )
        .route(
            "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}/connectors/{id}/renew",
            post(connectors::renew_connector),
        )
        .layer(axum::middleware::from_fn_with_state(limiter, ip_rate_limit))
}

/// The routing endpoints.
pub(crate) fn routes() -> Router<ApiState> {
    let tenant = "/api/v1/organizations/{org_slug}/tenants/{tenant_slug}";
    http_routes(tenant)
        .merge(service_routes(tenant))
        .merge(stream_route_routes(tenant))
        .merge(egress_routes(tenant))
        .merge(connector_routes(tenant))
}

/// HTTP route definitions, standing, and workflow access.
fn http_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/routes"),
            post(routes::create_route).get(shared(routes::list_routes)),
        )
        .route(
            &format!("{tenant}/routes/{{id}}"),
            get(routes::get_route)
                .patch(shared(routes::update_route))
                .delete(shared(routes::delete_route)),
        )
        .route(
            &format!("{tenant}/routes/{{id}}/activate"),
            post(routes::activate_route),
        )
        .route(
            &format!("{tenant}/routes/{{id}}/disable"),
            post(routes::disable_route),
        )
        .route(
            &format!("{tenant}/routes/{{id}}/open-to-workflows"),
            post(routes::open_route_to_workflows),
        )
        .route(
            &format!("{tenant}/routes/{{id}}/close-to-workflows"),
            post(routes::close_route_to_workflows),
        )
        .route(&format!("{tenant}/me/apps"), get(routes::list_my_apps))
        .merge(traffic_routes(tenant))
}

/// Attack protection, request conditions, and measured HTTP traffic.
fn traffic_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/routes/{{id}}/attack-mode"),
            post(routes::start_route_attack_mode).delete(routes::end_route_attack_mode),
        )
        .route(
            &format!("{tenant}/routes/{{id}}/conditions"),
            put(routes::change_route_conditions),
        )
        .route(
            &format!("{tenant}/metrics/routes"),
            get(routes::list_route_traffic),
        )
}

/// Service backends, their health, and upstream authentication.
fn service_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/services"),
            post(services::create_service).get(shared(services::list_services)),
        )
        .route(
            &format!("{tenant}/services/{{id}}"),
            get(services::get_service)
                .patch(shared(services::update_service))
                .delete(shared(services::delete_service)),
        )
        .route(
            &format!("{tenant}/services/{{id}}/health"),
            get(services::get_service_health),
        )
        .route(
            &format!("{tenant}/services/{{id}}/app-sign-in"),
            put(services::configure_app_sign_in),
        )
        .route(
            &format!("{tenant}/services/{{id}}/tls"),
            put(services::change_service_tls).delete(shared(services::remove_service_tls)),
        )
}

/// Stream route definitions, standing, and workflow access.
fn stream_route_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/stream-routes"),
            post(stream_routes::create_stream_route).get(shared(stream_routes::list_stream_routes)),
        )
        .route(
            &format!("{tenant}/stream-routes/{{id}}"),
            get(stream_routes::get_stream_route)
                .patch(shared(stream_routes::update_stream_route))
                .delete(shared(stream_routes::delete_stream_route)),
        )
        .route(
            &format!("{tenant}/stream-routes/{{id}}/activate"),
            post(stream_routes::activate_stream_route),
        )
        .route(
            &format!("{tenant}/stream-routes/{{id}}/disable"),
            post(stream_routes::disable_stream_route),
        )
        .route(
            &format!("{tenant}/stream-routes/{{id}}/open-to-workflows"),
            post(stream_routes::open_stream_route_to_workflows),
        )
        .route(
            &format!("{tenant}/stream-routes/{{id}}/close-to-workflows"),
            post(stream_routes::close_stream_route_to_workflows),
        )
}

/// Tenant egress policy definitions and their removal.
fn egress_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/egress-policies"),
            post(egress::create_egress_policy).get(shared(egress::list_egress_policies)),
        )
        .route(
            &format!("{tenant}/egress-policies/{{id}}"),
            get(egress::get_egress_policy)
                .patch(shared(egress::update_egress_policy))
                .delete(shared(egress::delete_egress_policy)),
        )
}

/// Private-network connector registration, scope, and revocation.
fn connector_routes(tenant: &str) -> Router<ApiState> {
    Router::new()
        .route(
            &format!("{tenant}/connectors"),
            post(connectors::create_connector).get(shared(connectors::list_connectors)),
        )
        .route(
            &format!("{tenant}/connectors/{{id}}"),
            get(connectors::get_connector).delete(shared(connectors::delete_connector)),
        )
        .route(
            &format!("{tenant}/connectors/{{id}}/scope"),
            put(connectors::change_connector_scope),
        )
        .route(
            &format!("{tenant}/connectors/{{id}}/revoke"),
            post(connectors::revoke_connector),
        )
}

/// The routing part of the OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        routes::create_route,
        routes::list_routes,
        routes::get_route,
        routes::list_my_apps,
        routes::update_route,
        routes::delete_route,
        routes::activate_route,
        routes::disable_route,
        routes::open_route_to_workflows,
        routes::close_route_to_workflows,
        routes::start_route_attack_mode,
        routes::end_route_attack_mode,
        routes::change_route_conditions,
        routes::list_route_traffic,
        services::create_service,
        services::list_services,
        services::get_service,
        services::get_service_health,
        services::update_service,
        services::delete_service,
        services::configure_app_sign_in,
        services::change_service_tls,
        services::remove_service_tls,
        stream_routes::create_stream_route,
        stream_routes::list_stream_routes,
        stream_routes::get_stream_route,
        stream_routes::update_stream_route,
        stream_routes::delete_stream_route,
        stream_routes::activate_stream_route,
        stream_routes::disable_stream_route,
        stream_routes::open_stream_route_to_workflows,
        stream_routes::close_stream_route_to_workflows,
        egress::create_egress_policy,
        egress::list_egress_policies,
        egress::get_egress_policy,
        egress::update_egress_policy,
        egress::delete_egress_policy,
        connectors::create_connector,
        connectors::list_connectors,
        connectors::get_connector,
        connectors::change_connector_scope,
        connectors::revoke_connector,
        connectors::delete_connector,
        connectors::enroll_connector,
        connectors::renew_connector,
    ),
    components(schemas(
        CreateRouteBody,
        UpdateRouteBody,
        RouteConditionsBody,
        ChangeServiceTlsBody,
        UpstreamTlsBody,
        ClientCertificateBody,
        UpstreamTlsView,
        CreateConnectorBody,
        CreateConnectorResponse,
        ChangeConnectorScopeBody,
        ConnectorResponse,
        ConnectorEnrollmentView,
        EnrollConnectorBody,
        RenewConnectorBody,
        ConnectorCertificateResponse,
        PathRewriteBody,
        RouteResponse,
        OpenableAppResponse,
        CreateRouteResponse,
        StartAttackModeBody,
        AttackModeResponse,
        RouteTrafficResponse,
        RouteTrafficListResponse,
        MetricsWindowResponse,
        CreateServiceBody,
        UpdateServiceBody,
        HealthCheckBody,
        ServiceResponse,
        ServiceHealthResponse,
        BackendHealthView,
        CreateServiceResponse,
        AppSignInBody,
        AppSignInSettings,
        AppSignInView,
        SignInAddresses,
        SignInDeliveryBody,
        SignInPaths,
        SignedOutBrowsersBody,
        CreateStreamRouteBody,
        UpdateStreamRouteBody,
        StreamBackendBody,
        StreamSniBody,
        StreamTimeoutsBody,
        StreamRouteResponse,
        CreateStreamRouteResponse,
        OpenStreamRouteToWorkflowsBody,
        LoginTlsBody,
        CreateEgressPolicyBody,
        UpdateEgressPolicyBody,
        EgressDestinationBody,
        EgressPolicyResponse,
        CreatorResponse,
        CreatorKind,
    ))
)]
pub(crate) struct Document;
