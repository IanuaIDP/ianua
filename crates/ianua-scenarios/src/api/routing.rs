//! A tenant's routing: services, pipelines and their stages, routes,
//! stream routes, and the names the tenant is reached on.

use super::{Request, TenantPath};
use crate::net::Call;
use crate::wire::app_sign_in::ConfigureAppSignIn;
use crate::wire::routing::{
    DeclaredAction, Hostnames, Made, NewPipeline, NewRoute, NewService, NewStage, NewStreamRoute,
    OpenableApp, PolicyChange, RouteChange, WorkflowLogin,
};

/// `POST …/services`.
#[must_use]
pub fn create_service(tenant: &TenantPath, service: &NewService) -> Request<Made> {
    Request::of(Call::post(tenant.at("/services")).json(service))
}

/// `POST …/pipelines`.
#[must_use]
pub fn create_pipeline(tenant: &TenantPath, pipeline: &NewPipeline) -> Request<Made> {
    Request::of(Call::post(tenant.at("/pipelines")).json(pipeline))
}

/// `POST …/pipelines/{id}/stages`: appends the stage, answering no content.
#[must_use]
pub fn add_stage(tenant: &TenantPath, pipeline_id: &str, stage: &NewStage) -> Request<()> {
    let path = tenant.at(&format!("/pipelines/{pipeline_id}/stages"));
    Request::of(Call::post(path).json(stage))
}

/// `POST …/pipelines/{id}/activate`.
#[must_use]
pub fn activate_pipeline(tenant: &TenantPath, pipeline_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/pipelines/{pipeline_id}/activate")),
    ))
}

/// `POST …/routes`.
#[must_use]
pub fn create_route(tenant: &TenantPath, route: &NewRoute) -> Request<Made> {
    Request::of(Call::post(tenant.at("/routes")).json(route))
}

/// `PATCH …/routes/{id}`: changes the route; a field left out keeps its
/// value.
#[must_use]
pub fn change_route(tenant: &TenantPath, route_id: &str, change: &RouteChange) -> Request<()> {
    Request::of(Call::patch(tenant.at(&format!("/routes/{route_id}"))).json(change))
}

/// `PATCH …/routes/{id}` with only the kind of action the route takes.
#[must_use]
pub fn declare_action(
    tenant: &TenantPath,
    route_id: &str,
    declared: &DeclaredAction,
) -> Request<()> {
    Request::of(Call::patch(tenant.at(&format!("/routes/{route_id}"))).json(declared))
}

/// `PATCH …/routes/{id}` with only what the route asks of a caller.
#[must_use]
pub fn change_policy(tenant: &TenantPath, route_id: &str, change: &PolicyChange) -> Request<()> {
    Request::of(Call::patch(tenant.at(&format!("/routes/{route_id}"))).json(change))
}

/// `POST …/routes/{id}/disable`: takes the route down and keeps it.
#[must_use]
pub fn disable_route(tenant: &TenantPath, route_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/routes/{route_id}/disable")),
    ))
}

/// `POST …/routes/{id}/activate`: puts a disabled route back up.
#[must_use]
pub fn activate_route(tenant: &TenantPath, route_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/routes/{route_id}/activate")),
    ))
}

/// `POST …/routes/{id}/open-to-workflows`: lets the tenant's workflows
/// call the route as the person each run acts for.
#[must_use]
pub fn open_route_to_workflows(tenant: &TenantPath, route_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/routes/{route_id}/open-to-workflows")),
    ))
}

/// `POST …/routes/{id}/close-to-workflows`: stops the tenant's workflows
/// calling the route.
#[must_use]
pub fn close_route_to_workflows(tenant: &TenantPath, route_id: &str) -> Request<()> {
    Request::of(Call::post(
        tenant.at(&format!("/routes/{route_id}/close-to-workflows")),
    ))
}

/// `DELETE …/routes/{id}/attack-mode`: ends the route's attack mode early.
#[must_use]
pub fn end_attack_mode(tenant: &TenantPath, route_id: &str) -> Request<()> {
    Request::of(Call::delete(
        tenant.at(&format!("/routes/{route_id}/attack-mode")),
    ))
}

/// `POST …/stream-routes`.
#[must_use]
pub fn create_stream_route(tenant: &TenantPath, route: &NewStreamRoute) -> Request<Made> {
    Request::of(Call::post(tenant.at("/stream-routes")).json(route))
}

/// `POST …/stream-routes/{id}/open-to-workflows`: lets the tenant's
/// workflows reach the stream route as the person each run acts for,
/// signing in with `login`.
#[must_use]
pub fn open_stream_route_to_workflows(
    tenant: &TenantPath,
    stream_route_id: &str,
    login: &WorkflowLogin,
) -> Request<()> {
    let path = tenant.at(&format!(
        "/stream-routes/{stream_route_id}/open-to-workflows"
    ));
    Request::of(Call::post(path).json(login))
}

/// `POST …/stream-routes/{id}/close-to-workflows`: stops the tenant's
/// workflows reaching the stream route, and forgets its login.
#[must_use]
pub fn close_stream_route_to_workflows(tenant: &TenantPath, stream_route_id: &str) -> Request<()> {
    Request::of(Call::post(tenant.at(&format!(
        "/stream-routes/{stream_route_id}/close-to-workflows"
    ))))
}

/// `DELETE …/routes/{id}`: removes the route for good.
#[must_use]
pub fn remove_route(tenant: &TenantPath, route_id: &str) -> Request<()> {
    Request::of(Call::delete(tenant.at(&format!("/routes/{route_id}"))))
}

/// `GET …/hostname`.
#[must_use]
pub fn hostnames(tenant: &TenantPath) -> Request<Hostnames> {
    Request::of(Call::get(tenant.at("/hostname")))
}

/// `GET …/me/apps`: the start page of the person signed in, the apps the
/// gateway would let them open.
#[must_use]
pub fn my_apps(tenant: &TenantPath) -> Request<Vec<OpenableApp>> {
    Request::of(Call::get(tenant.at("/me/apps")))
}

/// `PUT …/services/{id}/app-sign-in`.
#[must_use]
pub fn configure_app_sign_in(
    tenant: &TenantPath,
    service_id: &str,
    settings: &ConfigureAppSignIn,
) -> Request<serde::de::IgnoredAny> {
    let path = tenant.at(&format!("/services/{service_id}/app-sign-in"));
    Request::of(Call::put(path).json(settings))
}
