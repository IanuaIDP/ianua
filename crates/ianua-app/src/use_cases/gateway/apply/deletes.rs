//! Removing what a replace leaves out, each only once the domain agrees it
//! may go, as deleting it by hand would need.

use ianua_domain::types::Label;

use crate::error::{AppError, OrInternal};
use crate::use_cases::gateway::apply::consumers::delete_consumer;
use crate::use_cases::gateway::apply::egress::delete_egress_policy;
use crate::use_cases::gateway::apply::state::{Apply, pipeline_refused};
use crate::use_cases::gateway::diff::{ChangeKind, ConfigDiff, ResourceChange, ResourceKind};
use crate::use_cases::routing::lookup::{routes_on, routes_to, services_accepting};

/// Refuses a plan that would delete a route still taking traffic, before
/// anything is written.
///
/// Pipelines and services are judged when their turn comes, against the
/// routes the apply has left by then. A route is judged on its own, so a
/// plan that would stop at one is refused whole instead of halfway.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not delete routing.
/// - `AppError::Domain` when a route to delete is still active.
pub(crate) fn ensure_routes_deletable(
    apply: &Apply<'_>,
    plan: &ConfigDiff,
) -> Result<(), AppError> {
    plan.changes
        .iter()
        .filter(|change| change.kind == ChangeKind::Delete)
        .filter(|change| change.resource == ResourceKind::Route)
        .filter_map(|change| apply.routes.get(&change.name))
        .try_for_each(|route| route.ensure_deletable(&apply.applier.by))
        .map_err(AppError::from_domain)
}

/// Removes the resource `change` names, if it still exists.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not delete it.
/// - `AppError::Domain` when a route is still active.
/// - `AppError::Conflict` when a route still runs the pipeline or forwards
///   to the service, or another service accepts the service's sign-in.
/// - `AppError::Forbidden` when the caller may not delete a consumer.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn delete_resource(
    apply: &mut Apply<'_>,
    change: &ResourceChange,
) -> Result<(), AppError> {
    match change.resource {
        ResourceKind::Route => delete_route(apply, &change.name).await,
        ResourceKind::Pipeline => delete_pipeline(apply, &change.name).await,
        ResourceKind::Service => delete_service(apply, &change.name).await,
        ResourceKind::StreamRoute => delete_stream_route(apply, &change.name).await,
        ResourceKind::EgressPolicy => delete_egress_policy(apply, &change.name).await,
        ResourceKind::Consumer => delete_consumer(apply, &change.name).await,
    }
}

/// Removes the stream route `name`, if it still exists, freeing its port.
async fn delete_stream_route(apply: &mut Apply<'_>, name: &Label) -> Result<(), AppError> {
    let Some(mut route) = apply.stream_routes.remove(name) else {
        return Ok(());
    };
    route
        .delete(&apply.applier.by)
        .map_err(AppError::from_domain)?;
    apply
        .applier
        .ports
        .records
        .stream_route_store
        .delete(&apply.tenant(), route.id())
        .await
        .or_internal()
}

async fn delete_route(apply: &mut Apply<'_>, name: &Label) -> Result<(), AppError> {
    let Some(mut route) = apply.routes.remove(name) else {
        return Ok(());
    };
    route
        .delete(&apply.applier.by)
        .map_err(AppError::from_domain)?;
    apply
        .applier
        .ports
        .records
        .route_store
        .delete(&apply.tenant(), route.id())
        .await
        .or_internal()
}

async fn delete_pipeline(apply: &mut Apply<'_>, name: &Label) -> Result<(), AppError> {
    let Some(mut pipeline) = apply.pipelines.remove(name) else {
        return Ok(());
    };
    let (ports, tenant) = (apply.applier.ports, apply.tenant());
    let routes = routes_on(ports.records.route_store.as_ref(), &tenant, pipeline.id()).await?;
    pipeline
        .delete(&routes, &apply.applier.by)
        .map_err(pipeline_refused)?;
    ports
        .records
        .pipeline_store
        .delete(&tenant, pipeline.id())
        .await
        .map_err(AppError::from_domain)
}

async fn delete_service(apply: &mut Apply<'_>, name: &Label) -> Result<(), AppError> {
    let Some(mut service) = apply.services.remove(name) else {
        return Ok(());
    };
    let (ports, tenant) = (apply.applier.ports, apply.tenant());
    let routes = routes_to(ports.records.route_store.as_ref(), &tenant, service.id()).await?;
    let accepting =
        services_accepting(ports.records.service_store.as_ref(), &tenant, service.id()).await?;
    service
        .delete(&routes, &accepting, &apply.applier.by)
        .map_err(AppError::from_domain)?;
    ports
        .records
        .service_store
        .delete(&tenant, service.id())
        .await
        .map_err(AppError::from_domain)
}
