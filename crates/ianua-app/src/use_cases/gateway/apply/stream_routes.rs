//! Writing the stream routes a document declares, held to the same checks
//! as opening and editing one by hand.

use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::stream::access::{StreamAccess, StreamConsumers};
use ianua_domain::domains::routing::stream::{CreateStreamRouteParams, StreamRoute};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{ConsumerId, Label};

use crate::error::AppError;
use crate::ports::limits::ResourceKind;
use crate::use_cases::gateway::apply::state::{
    Apply, declared, ensure_within_limit, invalid, missing_reference, settle_status,
};
use crate::use_cases::gateway::document::{StreamAccessDeclaration, StreamRouteDeclaration};
use crate::use_cases::routing::lookup::ensure_policy_permissions_declared;
use crate::use_cases::routing::stream_routes::access::change_admission;

/// Writes the stream route the document declares under `name`.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not create or update
///   routing, or a new route would exceed the plan.
/// - `AppError::Domain` when its access names a consumer the gateway would
///   not have or holds people to an undeclared permission, it changes the
///   protocol or port of a route that exists, or the domain refuses it.
/// - `AppError::Conflict` when its port is already claimed.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn write_stream_route(
    apply: &mut Apply<'_>,
    name: &Label,
) -> Result<(), AppError> {
    let desired = apply.desired;
    let want = declared(&desired.stream_routes, name, |r| &r.name)?;
    let access = resolved_access(apply, want)?;
    ensure_permissions_declared(apply, &access).await?;
    let by = apply.applier.by;
    let route = match apply.stream_routes.remove(name) {
        None => {
            ensure_within_limit(apply.applier, ResourceKind::StreamRoutes).await?;
            created(want, access, &by).map_err(AppError::from_domain)?
        }
        Some(route) => {
            ensure_same_socket(&route, want)?;
            updated(route, want, access, &by).map_err(AppError::from_domain)?
        }
    };
    apply
        .applier
        .ports
        .records
        .stream_route_store
        .save(&apply.tenant(), &route)
        .await
        .map_err(AppError::from_domain)?;
    apply.stream_routes.insert(name.clone(), route);
    Ok(())
}

/// The access `want` declares, its consumers found by name among those the
/// gateway holds as written so far.
fn resolved_access(
    apply: &Apply<'_>,
    want: &StreamRouteDeclaration,
) -> Result<StreamAccess, AppError> {
    match &want.access {
        StreamAccessDeclaration::AnyHolder => Ok(StreamAccess::AnyHolder),
        StreamAccessDeclaration::People(policy) => Ok(StreamAccess::People(policy.clone())),
        StreamAccessDeclaration::Consumers(names) => {
            let ids = names
                .iter()
                .map(|consumer| consumer_id(apply, want, consumer))
                .collect::<Result<Vec<_>, _>>()?;
            let named = StreamConsumers::new(ids).map_err(AppError::from_domain)?;
            Ok(StreamAccess::Consumers(named))
        }
    }
}

/// The id of the consumer `want` names `consumer`.
fn consumer_id(
    apply: &Apply<'_>,
    want: &StreamRouteDeclaration,
    consumer: &Label,
) -> Result<ConsumerId, AppError> {
    apply
        .consumers
        .get(consumer)
        .map(|found| *found.id())
        .ok_or_else(|| missing_reference(&want.name, "consumer", consumer))
}

/// Refuses people held to a permission the tenant's catalogue does not
/// declare.
async fn ensure_permissions_declared(
    apply: &Apply<'_>,
    access: &StreamAccess,
) -> Result<(), AppError> {
    let StreamAccess::People(policy) = access else {
        return Ok(());
    };
    let resource_types = apply.applier.ports.checks.resource_type_store.as_ref();
    ensure_policy_permissions_declared(resource_types, &apply.tenant(), policy).await
}

/// Refuses a change of protocol or port: that is another socket on another
/// listener, so a new route rather than an edit.
fn ensure_same_socket(
    route: &StreamRoute<ResolvedTenant>,
    want: &StreamRouteDeclaration,
) -> Result<(), AppError> {
    if route.protocol() == want.protocol && route.listen_port() == want.listen_port {
        return Ok(());
    }
    Err(invalid(format!(
        "stream route '{}' changes its protocol or port; remove it and declare a new one",
        want.name
    )))
}

/// A new stream route as `want` declares it, letting in `access`.
fn created(
    want: &StreamRouteDeclaration,
    access: StreamAccess,
    by: &RoutingControl<'_>,
) -> Result<StreamRoute<ResolvedTenant>, DomainError> {
    let mut route = StreamRoute::create(
        CreateStreamRouteParams {
            name: want.name.clone(),
            protocol: want.protocol,
            listen_port: want.listen_port,
            sni: want.sni.clone(),
            policy: want.policy,
            access,
            backends: want.backends.clone(),
            timeouts: want.timeouts,
        },
        by,
    )?;
    settle_status(&mut route, want.status, by)?;
    Ok(route)
}

/// `route` changed to what `want` declares, letting in `access`.
fn updated(
    mut route: StreamRoute<ResolvedTenant>,
    want: &StreamRouteDeclaration,
    access: StreamAccess,
    by: &RoutingControl<'_>,
) -> Result<StreamRoute<ResolvedTenant>, DomainError> {
    if route.sni() != &want.sni {
        route.change_sni(want.sni.clone(), by)?;
    }
    let policy = (route.policy() != want.policy).then_some(want.policy);
    let access = (route.access() != &access).then_some(access);
    change_admission(&mut route, policy, access, by)?;
    if route.backends() != want.backends.as_slice() {
        route.replace_backends(want.backends.clone(), by)?;
    }
    if route.timeouts() != want.timeouts {
        route.change_timeouts(want.timeouts, by)?;
    }
    settle_status(&mut route, want.status, by)?;
    Ok(route)
}
