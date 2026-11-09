//! Writing the routes a document declares, held to the same checks as
//! creating and editing one by hand.

use ianua_domain::domains::proxy::pipeline::Pipeline;
use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::route::{CreateRouteParams, Route};
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Label;

use crate::error::AppError;
use crate::ports::limits::ResourceKind;
use crate::use_cases::gateway::apply::state::{
    Applier, Apply, declared, ensure_within_limit, missing_reference, settle_status,
};
use crate::use_cases::gateway::document::RouteDeclaration;
use crate::use_cases::routing::lookup::{
    ensure_hosts_belong_to_tenant, ensure_policy_permissions_declared,
};
use crate::use_cases::routing::routes::retarget::{Retarget, RouteTargets, retarget};

/// Writes the route the document declares under `name`.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not create or update
///   routing, or a new route would exceed the plan.
/// - `AppError::Domain` when the route names a service or pipeline the
///   gateway would not have, a host the tenant has not verified, an
///   undeclared permission, or sign-in its service or pipeline cannot keep
///   apart, or its rewrite does not fit its pattern.
/// - `AppError::Conflict` when the store refuses the name.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn write_route(apply: &mut Apply<'_>, name: &Label) -> Result<(), AppError> {
    let desired = apply.desired;
    let want = declared(&desired.routes, name, |r| &r.name)?;
    ensure_references_known(apply.applier, want).await?;
    let existing = apply.routes.remove(name);
    if existing.is_none() {
        ensure_within_limit(apply.applier, ResourceKind::Routes).await?;
    }
    let next = declared_targets(apply, want)?;
    let by = apply.applier.by;
    let route = match existing {
        None => created_route(want, next, &by),
        Some(route) => {
            let current = current_targets(apply, &route)?;
            updated_route(route, want, Retarget { current, next }, &by)
        }
    }
    .map_err(AppError::from_domain)?;
    apply
        .applier
        .ports
        .records
        .route_store
        .save(&apply.tenant(), &route)
        .await
        .map_err(AppError::from_domain)?;
    apply.routes.insert(name.clone(), route);
    Ok(())
}

/// Refuses a route whose hosts the tenant has not verified or whose
/// required permissions its catalogue does not declare.
async fn ensure_references_known(
    applier: Applier<'_>,
    want: &RouteDeclaration,
) -> Result<(), AppError> {
    let tenant = applier.caller.tenant();
    ensure_hosts_belong_to_tenant(
        applier.ports.checks.domain_store.as_ref(),
        &tenant,
        &want.hosts,
        applier.platform,
    )
    .await?;
    ensure_policy_permissions_declared(
        applier.ports.checks.resource_type_store.as_ref(),
        &tenant,
        &want.policy,
    )
    .await
}

/// The service and pipeline `want` names, as written so far.
fn declared_targets<'a>(
    apply: &'a Apply<'_>,
    want: &RouteDeclaration,
) -> Result<RouteTargets<'a>, AppError> {
    let service = apply
        .services
        .get(&want.service)
        .ok_or_else(|| missing_reference(&want.name, "service", &want.service))?;
    let pipeline = apply
        .pipelines
        .get(&want.pipeline)
        .ok_or_else(|| missing_reference(&want.name, "pipeline", &want.pipeline))?;
    Ok(RouteTargets { service, pipeline })
}

/// The service `route` forwards to and the pipeline it runs now.
fn current_targets<'a>(
    apply: &'a Apply<'_>,
    route: &Route<ResolvedTenant>,
) -> Result<RouteTargets<'a>, AppError> {
    let service = apply
        .services
        .values()
        .find(|service: &&Service<ResolvedTenant>| service.id() == route.service_id());
    let pipeline = apply
        .pipelines
        .values()
        .find(|pipeline: &&Pipeline<ResolvedTenant>| pipeline.id() == route.pipeline_id());
    let (Some(service), Some(pipeline)) = (service, pipeline) else {
        return Err(AppError::internal_msg(format!(
            "route '{}' forwards to a service or runs a pipeline the tenant does not hold",
            route.name()
        )));
    };
    Ok(RouteTargets { service, pipeline })
}

/// A new route as `want` declares it.
fn created_route(
    want: &RouteDeclaration,
    targets: RouteTargets<'_>,
    by: &RoutingControl<'_>,
) -> Result<Route<ResolvedTenant>, DomainError> {
    let mut route = Route::create(
        CreateRouteParams {
            name: want.name.clone(),
            path_pattern: want.path_pattern.clone(),
            methods: want.methods.clone(),
            policy: want.policy.clone(),
            hosts: want.hosts.clone(),
            path_rewrite: want.path_rewrite.clone(),
            priority: want.priority,
        },
        targets.service,
        targets.pipeline,
        by,
    )?;
    redeclare(&mut route, want, by)?;
    if route.conditions() != &want.conditions {
        route.change_conditions(want.conditions.clone(), by)?;
    }
    settle_status(&mut route, want.status, by)?;
    Ok(route)
}

/// `route` changed to what `want` declares.
fn updated_route(
    mut route: Route<ResolvedTenant>,
    want: &RouteDeclaration,
    targets: Retarget<'_>,
    by: &RoutingControl<'_>,
) -> Result<Route<ResolvedTenant>, DomainError> {
    rematch(&mut route, want, by)?;
    redeclare(&mut route, want, by)?;
    let policy = (route.policy() != &want.policy).then(|| want.policy.clone());
    retarget(&mut route, policy, targets, by)?;
    settle_status(&mut route, want.status, by)?;
    Ok(route)
}

/// Changes which requests `route` matches to what `want` declares.
fn rematch(
    route: &mut Route<ResolvedTenant>,
    want: &RouteDeclaration,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    if route.path_pattern() != &want.path_pattern || route.path_rewrite() != &want.path_rewrite {
        route.change_path(want.path_pattern.clone(), want.path_rewrite.clone(), by)?;
    }
    if route.methods() != want.methods.as_slice() {
        route.change_methods(want.methods.clone(), by)?;
    }
    if route.priority() != want.priority {
        route.change_priority(want.priority, by)?;
    }
    if route.conditions() != &want.conditions {
        route.change_conditions(want.conditions.clone(), by)?;
    }
    if route.hosts() == &want.hosts {
        return Ok(());
    }
    route.change_hosts(want.hosts.clone(), by)
}

/// Changes what `route` declares about the data and actions behind it to
/// what `want` says.
fn redeclare(
    route: &mut Route<ResolvedTenant>,
    want: &RouteDeclaration,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    if route.data_class() != want.data_class {
        route.declare_data_class(want.data_class, by)?;
    }
    if route.declared_action_class() != want.action_class {
        route.declare_action_class(want.action_class, by)?;
    }
    if route.reach() != want.reach {
        route.declare_reach(want.reach, by)?;
    }
    if route.parameter_rules() == want.parameter_rules.as_slice() {
        return Ok(());
    }
    route.replace_parameter_rules(want.parameter_rules.clone(), by)
}
