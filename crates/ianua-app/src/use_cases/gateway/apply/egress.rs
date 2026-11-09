//! Writing the egress policies a document declares, through the same domain
//! steps as making and editing one by hand.

use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::egress::{CreateEgressPolicyParams, EgressPolicy};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Label;

use crate::error::{AppError, OrInternal};
use crate::ports::limits::ResourceKind;
use crate::use_cases::gateway::apply::state::{Apply, declared, ensure_within_limit};
use crate::use_cases::gateway::document::EgressPolicyDeclaration;

/// Writes the egress policy the document declares under `name`, matched
/// to the live one by the service it is for.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not create or update
///   routing, or a new policy would exceed the plan.
/// - `AppError::Domain` when the domain refuses its destinations.
/// - `AppError::Conflict` when the store already holds a policy for the
///   service.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn write_egress_policy(
    apply: &mut Apply<'_>,
    name: &Label,
) -> Result<(), AppError> {
    let desired = apply.desired;
    let want = declared(&desired.egress_policies, name, |p| &p.name)?;
    let by = apply.applier.by;
    let policy = match apply.egress_policies.remove(&want.service) {
        None => {
            ensure_within_limit(apply.applier, ResourceKind::EgressPolicies).await?;
            created(want, &by).map_err(AppError::from_domain)?
        }
        Some(policy) => updated(policy, want, &by).map_err(AppError::from_domain)?,
    };
    apply
        .applier
        .ports
        .records
        .egress_store
        .save(&apply.tenant(), &policy)
        .await
        .map_err(AppError::from_domain)?;
    apply
        .egress_policies
        .insert(policy.service().clone(), policy);
    Ok(())
}

/// Removes the live egress policy named `name` whose service the document
/// no longer declares, if one is left.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not delete routing.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn delete_egress_policy(
    apply: &mut Apply<'_>,
    name: &Label,
) -> Result<(), AppError> {
    let desired = apply.desired;
    let undeclared = apply
        .egress_policies
        .iter()
        .find(|(service, policy)| {
            policy.name() == name
                && !desired
                    .egress_policies
                    .iter()
                    .any(|p| &p.service == *service)
        })
        .map(|(service, _)| service.clone());
    let Some(mut policy) = undeclared.and_then(|service| apply.egress_policies.remove(&service))
    else {
        return Ok(());
    };
    policy
        .delete(&apply.applier.by)
        .map_err(AppError::from_domain)?;
    apply
        .applier
        .ports
        .records
        .egress_store
        .delete(&apply.tenant(), policy.id())
        .await
        .or_internal()
}

/// A new egress policy as `want` declares it.
fn created(
    want: &EgressPolicyDeclaration,
    by: &RoutingControl<'_>,
) -> Result<EgressPolicy<ResolvedTenant>, DomainError> {
    EgressPolicy::create(
        CreateEgressPolicyParams {
            name: want.name.clone(),
            service: want.service.clone(),
            destinations: want.destinations.clone(),
            max_data_class: want.max_data_class,
        },
        by,
    )
}

/// `policy` changed to what `want` declares, its name included.
fn updated(
    mut policy: EgressPolicy<ResolvedTenant>,
    want: &EgressPolicyDeclaration,
    by: &RoutingControl<'_>,
) -> Result<EgressPolicy<ResolvedTenant>, DomainError> {
    if policy.name() != &want.name {
        policy.rename(want.name.clone(), by)?;
    }
    if policy.destinations() != want.destinations.as_slice() {
        policy.replace_destinations(want.destinations.clone(), by)?;
    }
    if policy.max_data_class() != want.max_data_class {
        policy.change_max_data_class(want.max_data_class, by)?;
    }
    Ok(policy)
}
