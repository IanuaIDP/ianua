//! Giving each changed service the app sign-in its declaration states, once
//! the routes it is checked against are in place, held to the same rules as
//! setting it by hand.

use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::routing::sign_in::accepted::AcceptedSignIn;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::Setting;

use crate::error::AppError;
use crate::use_cases::gateway::apply::state::{Apply, declared, invalid, missing_sign_in_owner};
use crate::use_cases::gateway::diff::{ChangeKind, ConfigDiff, ResourceKind};
use crate::use_cases::gateway::document::ServiceDeclaration;
use crate::use_cases::routing::lookup::all_routes;
use crate::use_cases::routing::services::sign_in_checks::{
    AcceptanceChecks, SignInPlacement, SignInSettings, apply_sign_in, ensure_accepts, ensure_fits,
};

/// Sets the app sign-in of every service the plan creates or updates.
///
/// Services signing people in go first, so one accepting another's sign-in
/// finds it there.
///
/// # Errors
///
/// - `AppError::Forbidden` when the caller may not update routing.
/// - `AppError::Domain` when a sign-in breaks a rule setting it by hand is
///   held to, or a service accepts the sign-in of one that does not exist.
/// - `AppError::Conflict` when a sign-in host is another service's.
/// - `AppError::Internal` on storage failure.
pub(crate) async fn settle_app_sign_in(
    apply: &mut Apply<'_>,
    plan: &ConfigDiff,
) -> Result<(), AppError> {
    let desired = apply.desired;
    let changed = plan
        .effective()
        .into_iter()
        .filter(|change| change.resource == ResourceKind::Service)
        .filter(|change| change.kind != ChangeKind::Delete)
        .map(|change| declared(&desired.services, &change.name, |s| &s.name))
        .collect::<Result<Vec<_>, _>>()?;
    if changed.is_empty() {
        return Ok(());
    }
    let routes = all_routes(
        apply.applier.ports.records.route_store.as_ref(),
        &apply.tenant(),
    )
    .await?;
    let (owners, others): (Vec<_>, Vec<_>) = changed
        .into_iter()
        .partition(|want| !want.app_sign_in.is_unset());
    for want in owners.into_iter().chain(others) {
        settle_one(apply, want, &routes).await?;
    }
    Ok(())
}

/// Gives the service `want` declares the sign-in it states.
async fn settle_one(
    apply: &mut Apply<'_>,
    want: &ServiceDeclaration,
    routes: &[Route<ResolvedTenant>],
) -> Result<(), AppError> {
    let accepted = accepted_of(apply, want, routes).await?;
    let mut service = apply
        .services
        .get(&want.name)
        .cloned()
        .ok_or_else(|| unwritten(want))?;
    let unchanged = service.app_sign_in() == want.app_sign_in.value()
        && service.accepted_sign_in() == accepted.value();
    if unchanged {
        return Ok(());
    }
    ensure_own_fits(apply, &service, want, routes).await?;
    let (ports, tenant) = (apply.applier.ports, apply.tenant());
    let settings = SignInSettings {
        own: want.app_sign_in.clone(),
        accepted,
    };
    apply_sign_in(&mut service, settings, &apply.applier.by).map_err(AppError::from_domain)?;
    ports
        .records
        .service_store
        .save(&tenant, &service)
        .await
        .map_err(AppError::from_domain)?;
    apply.services.insert(want.name.clone(), service);
    Ok(())
}

/// Refuses the sign-in `want` gives `service` of its own unless it fits the
/// routes and domains it sits among.
async fn ensure_own_fits(
    apply: &Apply<'_>,
    service: &Service<ResolvedTenant>,
    want: &ServiceDeclaration,
    routes: &[Route<ResolvedTenant>],
) -> Result<(), AppError> {
    let Setting::Set(sign_in) = &want.app_sign_in else {
        return Ok(());
    };
    let placement = SignInPlacement {
        service,
        routes,
        sign_in,
    };
    let store = apply.applier.ports.checks.domain_store.as_ref();
    ensure_fits(store, &apply.tenant(), placement, apply.applier.platform).await
}

/// The sign-in `want` accepts, found by name and held to the rules of
/// accepting it by hand.
async fn accepted_of(
    apply: &Apply<'_>,
    want: &ServiceDeclaration,
    routes: &[Route<ResolvedTenant>],
) -> Result<Setting<AcceptedSignIn>, AppError> {
    let Setting::Set(declared) = &want.accepts_app_sign_in else {
        return Ok(Setting::Unset);
    };
    let owner = apply
        .services
        .get(&declared.owner)
        .ok_or_else(|| missing_sign_in_owner(&want.name, &declared.owner))?;
    let service = apply
        .services
        .get(&want.name)
        .ok_or_else(|| unwritten(want))?;
    let accepted = AcceptedSignIn::new(*owner.id(), declared.delivery.clone());
    let tenant = apply.tenant();
    let checks = AcceptanceChecks {
        platform: apply.applier.platform,
        domain_store: apply.applier.ports.checks.domain_store.as_ref(),
        site_rules: apply.applier.ports.checks.site_rules.as_ref(),
        tenant: &tenant,
        routes,
    };
    ensure_accepts(&checks, service, owner, &accepted).await?;
    Ok(Setting::Set(accepted))
}

fn unwritten(want: &ServiceDeclaration) -> AppError {
    invalid(format!("'{}' is planned but was not written", want.name))
}
