//! The rules a service's app sign-in is held to beyond the service itself:
//! where it may answer among the tenant's routes and domains, and whose
//! sign-in it may accept. Setting it by hand and importing a gateway
//! document both go through these, so neither is a way around the other.

use ianua_domain::domains::routing::control::RoutingControl;
use ianua_domain::domains::routing::matching::host::RouteHosts;
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::routing::sign_in::accepted::AcceptedSignIn;
use ianua_domain::domains::routing::sign_in::app::{AppSignIn, SignInAction, SignInPath};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{DomainName, Setting};

use crate::error::AppError;
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::shared::SiteRules;
use crate::services::hosts::PlatformAddresses;
use crate::tenancy::ScopedTenant;
use crate::use_cases::routing::lookup::ensure_hosts_belong_to_tenant;

/// How a service signs people in from now on: its own app sign-in, and
/// whose sign-in it accepts instead.
pub struct SignInSettings {
    /// Its own app sign-in.
    pub own: Setting<AppSignIn>,
    /// Whose app sign-in it accepts, and how it reaches it.
    pub accepted: Setting<AcceptedSignIn>,
}

/// A service's own app sign-in, and the routes it sits among.
pub(crate) struct SignInPlacement<'a> {
    /// The service that signs people in.
    pub(crate) service: &'a Service<ResolvedTenant>,
    /// The tenant's routes.
    pub(crate) routes: &'a [Route<ResolvedTenant>],
    /// The sign-in settings being checked.
    pub(crate) sign_in: &'a AppSignIn,
}

/// What checking a service's acceptance of another's sign-in reads.
pub(crate) struct AcceptanceChecks<'a> {
    /// Current ownership of the deployment's tenant names.
    pub(crate) platform: Option<&'a PlatformAddresses>,
    /// The tenant's registered domains.
    pub(crate) domain_store: &'a dyn RegisteredDomainStore,
    /// Which hosts are on the same site.
    pub(crate) site_rules: &'a dyn SiteRules,
    /// The scope whose hosts and sign-in settings are being checked.
    pub(crate) tenant: &'a ScopedTenant,
    /// The tenant's routes.
    pub(crate) routes: &'a [Route<ResolvedTenant>],
}

/// Refuses `placement` unless every host is a verified domain of the tenant
/// that a route of the service answers on, and no route's own path is a
/// sign-in address there.
///
/// # Errors
///
/// - `AppError::Domain` naming the first rule broken.
/// - `AppError::Internal` if the tenant's domains cannot be read.
pub(crate) async fn ensure_fits(
    domain_store: &dyn RegisteredDomainStore,
    tenant: &ScopedTenant,
    placement: SignInPlacement<'_>,
    platform: Option<&PlatformAddresses>,
) -> Result<(), AppError> {
    let SignInPlacement {
        service,
        routes,
        sign_in,
    } = placement;
    ensure_hosts_verified(domain_store, tenant, sign_in.hosts(), platform).await?;
    ensure_served_on(service, routes, sign_in.hosts())?;
    ensure_no_route_hidden(routes, sign_in)
}

/// Refuses `accepted` for `service` unless `owner` has app sign-in, and the
/// hosts of a cookie of its own are verified domains of the tenant that a
/// route of the service answers on, on the same site as the owner's, with no
/// route's own path at the address the cookie is set from.
///
/// # Errors
///
/// - `AppError::Domain` naming the first rule broken.
/// - `AppError::Internal` if the tenant's domains cannot be read.
pub(crate) async fn ensure_accepts(
    checks: &AcceptanceChecks<'_>,
    service: &Service<ResolvedTenant>,
    owner: &Service<ResolvedTenant>,
    accepted: &AcceptedSignIn,
) -> Result<(), AppError> {
    ensure_signs_in(owner)?;
    let hosts = accepted.cookie_hosts();
    let Some(sign_in) = owner.app_sign_in().filter(|_| !hosts.is_empty()) else {
        return Ok(());
    };
    ensure_hosts_verified(checks.domain_store, checks.tenant, hosts, checks.platform).await?;
    ensure_served_on(service, checks.routes, hosts)?;
    ensure_same_site(checks.site_rules, hosts, sign_in)?;
    ensure_path_free(checks.routes, hosts, &sign_in.hop_path())
}

/// Refuses a cookie on a host of another site: it is never sent from the
/// owner's pages, so the service would be reached by nobody signed in there.
fn ensure_same_site(
    site_rules: &dyn SiteRules,
    hosts: &[DomainName],
    sign_in: &AppSignIn,
) -> Result<(), AppError> {
    let elsewhere = hosts.iter().find(|host| {
        !sign_in
            .hosts()
            .iter()
            .any(|own| site_rules.same_site(host, own))
    });
    let Some(host) = elsewhere else {
        return Ok(());
    };
    Err(invalid(format!(
        "{host} is not on the same site as the sign-in's domains, so the browser would not \
         send its cookie from their pages; use a domain under the same parent, or short-lived \
         tokens"
    )))
}

/// Refuses hosts that are not verified domains of the tenant.
async fn ensure_hosts_verified(
    domain_store: &dyn RegisteredDomainStore,
    tenant: &ScopedTenant,
    hosts: &[DomainName],
    platform: Option<&PlatformAddresses>,
) -> Result<(), AppError> {
    let hosts = RouteHosts::only(hosts.to_vec()).map_err(AppError::from_domain)?;
    ensure_hosts_belong_to_tenant(domain_store, tenant, &hosts, platform).await
}

/// Refuses accepting the sign-in of a service that has none: it would
/// accept nothing, and the dashboard would say otherwise.
fn ensure_signs_in(owner: &Service<ResolvedTenant>) -> Result<(), AppError> {
    if owner.app_sign_in().is_none() {
        return Err(invalid(format!(
            "{} has no app sign-in to accept",
            owner.name()
        )));
    }
    Ok(())
}

/// Refuses a host no route of the service answers on: sign-in addresses
/// there would hand out sessions nothing accepts.
fn ensure_served_on(
    service: &Service<ResolvedTenant>,
    routes: &[Route<ResolvedTenant>],
    hosts: &[DomainName],
) -> Result<(), AppError> {
    let unserved = hosts.iter().find(|host| {
        !routes
            .iter()
            .filter(|route| route.service_id() == service.id())
            .any(|route| answers_on(route, host))
    });
    let Some(host) = unserved else {
        return Ok(());
    };
    Err(invalid(format!(
        "no route of {} answers on {host}; add one before signing people in there",
        service.name()
    )))
}

/// Refuses sign-in addresses that are a route's own path: the gateway
/// answers a sign-in address before matching any route, so that route would
/// never be reached again.
fn ensure_no_route_hidden(
    routes: &[Route<ResolvedTenant>],
    sign_in: &AppSignIn,
) -> Result<(), AppError> {
    let addresses = SignInAction::ALL
        .map(|action| sign_in.path(action))
        .into_iter()
        .chain([
            sign_in.token_path(),
            sign_in.hop_path(),
            sign_in.script_path(),
        ]);
    for path in addresses {
        ensure_path_free(routes, sign_in.hosts(), &path)?;
    }
    Ok(())
}

/// Refuses `path` on `hosts` when a route answering there claims it.
fn ensure_path_free(
    routes: &[Route<ResolvedTenant>],
    hosts: &[DomainName],
    path: &SignInPath,
) -> Result<(), AppError> {
    let hidden = routes.iter().find(|route| {
        route.path_pattern().as_str() == path.as_str()
            && hosts.iter().any(|host| answers_on(route, host))
    });
    let Some(route) = hidden else {
        return Ok(());
    };
    Err(invalid(format!(
        "{path} is the path of route {}; move the sign-in address or the route",
        route.name()
    )))
}

/// Gives `service` the sign-in `settings` state, on behalf of `by`.
///
/// Whichever of the two is being turned off goes first, so a switch from
/// accepting another's sign-in to owning one, or back, is never refused
/// halfway.
///
/// # Errors
///
/// Returns the service's own refusal, such as sign-in on a service that pins
/// no audience, or `by` not holding the right to update routing.
pub(crate) fn apply_sign_in(
    service: &mut Service<ResolvedTenant>,
    settings: SignInSettings,
    by: &RoutingControl<'_>,
) -> Result<(), DomainError> {
    let SignInSettings { own, accepted } = settings;
    if own.is_unset() {
        service.change_app_sign_in(Setting::Unset, by)?;
        return service.accept_app_sign_in_of(accepted, by);
    }
    service.accept_app_sign_in_of(accepted, by)?;
    service.change_app_sign_in(own, by)
}

fn answers_on(route: &Route<ResolvedTenant>, host: &DomainName) -> bool {
    route.hosts().accepts(host.as_str())
}

fn invalid(message: String) -> AppError {
    AppError::Domain(DomainError::invalid(message))
}
