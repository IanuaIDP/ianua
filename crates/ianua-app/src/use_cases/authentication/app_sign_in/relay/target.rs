//! Which app a sign-in request is for, checked against what is stored.

use std::sync::Arc;

use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::domains::routing::sign_in::app::AppSignIn;
use ianua_domain::domains::tenant::lifecycle::Tenant;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::message;
use ianua_domain::types::{Audience, DomainName, ServiceId};

use crate::error::{AppError, OrInternal};
use crate::ports::organization::OrganizationStore;
use crate::ports::routing::ServiceStore;
use crate::ports::tenant::TenantStore;
use crate::tenancy::ScopedTenant;

/// The stores an app sign-in request is resolved against.
#[derive(Clone, ianua_macros::Fakes)]
pub struct TargetPorts {
    /// Port for the tenant the request is for.
    pub tenant_store: Arc<dyn TenantStore>,
    /// Port for the tenant's organization.
    pub org_store: Arc<dyn OrganizationStore>,
    /// Port for the service whose app sign-in is used.
    pub service_store: Arc<dyn ServiceStore>,
}

/// An app sign-in request's tenant, organization and service, each loaded
/// from storage and checked to fit together.
pub(in crate::use_cases::authentication::app_sign_in) struct Target {
    /// The tenant the host belongs to.
    pub(in crate::use_cases::authentication::app_sign_in) tenant: Arc<Tenant>,
    /// The tenant's organization.
    pub(in crate::use_cases::authentication::app_sign_in) org: Arc<Organization>,
    /// The service whose sign-in is used.
    pub(in crate::use_cases::authentication::app_sign_in) service: Service<ResolvedTenant>,
    /// The service's sign-in settings.
    pub(in crate::use_cases::authentication::app_sign_in) sign_in: AppSignIn,
    /// The host the request came to.
    pub(in crate::use_cases::authentication::app_sign_in) host: DomainName,
}

impl Target {
    /// The audience the service pins, which its app sign-in requires.
    pub(in crate::use_cases::authentication::app_sign_in) fn audience(
        &self,
    ) -> Result<Audience, AppError> {
        pinned_audience(&self.service)
    }
}

/// Loads what a request names and checks it: the tenant exists, the service
/// is the tenant's and active, has app sign-in, and answers on `host`.
///
/// The request's tenant, service and host come from the gateway, which read
/// them off the connection and its own routing table. They are still only
/// claims about the request until stored settings agree with them.
///
/// # Errors
///
/// Returns `AppError::NotFound` for anything that does not fit, without
/// saying which part: an outsider learns nothing about the tenant's apps.
pub(in crate::use_cases::authentication::app_sign_in) async fn resolve(
    ports: &TargetPorts,
    tenant: &ScopedTenant,
    service_id: &ServiceId,
    host: &DomainName,
) -> Result<Target, AppError> {
    let (found, org) = tenant_and_org(ports, tenant).await?;
    let service = active_service(ports, tenant, service_id)
        .await?
        .ok_or_else(not_found)?;
    let sign_in = service
        .app_sign_in()
        .filter(|sign_in| sign_in.serves(host.as_str()))
        .cloned()
        .ok_or_else(not_found)?;
    Ok(Target {
        tenant: found,
        org,
        service,
        sign_in,
        host: host.clone(),
    })
}

/// A host of a service accepting another's sign-in with a cookie of its
/// own: that service, the owner and their tenant, each loaded and checked.
pub(in crate::use_cases::authentication::app_sign_in) struct CookieTarget {
    /// The tenant the host belongs to.
    pub(in crate::use_cases::authentication::app_sign_in) tenant: Arc<Tenant>,
    /// The tenant's organization.
    pub(in crate::use_cases::authentication::app_sign_in) org: Arc<Organization>,
    /// The service accepting the owner's sign-in.
    pub(in crate::use_cases::authentication::app_sign_in) service: Service<ResolvedTenant>,
    /// The service whose sign-in it accepts.
    pub(in crate::use_cases::authentication::app_sign_in) owner: Service<ResolvedTenant>,
}

/// Loads what a hop to `host` names and checks it: the service is the
/// tenant's and active, accepts an active owner's sign-in with a cookie of
/// its own on `host`, and the owner still signs people in.
///
/// # Errors
///
/// Returns `AppError::NotFound` for anything that does not fit, without
/// saying which part.
pub(in crate::use_cases::authentication::app_sign_in) async fn resolve_cookie_host(
    ports: &TargetPorts,
    tenant: &ScopedTenant,
    service_id: &ServiceId,
    host: &DomainName,
) -> Result<CookieTarget, AppError> {
    let service = active_service(ports, tenant, service_id)
        .await?
        .ok_or_else(not_found)?;
    let accepted = service
        .accepted_sign_in()
        .filter(|accepted| has_cookie_host(accepted.cookie_hosts(), host))
        .ok_or_else(not_found)?;
    let owner = active_service(ports, tenant, accepted.owner())
        .await?
        .filter(|owner| owner.app_sign_in().is_some())
        .ok_or_else(not_found)?;
    let (found, org) = tenant_and_org(ports, tenant).await?;
    Ok(CookieTarget {
        tenant: found,
        org,
        service,
        owner,
    })
}

/// The audience `service` pins, which a session or token for it names.
///
/// # Errors
///
/// Returns `AppError::Internal` when the service pins none: the domain
/// refuses app sign-in on such a service, so the stored record is broken.
pub(in crate::use_cases::authentication::app_sign_in) fn pinned_audience(
    service: &Service<ResolvedTenant>,
) -> Result<Audience, AppError> {
    service
        .upstream()
        .expected_audience()
        .cloned()
        .ok_or_else(|| AppError::internal_msg("app sign-in on a service with no audience"))
}

/// Whether `host` is one of `hosts`, compared without case.
fn has_cookie_host(hosts: &[DomainName], host: &DomainName) -> bool {
    hosts
        .iter()
        .any(|own| own.as_str().eq_ignore_ascii_case(host.as_str()))
}

/// The tenant and its organization, each of which must exist.
async fn tenant_and_org(
    ports: &TargetPorts,
    tenant: &ScopedTenant,
) -> Result<(Arc<Tenant>, Arc<Organization>), AppError> {
    let found = ports
        .tenant_store
        .find_by_id(tenant)
        .await
        .or_internal()?
        .ok_or_else(not_found)?;
    let org = ports
        .org_store
        .find_by_id(found.organization_id())
        .await
        .or_internal()?
        .ok_or_else(not_found)?;
    Ok((Arc::new(found), Arc::new(org)))
}

/// The tenant's service with `service_id`, provided it is active.
async fn active_service(
    ports: &TargetPorts,
    tenant: &ScopedTenant,
    service_id: &ServiceId,
) -> Result<Option<Service<ResolvedTenant>>, AppError> {
    ports
        .service_store
        .find_by_id(tenant, service_id)
        .await
        .or_internal()
        .map(|found| found.filter(Service::is_active))
}

/// The one refusal for a request that does not fit, whichever part fails.
fn not_found() -> AppError {
    AppError::NotFound(message!(
        "authentication-no-app-sign-in-here",
        "no app sign-in here"
    ))
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::test_support::authentication::{
        SHOP_HOST, app_sign_in_services, app_sign_in_target_ports, shop_with_app_sign_in,
    };
    use crate::test_support::routing::{pinned_upstream, routing_admin, service_named};
    use crate::test_support::{block_on, test_ctx};

    struct Fixture {
        ports: TargetPorts,
        service_id: ServiceId,
    }

    fn fixture_with(service: Service<ResolvedTenant>) -> Fixture {
        let service_id = *service.id();
        Fixture {
            ports: app_sign_in_target_ports(app_sign_in_services([service])),
            service_id,
        }
    }

    fn resolve_on(f: &Fixture, host: &str) -> Result<Target, AppError> {
        block_on(resolve(
            &f.ports,
            &test_ctx().tenant(),
            &f.service_id,
            &DomainName::new(host).unwrap(),
        ))
    }

    /// Ann's shop has app sign-in on its host. A request there resolves to
    /// the shop, its sign-in and the audience it pins.
    #[test]
    fn a_service_with_app_sign_in_on_the_host_resolves() {
        let f = fixture_with(shop_with_app_sign_in());

        let target = resolve_on(&f, SHOP_HOST).unwrap();

        assert_eq!(target.service.id(), &f.service_id);
        assert!(target.sign_in.serves(SHOP_HOST));
        assert_eq!(target.audience().unwrap().as_str(), "shop");
    }

    /// Resolving a service without app sign-in returns not found.
    #[test]
    fn a_service_without_app_sign_in_is_not_found() {
        let f = fixture_with(service_named(
            "shop",
            pinned_upstream("https://shop.internal", "shop"),
        ));

        assert!(matches!(
            resolve_on(&f, SHOP_HOST),
            Err(AppError::NotFound(_))
        ));
    }

    /// Resolving the shop on a host outside its sign-in settings returns
    /// not found.
    #[test]
    fn a_host_the_service_does_not_sign_in_on_is_not_found() {
        let f = fixture_with(shop_with_app_sign_in());

        assert!(matches!(
            resolve_on(&f, "other.example.com"),
            Err(AppError::NotFound(_))
        ));
    }

    /// A disabled shop returns not found even on its configured sign-in host.
    #[test]
    fn a_disabled_service_is_not_found() {
        let mut shop = shop_with_app_sign_in();
        shop.disable(&routing_admin()).unwrap();
        let f = fixture_with(shop);

        assert!(matches!(
            resolve_on(&f, SHOP_HOST),
            Err(AppError::NotFound(_))
        ));
    }

    /// Resolving a request for an unknown tenant returns not found.
    #[test]
    fn an_unknown_tenant_is_not_found() {
        let f = fixture_with(shop_with_app_sign_in());

        let result = block_on(resolve(
            &f.ports,
            &ScopedTenant::for_test(TenantId::new()),
            &f.service_id,
            &DomainName::new(SHOP_HOST).unwrap(),
        ));

        assert!(matches!(result, Err(AppError::NotFound(_))));
    }
}
