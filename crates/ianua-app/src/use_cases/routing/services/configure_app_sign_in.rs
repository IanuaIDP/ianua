//! Configure app sign-in: where people sign in on a service's hosts, and
//! whether a service accepts another's sign-in instead.

use std::sync::Arc;

use ianua_domain::domains::routing::control::{RoutingControl, RoutingRight};
use ianua_domain::domains::routing::route::Route;
use ianua_domain::domains::routing::service::Service;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::shared::events::raised::Raises as _;
use ianua_domain::types::{ServiceId, Setting};

use crate::acting::TenantAuthorities;
use crate::auditor::RequestAuditor;
use crate::context::CallerContext;
use crate::error::{AppError, OrInternal};
use crate::ports::domain::RegisteredDomainStore;
use crate::ports::routing::{RouteStore, ServiceStore};
use crate::ports::shared::SiteRules;
use crate::services::hosts::PlatformAddresses;
use crate::tenancy::ScopedTenant;
use crate::use_case::Command;
use crate::use_cases::routing::lookup::{all_routes, existing_service};
use crate::use_cases::routing::services::sign_in_checks::{
    AcceptanceChecks, SignInPlacement, SignInSettings, apply_sign_in, ensure_accepts, ensure_fits,
};

/// How a service signs people in from now on.
pub struct ConfigureAppSignInRequest {
    /// The service to configure.
    pub service_id: ServiceId,
    /// Its own app sign-in, and whose it accepts instead.
    pub settings: SignInSettings,
}

/// The ports [`ConfigureAppSignInUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ConfigureAppSignInPorts {
    /// Keeps the tenant's services.
    pub service_store: Arc<dyn ServiceStore>,
    /// The tenant's routes, which serve the sign-in hosts.
    pub route_store: Arc<dyn RouteStore>,
    /// The tenant's registered domains, which sign-in hosts must be.
    pub domain_store: Arc<dyn RegisteredDomainStore>,
    /// Which hosts are on the same site.
    pub site_rules: Arc<dyn SiteRules>,
    /// What a caller holds in their tenant.
    pub tenant_authorities: Arc<dyn TenantAuthorities>,
}

/// Sets how people sign in on a service.
pub struct ConfigureAppSignInUseCase {
    ports: ConfigureAppSignInPorts,
    platform: Option<Arc<PlatformAddresses>>,
}

impl ConfigureAppSignInUseCase {
    /// A use case working through `ports`.
    #[must_use]
    pub fn new(ports: ConfigureAppSignInPorts) -> Self {
        ConfigureAppSignInUseCase {
            ports,
            platform: None,
        }
    }

    /// Checks random and readable hosts against current tenant ownership.
    #[must_use]
    pub fn with_platform_addresses(mut self, platform: Arc<PlatformAddresses>) -> Self {
        self.platform = Some(platform);
        self
    }

    /// Persists the changed sign-in settings before recording their events.
    async fn keep(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        mut service: Service<ResolvedTenant>,
    ) -> Result<(), AppError> {
        let tenant = caller.tenant();
        self.ports
            .service_store
            .save(&tenant, &service)
            .await
            .map_err(AppError::from_domain)?;
        auditor
            .dispatch_by(&caller.actor(), service.take_events(&tenant))
            .await
            .or_internal()
    }
}

impl Command for ConfigureAppSignInUseCase {
    type Caller = CallerContext;
    type Input = ConfigureAppSignInRequest;
    type Output = Result<(), AppError>;

    /// Sets the service's app sign-in and records
    /// `routing.app_sign_in_changed`.
    ///
    /// # Errors
    ///
    /// - `AppError::Unauthenticated` for an invalid caller; `Forbidden` without routing-update rights; `NotFound` for a missing service or accepted-sign-in service.
    /// - `AppError::Domain` for unverified sign-in/cookie hosts, hosts without routes, colliding sign-in/route paths or missing required audiences.
    /// - `AppError::Domain` also covers an accepted service without sign-in, cross-site cookie hosts, or both owning and accepting sign-in.
    /// - `AppError::Conflict` for hosts claimed by another service's sign-in/cookie; `Internal` on storage or audit failure.
    async fn execute(
        &self,
        caller: &CallerContext,
        auditor: &RequestAuditor,
        request: ConfigureAppSignInRequest,
    ) -> Result<(), AppError> {
        let authority = self.ports.tenant_authorities.authority(caller).await?;
        let control = RoutingControl::new(&authority);
        control
            .ensure_may(RoutingRight::Update)
            .map_err(AppError::from_domain)?;
        let tenant = caller.tenant();
        let mut service = existing_service(
            self.ports.service_store.as_ref(),
            &tenant,
            &request.service_id,
        )
        .await?;
        ensure_settings_fit(
            &self.ports,
            &tenant,
            &service,
            &request.settings,
            self.platform.as_deref(),
        )
        .await?;
        apply_sign_in(&mut service, request.settings, &control).map_err(AppError::from_domain)?;
        self.keep(caller, auditor, service).await
    }
}

/// Refuses settings that break the rules sign-in on `service` is held to:
/// its own sign-in must fit the routes it sits among, and the sign-in it
/// accepts must be one it can receive.
async fn ensure_settings_fit(
    ports: &ConfigureAppSignInPorts,
    tenant: &ScopedTenant,
    service: &Service<ResolvedTenant>,
    settings: &SignInSettings,
    platform: Option<&PlatformAddresses>,
) -> Result<(), AppError> {
    let routes = all_routes(ports.route_store.as_ref(), tenant).await?;
    if let Setting::Set(sign_in) = &settings.own {
        let placement = SignInPlacement {
            service,
            routes: &routes,
            sign_in,
        };
        ensure_fits(ports.domain_store.as_ref(), tenant, placement, platform).await?;
    }
    let Setting::Set(accepted) = &settings.accepted else {
        return Ok(());
    };
    let owner = existing_service(ports.service_store.as_ref(), tenant, accepted.owner()).await?;
    ensure_accepts(
        &acceptance_checks(ports, tenant, &routes, platform),
        service,
        &owner,
        accepted,
    )
    .await
}

/// What checking an acceptance reads, from `ports`.
fn acceptance_checks<'a>(
    ports: &'a ConfigureAppSignInPorts,
    tenant: &'a ScopedTenant,
    routes: &'a [Route<ResolvedTenant>],
    platform: Option<&'a PlatformAddresses>,
) -> AcceptanceChecks<'a> {
    AcceptanceChecks {
        platform,
        domain_store: ports.domain_store.as_ref(),
        site_rules: ports.site_rules.as_ref(),
        tenant,
        routes,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ianua_domain::domains::routing::matching::host::RouteHosts;
    use ianua_domain::domains::routing::sign_in::accepted::{
        AcceptedSignIn, CookieHosts, SignInDelivery,
    };
    use ianua_domain::domains::routing::sign_in::app::{
        AppSignIn, AppSignInParams, SignInAction, SignInPath, SignedOutBrowsers,
    };
    use ianua_domain::types::DomainName;

    use super::*;
    use crate::test_support::acting::{FakeTenantAuthorities, Refusal};
    use crate::test_support::proxy::test_pipeline;
    use crate::test_support::routing::{
        FakeRouteStore, FakeServiceStore, RouteShape, pinned_upstream, route_of, service_named,
        unpinned_upstream, verified_domains,
    };
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor, test_ctx};

    const HOST: &str = "shop.example.com";
    const API_HOST: &str = "api.example.com";
    const OTHER_SITE_HOST: &str = "api.other.test";

    struct Fixture {
        services: Arc<FakeServiceStore>,
        routes: Arc<FakeRouteStore>,
        audit: Arc<FakeEventDispatcher>,
        shop: Service<ResolvedTenant>,
        use_case: ConfigureAppSignInUseCase,
    }

    fn tenant() -> ScopedTenant {
        test_ctx().tenant()
    }

    fn fixture_with(
        shop: Service<ResolvedTenant>,
        served_on: RouteHosts,
        authorities: FakeTenantAuthorities,
    ) -> Fixture {
        let services = Arc::new(FakeServiceStore::empty());
        block_on(services.save(&tenant(), &shop)).unwrap();
        let routes = Arc::new(FakeRouteStore::empty());
        let f = Fixture {
            use_case: ConfigureAppSignInUseCase::new(ConfigureAppSignInPorts {
                service_store: services.clone(),
                route_store: routes.clone(),
                domain_store: verified_domains(&tenant(), &[HOST, API_HOST, OTHER_SITE_HOST]),
                tenant_authorities: Arc::new(authorities),
                ..ConfigureAppSignInPorts::fakes()
            }),
            services,
            routes,
            audit: Arc::new(FakeEventDispatcher::new()),
            shop,
        };
        let shop_route = RouteShape {
            hosts: served_on,
            ..RouteShape::public("shop", "/*")
        };
        seed_route(&f, &f.shop, shop_route);
        f
    }

    fn pinned_shop() -> Service<ResolvedTenant> {
        service_named(
            "shop",
            pinned_upstream("https://shop.internal:8080", "shop"),
        )
    }

    fn fixture() -> Fixture {
        fixture_with(
            pinned_shop(),
            RouteHosts::Any,
            FakeTenantAuthorities::holding_everything(),
        )
    }

    fn only(host: &str) -> RouteHosts {
        RouteHosts::only(vec![DomainName::new(host).unwrap()]).unwrap()
    }

    fn seed_route(f: &Fixture, service: &Service<ResolvedTenant>, shape: RouteShape<'_>) {
        let route = route_of(shape, service, &test_pipeline());
        block_on(f.routes.save(&tenant(), &route)).unwrap();
    }

    fn sign_in(host: &str, login: Option<&str>) -> AppSignIn {
        let moved: BTreeMap<_, _> = login
            .map(|login| (SignInAction::LogIn, SignInPath::new(login).unwrap()))
            .into_iter()
            .collect();
        AppSignIn::new(AppSignInParams {
            hosts: vec![DomainName::new(host).unwrap()],
            prefix: Setting::Unset,
            moved,
            after_sign_in: Setting::Unset,
            signed_out_browsers: SignedOutBrowsers::Refuse,
        })
        .unwrap()
    }

    fn configure(
        f: &Fixture,
        service_id: ServiceId,
        settings: SignInSettings,
    ) -> Result<(), AppError> {
        block_on(f.use_case.execute(
            &test_ctx(),
            &test_auditor(f.audit.clone()),
            ConfigureAppSignInRequest {
                service_id,
                settings,
            },
        ))
    }

    fn turn_on(f: &Fixture, sign_in: AppSignIn) -> Result<(), AppError> {
        configure(
            f,
            *f.shop.id(),
            SignInSettings {
                own: Setting::Set(sign_in),
                accepted: Setting::Unset,
            },
        )
    }

    fn accept(f: &Fixture, borrower: ServiceId, delivery: SignInDelivery) -> Result<(), AppError> {
        configure(
            f,
            borrower,
            SignInSettings {
                own: Setting::Unset,
                accepted: Setting::Set(AcceptedSignIn::new(*f.shop.id(), delivery)),
            },
        )
    }

    fn cookie_on(host: &str) -> SignInDelivery {
        SignInDelivery::OwnCookie(CookieHosts::new(vec![DomainName::new(host).unwrap()]).unwrap())
    }

    fn stored(f: &Fixture, id: &ServiceId) -> Service<ResolvedTenant> {
        block_on(f.services.find_by_id(&tenant(), id))
            .unwrap()
            .unwrap()
    }

    fn borrower(f: &Fixture, served_on: Option<RouteHosts>) -> ServiceId {
        let api = service_named(
            "shop-api",
            pinned_upstream("https://api.internal:8080", "api"),
        );
        block_on(f.services.save(&tenant(), &api)).unwrap();
        if let Some(hosts) = served_on {
            seed_route(
                f,
                &api,
                RouteShape {
                    hosts,
                    ..RouteShape::public("api", "/api/*")
                },
            );
        }
        *api.id()
    }

    /// Ann turns on sign-in for the shop on its own host. It is saved and
    /// the change is recorded.
    #[test]
    fn app_sign_in_is_saved_and_recorded() {
        let f = fixture();

        turn_on(&f, sign_in(HOST, None)).unwrap();

        assert!(stored(&f, f.shop.id()).app_sign_in().is_some());
        assert_eq!(
            *f.audit.records.lock().unwrap(),
            ["routing.app_sign_in_changed"]
        );
    }

    /// Ann turns on sign-in for a shop that pins no audience. The sessions it
    /// would hand out could name no audience, so it is refused.
    #[test]
    fn a_service_without_an_audience_cannot_turn_it_on() {
        let unpinned = service_named("shop", unpinned_upstream("https://shop.internal:8080"));
        let f = fixture_with(
            unpinned,
            RouteHosts::Any,
            FakeTenantAuthorities::holding_everything(),
        );

        let result = turn_on(&f, sign_in(HOST, None));

        assert!(matches!(result, Err(AppError::Domain(_))));
        assert!(stored(&f, f.shop.id()).app_sign_in().is_none());
    }

    /// Ann puts sign-in on a host Acme never proved. It is refused.
    #[test]
    fn a_host_that_is_not_a_verified_domain_is_refused() {
        let f = fixture();

        let result = turn_on(&f, sign_in("elsewhere.example.com", None));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann puts sign-in on a host none of the shop's routes answer on. The
    /// sessions it hands out would be accepted nowhere, so it is refused.
    #[test]
    fn a_host_none_of_the_services_routes_answer_on_is_refused() {
        let f = fixture_with(
            pinned_shop(),
            only("other.example.com"),
            FakeTenantAuthorities::holding_everything(),
        );

        let result = turn_on(&f, sign_in(HOST, None));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann moves the login onto `/login`, a route's own path. The gateway
    /// answers sign-in first, so the route would be hidden. It is refused.
    #[test]
    fn a_sign_in_path_that_would_hide_a_route_is_refused() {
        let f = fixture();
        let other = service_named("login-page", unpinned_upstream("https://login:8080"));
        seed_route(&f, &other, RouteShape::public("login", "/login"));

        let result = turn_on(&f, sign_in(HOST, Some("/login")));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann has the shop API accept the shop's sign-in before the shop has
    /// any. It is refused, then allowed once the shop signs people in.
    #[test]
    fn a_service_can_only_accept_the_sign_in_of_one_that_has_it() {
        let f = fixture();
        let api = borrower(&f, None);

        let early = accept(&f, api, SignInDelivery::SameHost);
        turn_on(&f, sign_in(HOST, None)).unwrap();
        let later = accept(&f, api, SignInDelivery::SameHost);

        assert!(matches!(early, Err(AppError::Domain(_))));
        assert!(later.is_ok(), "{later:?}");
    }

    /// Ann gives the shop API a cookie of its own on a domain Acme never
    /// proved. It is refused.
    #[test]
    fn a_cookie_of_its_own_goes_only_on_a_verified_domain() {
        let f = fixture();
        turn_on(&f, sign_in(HOST, None)).unwrap();
        let api = borrower(&f, Some(RouteHosts::Any));

        let result = accept(&f, api, cookie_on("api.unverified.com"));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann gives the shop API a cookie on a host none of its routes answer
    /// on. It would carry sessions nothing accepts, so it is refused.
    #[test]
    fn a_cookie_of_its_own_goes_only_on_a_host_the_service_is_served_on() {
        let f = fixture();
        turn_on(&f, sign_in(HOST, None)).unwrap();
        let api = borrower(&f, Some(only(HOST)));

        let result = accept(&f, api, cookie_on(API_HOST));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann gives the shop API a cookie on another site. The browser would
    /// never send it from the shop's pages, so it is refused.
    #[test]
    fn a_cookie_of_its_own_goes_only_on_the_same_site_as_the_sign_in() {
        let f = fixture();
        turn_on(&f, sign_in(HOST, None)).unwrap();
        let api = borrower(&f, Some(RouteHosts::Any));

        let result = accept(&f, api, cookie_on(OTHER_SITE_HOST));

        assert!(matches!(result, Err(AppError::Domain(_))));
    }

    /// Ann gives the shop API a cookie on its own verified host, on the
    /// shop's site. It is saved.
    #[test]
    fn a_cookie_of_its_own_on_a_verified_host_it_serves_is_accepted() {
        let f = fixture();
        turn_on(&f, sign_in(HOST, None)).unwrap();
        let api = borrower(&f, Some(only(API_HOST)));

        accept(&f, api, cookie_on(API_HOST)).unwrap();

        let saved = stored(&f, &api);
        assert_eq!(
            saved.accepted_sign_in().unwrap().cookie_hosts()[0].as_str(),
            API_HOST
        );
    }

    /// Ann turns sign-in off again. The shop has none.
    #[test]
    fn turning_it_off_clears_the_settings() {
        let f = fixture();
        turn_on(&f, sign_in(HOST, None)).unwrap();

        configure(
            &f,
            *f.shop.id(),
            SignInSettings {
                own: Setting::Unset,
                accepted: Setting::Unset,
            },
        )
        .unwrap();

        assert!(stored(&f, f.shop.id()).app_sign_in().is_none());
    }

    /// Disabling app sign-in without the routing update right is forbidden
    /// and preserves the service's sign-in settings.
    #[test]
    fn a_caller_without_the_update_right_is_refused() {
        let f = fixture();
        turn_on(&f, sign_in(HOST, None)).unwrap();
        let viewer = fixture_with(
            stored(&f, f.shop.id()),
            RouteHosts::Any,
            FakeTenantAuthorities::holding(&[]),
        );

        let result = configure(
            &viewer,
            *viewer.shop.id(),
            SignInSettings {
                own: Setting::Unset,
                accepted: Setting::Unset,
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
        assert!(stored(&viewer, viewer.shop.id()).app_sign_in().is_some());
    }

    /// A caller without the update right receives a permission refusal even
    /// when the service whose sign-in is being configured does not exist.
    #[test]
    fn a_caller_without_the_right_learns_nothing_of_an_unknown_service() {
        let viewer = fixture_with(
            pinned_shop(),
            RouteHosts::Any,
            FakeTenantAuthorities::holding(&[]),
        );

        let result = configure(
            &viewer,
            ServiceId::new(),
            SignInSettings {
                own: Setting::Unset,
                accepted: Setting::Unset,
            },
        );

        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    /// A signed-out session cannot enable app sign-in.
    #[test]
    fn a_signed_out_caller_is_refused() {
        let f = fixture_with(
            pinned_shop(),
            RouteHosts::Any,
            FakeTenantAuthorities::refusing(Refusal::SignedOut),
        );

        let result = turn_on(&f, sign_in(HOST, None));

        assert!(matches!(result, Err(AppError::Unauthenticated)));
    }
}
