//! A tenant's app sign-in by host: which hosts answer sign-in for which
//! service, which hosts carry a service's own session cookie, and what an
//! app session must say to be taken for a service on a host.
//!
//! Built from the services' stored settings. A host two of them claim is
//! contested: it takes no session at all rather than letting the order
//! services were read in pick whose sessions it takes. A service accepting
//! another's sign-in counts only while that other service is active and
//! has sign-in of its own: accepting nothing never reads as accepting
//! anything.

use std::collections::{HashMap, HashSet};

use crate::domains::routing::service::Service;
use crate::domains::routing::sign_in::accepted::{AcceptedSignIn, SignInDelivery};
use crate::domains::routing::sign_in::app::{AppSignIn, SignInPath};
use crate::isolation::scope::TenantScope;
use crate::types::{Audience, DomainName, HostOrigin, ServiceId};

/// The app sign-in answering on one host.
#[derive(Debug, Clone)]
pub struct SignInHost {
    owner: ServiceId,
    sign_in: AppSignIn,
    audience: Audience,
}

impl SignInHost {
    /// The service whose sign-in it is.
    #[must_use]
    pub fn owner(&self) -> &ServiceId {
        &self.owner
    }

    /// Its settings.
    #[must_use]
    pub fn sign_in(&self) -> &AppSignIn {
        &self.sign_in
    }

    /// The audience every session it hands out names.
    #[must_use]
    pub fn audience(&self) -> &Audience {
        &self.audience
    }
}

/// A host of a service that accepts another's sign-in with a session
/// cookie of its own.
#[derive(Debug, Clone)]
pub struct CookieHost {
    owner: ServiceId,
    service: ServiceId,
    audience: Audience,
    hop_path: SignInPath,
    owner_origins: Vec<HostOrigin>,
    onward_origins: Vec<HostOrigin>,
}

impl CookieHost {
    /// The service whose sign-in the session comes from.
    #[must_use]
    pub fn owner(&self) -> &ServiceId {
        &self.owner
    }

    /// The service the cookie is for.
    #[must_use]
    pub fn service(&self) -> &ServiceId {
        &self.service
    }

    /// The audience the cookie's session names: the service's own.
    #[must_use]
    pub fn audience(&self) -> &Audience {
        &self.audience
    }

    /// Where the hop carrying the session arrives on this host.
    #[must_use]
    pub fn hop_path(&self) -> &SignInPath {
        &self.hop_path
    }

    /// The `https://` origins of the owner's pages, which call this host.
    #[must_use]
    pub fn owner_origins(&self) -> &[HostOrigin] {
        &self.owner_origins
    }

    /// Where a hop arriving here may send the browser on to: the owner's
    /// hosts and the other cookie hosts carrying its sessions.
    #[must_use]
    pub fn onward_origins(&self) -> &[HostOrigin] {
        &self.onward_origins
    }

    /// What a session cookie on this host must say: the owner's sign-in,
    /// for this service's audience, sent by this host's or the owner's
    /// pages.
    fn rules(&self) -> AppSessionRules {
        AppSessionRules::new(
            self.owner,
            self.audience.clone(),
            self.owner_origins.clone(),
        )
    }
}

/// What an app session must say to be taken for a service on a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSessionRules {
    owner: ServiceId,
    audience: Audience,
    trusted_origins: Vec<HostOrigin>,
}

impl AppSessionRules {
    /// Sessions opened by `owner`'s sign-in for `audience`, sent by the
    /// host's own pages or by one of `trusted_origins`.
    #[must_use]
    pub fn new(owner: ServiceId, audience: Audience, trusted_origins: Vec<HostOrigin>) -> Self {
        Self {
            owner,
            audience,
            trusted_origins,
        }
    }

    /// The service whose sign-in must have opened the session.
    #[must_use]
    pub fn owner(&self) -> &ServiceId {
        &self.owner
    }

    /// The audience the session's token must name.
    #[must_use]
    pub fn audience(&self) -> &Audience {
        &self.audience
    }

    /// Origins besides the host's own whose pages may send it requests with
    /// the cookie: the owner's, on a host of a service's own cookie.
    #[must_use]
    pub fn trusted_origins(&self) -> &[HostOrigin] {
        &self.trusted_origins
    }
}

/// A tenant's app sign-in, indexed by host.
#[derive(Debug, Default)]
pub struct AppSignInHosts {
    by_host: HashMap<DomainName, SignInHost>,
    cookie_hosts: HashMap<DomainName, CookieHost>,
    owner_of: HashMap<ServiceId, ServiceId>,
    contested: HashSet<DomainName>,
}

impl AppSignInHosts {
    /// Indexes the app sign-in of `services` that are active.
    pub fn build<'a, T: TenantScope + 'a>(
        services: impl IntoIterator<Item = &'a Service<T>>,
    ) -> Self {
        let active: Vec<&Service<T>> = services
            .into_iter()
            .filter(|service| service.is_active())
            .collect();
        let owners: HashMap<ServiceId, SignInHost> =
            active.iter().copied().filter_map(owner_of).collect();
        let mut index = Self::default();
        for owner in owners.values() {
            index.add_owner(owner);
        }
        for service in &active {
            let accepted = service.accepted_sign_in();
            let owner = accepted.and_then(|accepted| owners.get(accepted.owner()));
            let (Some(accepted), Some(owner)) = (accepted, owner) else {
                continue;
            };
            index.add_accepting(service, accepted, owner);
        }
        index.drop_contested();
        index.link_onward_origins();
        index
    }

    /// The app sign-in answering on `host`, if one service's does.
    #[must_use]
    pub fn on_host(&self, host: &DomainName) -> Option<&SignInHost> {
        self.by_host.get(host)
    }

    /// The service whose own session cookie `host` carries, if any.
    #[must_use]
    pub fn cookie_host(&self, host: &DomainName) -> Option<&CookieHost> {
        self.cookie_hosts.get(host)
    }

    /// Whether `host` has app sign-in of any kind, or is claimed by two
    /// services' and so has none that can be trusted.
    #[must_use]
    pub fn covers(&self, host: &DomainName) -> bool {
        self.by_host.contains_key(host)
            || self.cookie_hosts.contains_key(host)
            || self.contested.contains(host)
    }

    /// What an app session must say to be taken for `service` on `host`:
    /// on the owner's hosts, the owner's sign-in for the owner or a service
    /// accepting it there; on a host of a service's own cookie, the owner's
    /// sign-in for that service alone. `None` when `host` takes no session
    /// for `service`.
    #[must_use]
    pub fn rules(&self, service: &ServiceId, host: &DomainName) -> Option<AppSessionRules> {
        if let Some(cookie) = self.cookie_host(host) {
            return (cookie.service == *service).then(|| cookie.rules());
        }
        let owner = self.owner_of.get(service)?;
        let on_host = self
            .on_host(host)
            .filter(|on_host| on_host.owner == *owner)?;
        Some(AppSessionRules::new(
            *owner,
            on_host.audience.clone(),
            Vec::new(),
        ))
    }

    fn add_owner(&mut self, owner: &SignInHost) {
        self.owner_of.insert(owner.owner, owner.owner);
        for host in owner.sign_in.hosts() {
            self.claim_sign_in_host(host, owner);
        }
    }

    fn claim_sign_in_host(&mut self, host: &DomainName, owner: &SignInHost) {
        if self.by_host.contains_key(host) {
            self.contested.insert(host.clone());
            return;
        }
        self.by_host.insert(host.clone(), owner.clone());
    }

    fn add_accepting<T: TenantScope>(
        &mut self,
        service: &Service<T>,
        accepted: &AcceptedSignIn,
        owner: &SignInHost,
    ) {
        match accepted.delivery() {
            SignInDelivery::SameHost => {
                self.owner_of.insert(*service.id(), owner.owner);
            }
            SignInDelivery::OwnCookie(hosts) => {
                let Some(audience) = service.upstream().expected_audience() else {
                    return;
                };
                let cookie = CookieHost {
                    owner: owner.owner,
                    service: *service.id(),
                    audience: audience.clone(),
                    hop_path: owner.sign_in.hop_path(),
                    owner_origins: origins(owner.sign_in.hosts()),
                    onward_origins: Vec::new(),
                };
                for host in hosts.hosts() {
                    self.claim_cookie_host(host, &cookie);
                }
            }
            SignInDelivery::Tokens => {}
        }
    }

    fn claim_cookie_host(&mut self, host: &DomainName, cookie: &CookieHost) {
        if self.by_host.contains_key(host) || self.cookie_hosts.contains_key(host) {
            self.contested.insert(host.clone());
            return;
        }
        self.cookie_hosts.insert(host.clone(), cookie.clone());
    }

    /// Takes every contested host out of both maps.
    fn drop_contested(&mut self) {
        for host in &self.contested {
            self.by_host.remove(host);
            self.cookie_hosts.remove(host);
        }
    }

    /// Gives each cookie host the origins a hop arriving there may move on
    /// to, once every host of every owner is known.
    fn link_onward_origins(&mut self) {
        let cookie_origins: Vec<(ServiceId, HostOrigin)> = self
            .cookie_hosts
            .iter()
            .filter_map(|(host, cookie)| Some((cookie.owner, HostOrigin::of(host).ok()?)))
            .collect();
        for cookie in self.cookie_hosts.values_mut() {
            let siblings = cookie_origins
                .iter()
                .filter(|(owner, _)| *owner == cookie.owner)
                .map(|(_, origin)| origin.clone());
            cookie.onward_origins = cookie
                .owner_origins
                .iter()
                .cloned()
                .chain(siblings)
                .collect();
        }
    }
}

/// `service`'s own sign-in, when it has one and pins the audience its
/// sessions name.
fn owner_of<T: TenantScope>(service: &Service<T>) -> Option<(ServiceId, SignInHost)> {
    let sign_in = service.app_sign_in()?;
    let audience = service.upstream().expected_audience()?;
    Some((
        *service.id(),
        SignInHost {
            owner: *service.id(),
            sign_in: sign_in.clone(),
            audience: audience.clone(),
        },
    ))
}

/// The `https://` origins of `hosts`. Sign-in and cookie hosts are never
/// wildcards; one that were would name no site and is left out, trusting
/// less rather than more.
fn origins(hosts: &[DomainName]) -> Vec<HostOrigin> {
    hosts
        .iter()
        .filter_map(|host| HostOrigin::of(host).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::domains::routing::backend::health_check::HealthCheckPolicy;
    use crate::domains::routing::backend::upstream::{HostHeader, Upstream, UpstreamTimeout};
    use crate::domains::routing::route_status::RouteStatus;
    use crate::domains::routing::service::ServiceRow;
    use crate::domains::routing::sign_in::accepted::CookieHosts;
    use crate::domains::routing::sign_in::app::{AppSignInParams, SignedOutBrowsers};
    use crate::isolation::scope::ResolvedTenant;
    use crate::types::{HttpUrl, Label, Setting};

    fn service_with(
        name: &str,
        app_sign_in: Setting<AppSignIn>,
        accepted_sign_in: Setting<AcceptedSignIn>,
    ) -> Service<ResolvedTenant> {
        let now = crate::shared::clock::now();
        Service::reconstitute(ServiceRow {
            id: ServiceId::new(),
            name: Label::new("name", name).unwrap(),
            upstream: Upstream::new(
                HttpUrl::new("https://app.internal:8080").unwrap(),
                UpstreamTimeout::DEFAULT,
                HostHeader::Rewrite,
            )
            .with_audience(Audience::new(format!("{name}-aud")).unwrap()),
            health_check: HealthCheckPolicy::Disabled,
            app_sign_in,
            accepted_sign_in,
            status: RouteStatus::Active,
            created_at: now,
            updated_at: now,
        })
        .unwrap()
    }

    fn plain(name: &str) -> Service<ResolvedTenant> {
        service_with(name, Setting::Unset, Setting::Unset)
    }

    fn signing_in(name: &str, host: &str) -> Service<ResolvedTenant> {
        let sign_in = AppSignIn::new(AppSignInParams {
            hosts: vec![DomainName::new(host).unwrap()],
            prefix: Setting::Unset,
            moved: BTreeMap::new(),
            after_sign_in: Setting::Unset,
            signed_out_browsers: SignedOutBrowsers::Refuse,
        })
        .unwrap();
        service_with(name, Setting::Set(sign_in), Setting::Unset)
    }

    fn accepting(
        name: &str,
        owner: &ServiceId,
        delivery: SignInDelivery,
    ) -> Service<ResolvedTenant> {
        let accepted = AcceptedSignIn::new(*owner, delivery);
        service_with(name, Setting::Unset, Setting::Set(accepted))
    }

    fn own_cookie(host: &str) -> SignInDelivery {
        SignInDelivery::OwnCookie(CookieHosts::new(vec![DomainName::new(host).unwrap()]).unwrap())
    }

    fn host(name: &str) -> DomainName {
        DomainName::new(name).unwrap()
    }

    fn origin(text: &str) -> HostOrigin {
        HostOrigin::new(text).unwrap()
    }

    #[test]
    fn a_service_accepts_its_own_sign_in_where_it_answers() {
        let shop = signing_in("shop", "shop.example.com");
        let index = AppSignInHosts::build([&shop]);

        let rules = index.rules(shop.id(), &host("shop.example.com")).unwrap();

        assert_eq!(rules.owner(), shop.id());
        assert_eq!(rules.audience().as_str(), "shop-aud");
        assert!(index.rules(shop.id(), &host("other.example.com")).is_none());
    }

    #[test]
    fn a_service_accepts_another_sign_in_only_when_it_says_so() {
        let shop = signing_in("shop", "shop.example.com");
        let silent = plain("api");
        let opted_in = accepting("orders", shop.id(), SignInDelivery::SameHost);

        let index = AppSignInHosts::build([&shop, &silent, &opted_in]);

        assert!(
            index
                .rules(silent.id(), &host("shop.example.com"))
                .is_none()
        );
        let rules = index
            .rules(opted_in.id(), &host("shop.example.com"))
            .unwrap();
        assert_eq!(rules.owner(), shop.id());
        assert_eq!(rules.audience().as_str(), "shop-aud");
    }

    /// Naming an owner without app sign-in produces no session rules for
    /// the accepting service on the requested host.
    #[test]
    fn accepting_a_service_without_sign_in_accepts_nothing() {
        let other = plain("other");
        let borrower = accepting("orders", other.id(), SignInDelivery::SameHost);

        let index = AppSignInHosts::build([&other, &borrower]);

        assert!(
            index
                .rules(borrower.id(), &host("shop.example.com"))
                .is_none()
        );
    }

    #[test]
    fn a_host_of_its_own_cookie_takes_the_owners_sessions_for_its_audience() {
        let shop = signing_in("shop", "shop.example.com");
        let api = accepting("api", shop.id(), own_cookie("api.example.com"));

        let index = AppSignInHosts::build([&shop, &api]);

        let rules = index.rules(api.id(), &host("api.example.com")).unwrap();
        assert_eq!(rules.owner(), shop.id());
        assert_eq!(rules.audience().as_str(), "api-aud");
        assert_eq!(
            rules.trusted_origins(),
            [origin("https://shop.example.com")]
        );
        let cookie = index.cookie_host(&host("api.example.com")).unwrap();
        assert_eq!(cookie.hop_path().as_str(), "/.ianua/hop");
        assert_eq!(
            cookie.onward_origins(),
            [
                origin("https://shop.example.com"),
                origin("https://api.example.com")
            ]
        );
    }

    /// The cookie on a service's own host is that service's alone, and the
    /// owner's hosts take no session made for it.
    #[test]
    fn a_cookie_of_its_own_is_good_for_that_service_on_that_host_only() {
        let shop = signing_in("shop", "shop.example.com");
        let api = accepting("api", shop.id(), own_cookie("api.example.com"));
        let other = plain("other");

        let index = AppSignInHosts::build([&shop, &api, &other]);

        assert!(index.rules(other.id(), &host("api.example.com")).is_none());
        assert!(index.rules(shop.id(), &host("api.example.com")).is_none());
        assert!(index.rules(api.id(), &host("shop.example.com")).is_none());
    }

    #[test]
    fn a_service_reached_by_tokens_takes_no_cookie() {
        let shop = signing_in("shop", "shop.example.com");
        let api = accepting("api", shop.id(), SignInDelivery::Tokens);

        let index = AppSignInHosts::build([&shop, &api]);

        assert!(index.rules(api.id(), &host("shop.example.com")).is_none());
    }

    /// A host claimed by two sign-in services has no sign-in entry or
    /// session rules for the first service, while remaining marked as covered.
    #[test]
    fn a_host_two_services_claim_takes_no_session() {
        let shop = signing_in("shop", "shop.example.com");
        let rival = signing_in("rival", "shop.example.com");

        let index = AppSignInHosts::build([&shop, &rival]);

        let on = host("shop.example.com");
        assert!(index.on_host(&on).is_none());
        assert!(index.covers(&on));
        assert!(index.rules(shop.id(), &on).is_none());
    }
}
