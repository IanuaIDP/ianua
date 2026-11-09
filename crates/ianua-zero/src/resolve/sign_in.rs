//! A tenant's app sign-in, indexed by host, and which session cookie a
//! request may present there.
//!
//! Which hosts answer sign-in for which service, which carry a service's
//! own session cookie, and what an app session must say to be taken for a
//! route on a host are the domain's rules ([`AppSignInHosts`]); the gateway
//! only asks them with the host it read.

use ianua_domain::domains::routing::service::Service;
pub(crate) use ianua_domain::domains::routing::sign_in::hosts::{
    AppSessionRules, AppSignInHosts, CookieHost, SignInHost,
};
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::ServiceId;

use crate::request::{RequestHost, SessionCookies};

/// A tenant's app sign-in, indexed for the request path.
#[derive(Debug, Default)]
pub(crate) struct AppSignInIndex {
    hosts: AppSignInHosts,
}

impl AppSignInIndex {
    /// Indexes the app sign-in of `services` that are active.
    pub(crate) fn build<'a>(
        services: impl IntoIterator<Item = &'a Service<ResolvedTenant>>,
    ) -> Self {
        Self {
            hosts: AppSignInHosts::build(services),
        }
    }

    /// The app sign-in answering on `host`, if one service's does.
    #[must_use]
    pub(crate) fn on_host(&self, host: &RequestHost) -> Option<&SignInHost> {
        self.hosts.on_host(host.name())
    }

    /// The service whose own session cookie `host` carries, if any.
    #[must_use]
    pub(crate) fn cookie_host(&self, host: &RequestHost) -> Option<&CookieHost> {
        self.hosts.cookie_host(host.name())
    }

    /// Whether `host` has app sign-in of any kind, or is claimed by two
    /// services' and so has none that can be trusted.
    #[must_use]
    pub(crate) fn covers(&self, host: &RequestHost) -> bool {
        self.hosts.covers(host.name())
    }

    /// What an app session cookie must say to be taken for `service` on
    /// `host`, as the domain rules it.
    #[must_use]
    pub(crate) fn rules(&self, service: &ServiceId, host: &RequestHost) -> Option<AppSessionRules> {
        self.hosts.rules(service, host.name())
    }

    /// Which session cookie a request for `service` on `host` may present.
    /// A host with app sign-in of any kind never reads the platform's
    /// cookie, since a sibling subdomain could have planted it.
    #[must_use]
    pub(crate) fn session_cookies(
        &self,
        service: &ServiceId,
        host: &RequestHost,
    ) -> SessionCookies {
        if !self.covers(host) {
            return SessionCookies::Platform;
        }
        SessionCookies::AppSignIn(self.rules(service, host))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use ianua_domain::domains::routing::backend::health_check::HealthCheckPolicy;
    use ianua_domain::domains::routing::backend::upstream::{
        HostHeader, Upstream, UpstreamTimeout,
    };
    use ianua_domain::domains::routing::route_status::RouteStatus;
    use ianua_domain::domains::routing::service::ServiceRow;
    use ianua_domain::domains::routing::sign_in::accepted::AcceptedSignIn;
    use ianua_domain::domains::routing::sign_in::app::{
        AppSignIn, AppSignInParams, SignedOutBrowsers,
    };
    use ianua_domain::types::{Audience, DomainName, HttpUrl, Label, Setting};

    use super::*;

    /// A stored service named `name`, pinning the audience `{name}-aud`,
    /// with the sign-in settings given.
    pub(crate) fn service_with(
        id: ServiceId,
        name: &str,
        app_sign_in: Setting<AppSignIn>,
        accepted_sign_in: Setting<AcceptedSignIn>,
    ) -> Service<ResolvedTenant> {
        let now = ianua_domain::shared::clock::now();
        Service::reconstitute(ServiceRow {
            id,
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

    fn signing_in(name: &str, host: &str) -> Service<ResolvedTenant> {
        let sign_in = AppSignIn::new(AppSignInParams {
            hosts: vec![DomainName::new(host).unwrap()],
            prefix: Setting::Unset,
            moved: BTreeMap::new(),
            after_sign_in: Setting::Unset,
            signed_out_browsers: SignedOutBrowsers::Refuse,
        })
        .unwrap();
        service_with(
            ServiceId::new(),
            name,
            Setting::Set(sign_in),
            Setting::Unset,
        )
    }

    fn host(name: &str) -> RequestHost {
        RequestHost::new(DomainName::new(name).unwrap()).unwrap()
    }

    #[test]
    fn a_host_with_app_sign_in_reads_only_its_app_session() {
        let shop = signing_in("shop", "shop.example.com");
        let index = AppSignInIndex::build([&shop]);

        let cookies = index.session_cookies(shop.id(), &host("shop.example.com"));

        assert!(matches!(
            cookies,
            SessionCookies::AppSignIn(Some(rules)) if rules.owner() == shop.id()
        ));
    }

    /// A sign-in host claimed by two services yields no accepted application
    /// session rules and does not fall back to platform cookies.
    #[test]
    fn a_host_two_services_claim_reads_no_session_cookie() {
        let shop = signing_in("shop", "shop.example.com");
        let rival = signing_in("rival", "shop.example.com");

        let index = AppSignInIndex::build([&shop, &rival]);

        assert!(matches!(
            index.session_cookies(shop.id(), &host("shop.example.com")),
            SessionCookies::AppSignIn(None)
        ));
    }

    #[test]
    fn a_host_without_app_sign_in_reads_the_platform_cookie() {
        let shop = signing_in("shop", "shop.example.com");
        let index = AppSignInIndex::build([&shop]);

        assert!(matches!(
            index.session_cookies(shop.id(), &host("plain.example.com")),
            SessionCookies::Platform
        ));
    }
}
