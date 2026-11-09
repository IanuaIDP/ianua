//! Which tenant a host belongs to.
//!
//! A tenant answers on its own domains and its permanent random platform
//! address. Readable names are served only with explicit tenant consent. An
//! exact name always beats a wildcard, as it does in the TLS handshake. A
//! name two tenants claim resolves to neither: the gateway never picks one
//! by load order.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use ianua_app::ports::proxy::HostedTenant;
use ianua_app::tenancy::ScopedTenant;
use ianua_domain::domains::tenant::hosts::{PlatformAddressing, PlatformHostParts, PlatformHosts};
use ianua_domain::types::{DomainName, TenantId};

use crate::request::RequestHost;

/// Which tenant a host belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostResolution {
    /// This tenant's.
    Tenant(ScopedTenant),
    /// No tenant's. Never a default tenant.
    Unknown,
    /// Claimed by more than one tenant, so refused.
    Ambiguous,
}

/// Every served name, by the tenant claiming it.
#[derive(Debug, Default)]
pub(crate) struct HostTable {
    exact: HashMap<String, Claim>,
    wildcards: HashMap<String, Claim>,
    flat_labels: HashMap<String, Claim>,
    base: Option<DomainName>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Claim {
    One(TenantId),
    Contested,
}

impl HostTable {
    /// The names `hosted` tenants answer on, their platform subdomains
    /// built under `base`.
    pub(crate) fn build<'a>(
        hosted: impl IntoIterator<Item = &'a HostedTenant>,
        base: &DomainName,
        shape: PlatformAddressing,
    ) -> Self {
        let mut table = Self {
            base: Some(base.clone()),
            ..Self::default()
        };
        for tenant in hosted {
            table.add(tenant, base, shape);
        }
        table
    }

    /// The tenant `host` belongs to: an exact name first, then a wildcard
    /// one label above it.
    pub(crate) fn resolve(&self, host: &RequestHost) -> HostResolution {
        if self
            .base
            .as_ref()
            .is_some_and(|base| base.as_str() == host.as_str())
        {
            return HostResolution::Unknown;
        }
        if let Some(claim) = self.exact.get(host.as_str()) {
            return claim.resolution();
        }
        if let Some(claim) = self.flat_claim(host.as_str()) {
            return claim.resolution();
        }
        let Some(wildcard) = wildcard_over(host.as_str()) else {
            return HostResolution::Unknown;
        };
        self.wildcards
            .get(&wildcard)
            .map_or(HostResolution::Unknown, Claim::resolution)
    }

    /// Finds the permanent suffix of a flat app name, requiring exactly one label.
    fn flat_claim(&self, host: &str) -> Option<&Claim> {
        let label = host
            .strip_suffix(self.base.as_ref()?.as_str())?
            .strip_suffix('.')?;
        if label.contains('.') {
            return None;
        }
        let (app, suffix) = label.rsplit_once('-')?;
        if app.is_empty() {
            return None;
        }
        self.flat_labels.get(suffix)
    }

    /// Installs custom names outside the reserved platform namespace, then platform names.
    fn add(&mut self, tenant: &HostedTenant, base: &DomainName, shape: PlatformAddressing) {
        for domain in &tenant.domains {
            if domain.as_str() == base.as_str()
                || domain.as_str().ends_with(&format!(".{}", base.as_str()))
            {
                continue;
            }
            let names = match domain.is_wildcard() {
                true => &mut self.wildcards,
                false => &mut self.exact,
            };
            claim(names, domain.as_str(), tenant.tenant_id);
        }
        for name in platform_names(tenant, base, shape) {
            claim(&mut self.exact, name.as_str(), tenant.tenant_id);
            if shape == PlatformAddressing::Nested {
                claim(
                    &mut self.wildcards,
                    &format!("*.{}", name.as_str()),
                    tenant.tenant_id,
                );
            }
        }
        if shape == PlatformAddressing::Flat {
            claim(
                &mut self.flat_labels,
                tenant.platform_label.as_str(),
                tenant.tenant_id,
            );
        }
    }
}

impl Claim {
    fn resolution(&self) -> HostResolution {
        match self {
            Self::One(tenant_id) => {
                HostResolution::Tenant(ScopedTenant::from_request_host(*tenant_id))
            }
            Self::Contested => HostResolution::Ambiguous,
        }
    }
}

/// Records that `tenant_id` answers on `name`. A name another tenant
/// already answers on becomes contested.
fn claim(names: &mut HashMap<String, Claim>, name: &str, tenant_id: TenantId) {
    match names.entry(name.to_owned()) {
        Entry::Vacant(free) => {
            free.insert(Claim::One(tenant_id));
        }
        Entry::Occupied(mut held) if *held.get() != Claim::One(tenant_id) => {
            held.insert(Claim::Contested);
        }
        Entry::Occupied(_) => {}
    }
}

/// The tenant's two subdomains of `base`, as the domain builds them. A slug
/// that cannot make a domain name gives no subdomain, rather than one the
/// handshake would not match.
fn platform_names(
    tenant: &HostedTenant,
    base: &DomainName,
    shape: PlatformAddressing,
) -> Vec<DomainName> {
    let hosts = PlatformHosts::under(
        base,
        PlatformHostParts {
            label: &tenant.platform_label,
            readable: tenant.readable_address,
            organization_slug: &tenant.organization_slug,
            tenant_slug: &tenant.slug,
        },
        shape,
    );
    hosts.names().cloned().collect()
}

/// The wildcard that covers `host` one label deep: `*.acme.com` for
/// `api.acme.com`. Deeper names are not covered, as a certificate for the
/// wildcard does not cover them either.
fn wildcard_over(host: &str) -> Option<String> {
    let (_, parent) = host.split_once('.')?;
    if parent.is_empty() {
        return None;
    }
    Some(format!("*.{parent}"))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::tenant::hosts::{PlatformLabel, ReadableAddress};
    use ianua_domain::shared::config::SlugLimits;
    use ianua_domain::types::TenantSlug;
    use proptest::prelude::*;

    use super::*;

    fn base() -> DomainName {
        DomainName::new("zero.test").unwrap()
    }

    fn hosted(org: &str, slug: &str, domains: &[&str]) -> HostedTenant {
        HostedTenant {
            platform_label: PlatformLabel::new(
                TenantId::new().as_uuid().simple().to_string()[16..].to_owned(),
            )
            .unwrap(),
            readable_address: ReadableAddress::Off,
            tenant_id: TenantId::new(),
            organization_slug: TenantSlug::new(org, &SlugLimits::default()).unwrap(),
            slug: TenantSlug::new(slug, &SlugLimits::default()).unwrap(),
            domains: domains
                .iter()
                .map(|d| DomainName::new(*d).unwrap())
                .collect(),
        }
    }

    fn host(name: &str) -> RequestHost {
        RequestHost::new(DomainName::new(name).unwrap()).unwrap()
    }

    fn tenant_of(tenant: &HostedTenant) -> HostResolution {
        HostResolution::Tenant(ScopedTenant::from_request_host(tenant.tenant_id))
    }

    #[test]
    fn a_tenant_answers_on_its_own_domain_and_random_platform_names() {
        let acme = hosted("acme", "prod", &["auth.acme.com"]);
        let table = HostTable::build([&acme], &base(), PlatformAddressing::Nested);

        for name in [
            "auth.acme.com".to_owned(),
            format!("{}.zero.test", acme.platform_label),
            format!("wiki.{}.zero.test", acme.platform_label),
        ] {
            assert_eq!(table.resolve(&host(&name)), tenant_of(&acme), "{name}");
        }
    }

    /// A host no tenant has is unknown, never someone's by default.
    #[test]
    fn an_unknown_host_belongs_to_no_tenant() {
        let acme = hosted("acme", "prod", &["auth.acme.com"]);
        let table = HostTable::build([&acme], &base(), PlatformAddressing::Nested);

        for name in [
            "other.com",
            "zero.test",
            "acme-staging.zero.test",
            "x.acme-prod.zero.test",
        ] {
            assert_eq!(
                table.resolve(&host(name)),
                HostResolution::Unknown,
                "{name}"
            );
        }
        assert_eq!(
            HostTable::default().resolve(&host("auth.acme.com")),
            HostResolution::Unknown
        );
    }

    #[test]
    fn a_wildcard_covers_one_label_and_no_more() {
        let acme = hosted("acme", "prod", &["*.auth.acme.com"]);
        let table = HostTable::build([&acme], &base(), PlatformAddressing::Nested);

        assert_eq!(table.resolve(&host("api.auth.acme.com")), tenant_of(&acme));
        assert_eq!(
            table.resolve(&host("a.b.auth.acme.com")),
            HostResolution::Unknown
        );
        assert_eq!(
            table.resolve(&host("auth.acme.com")),
            HostResolution::Unknown
        );
        assert_eq!(
            table.resolve(&host("api.notacme.com")),
            HostResolution::Unknown
        );
    }

    /// A tenant naming one host beneath another's wildcard gets its own
    /// requests, as the certificate picked for it says.
    #[test]
    fn an_exact_domain_beats_a_wildcard() {
        let wide = hosted("wide", "prod", &["*.auth.acme.com"]);
        let exact = hosted("exact", "prod", &["api.auth.acme.com"]);
        let table = HostTable::build([&wide, &exact], &base(), PlatformAddressing::Nested);

        assert_eq!(table.resolve(&host("api.auth.acme.com")), tenant_of(&exact));
        assert_eq!(table.resolve(&host("www.auth.acme.com")), tenant_of(&wide));
    }

    /// Exact and wildcard names claimed by two tenants both resolve as ambiguous.
    #[test]
    fn a_domain_two_tenants_claim_is_ambiguous() {
        let first = hosted("first", "prod", &["shop.acme.com", "*.acme.io"]);
        let second = hosted("second", "prod", &["shop.acme.com", "*.acme.io"]);
        let table = HostTable::build([&first, &second], &base(), PlatformAddressing::Nested);

        assert_eq!(
            table.resolve(&host("shop.acme.com")),
            HostResolution::Ambiguous
        );
        assert_eq!(table.resolve(&host("x.acme.io")), HostResolution::Ambiguous);
    }

    /// Concatenated organization/tenant slugs and tenant UUIDs resolve to no tenant.
    #[test]
    fn legacy_platform_addresses_are_refused() {
        let first = hosted("ab-cd", "ef", &[]);
        let second = hosted("ab", "cd-ef", &[]);
        let table = HostTable::build([&first, &second], &base(), PlatformAddressing::Nested);

        assert_eq!(
            table.resolve(&host("ab-cd-ef.zero.test")),
            HostResolution::Unknown
        );
        let own = format!("{}.zero.test", first.tenant_id);
        assert_eq!(table.resolve(&host(&own)), HostResolution::Unknown);
    }

    /// A custom registration inside the reserved platform namespace remains unknown.
    #[test]
    fn a_custom_domain_cannot_claim_the_platform_namespace() {
        let owner = hosted("acme", "prod", &[]);
        let squatter = hosted("evil", "prod", &["acme-prod.zero.test"]);
        let table = HostTable::build([&owner, &squatter], &base(), PlatformAddressing::Nested);

        assert_eq!(
            table.resolve(&host("acme-prod.zero.test")),
            HostResolution::Unknown
        );
    }

    /// A custom parent wildcard cannot claim the platform base, while its
    /// other child hosts still resolve to the tenant.
    #[test]
    fn a_parent_wildcard_cannot_serve_the_platform_base() {
        let tenant = hosted("acme", "main", &["*.example.com"]);
        let base = DomainName::new("apps.example.com").unwrap();
        let table = HostTable::build([&tenant], &base, PlatformAddressing::Disabled);
        assert_eq!(
            table.resolve(&host("apps.example.com")),
            HostResolution::Unknown
        );
        assert_eq!(table.resolve(&host("shop.example.com")), tenant_of(&tenant));
    }

    /// A readable app host resolves only while consent is enabled; withdrawing
    /// consent leaves the permanent random app host usable.
    #[test]
    fn readable_addresses_follow_consent() {
        let mut acme = hosted("acme", "main", &[]);
        let readable = host("wiki.main.acme.zero.test");
        let off = HostTable::build([&acme], &base(), PlatformAddressing::Nested);
        assert_eq!(off.resolve(&readable), HostResolution::Unknown);
        acme.readable_address = ReadableAddress::On;
        let on = HostTable::build([&acme], &base(), PlatformAddressing::Nested);
        assert_eq!(on.resolve(&readable), tenant_of(&acme));
        acme.readable_address = ReadableAddress::Off;
        let off = HostTable::build([&acme], &base(), PlatformAddressing::Nested);
        assert_eq!(off.resolve(&readable), HostResolution::Unknown);
        assert_eq!(
            off.resolve(&host(&format!("wiki.{}.zero.test", acme.platform_label))),
            tenant_of(&acme)
        );
    }

    /// Flat app labels resolve to their own tenant, while unknown suffixes
    /// and nested app names remain unknown.
    #[test]
    fn flat_addresses_preserve_tenant_isolation() {
        let acme = hosted("acme", "main", &[]);
        let other = hosted("other", "main", &[]);
        let table = HostTable::build([&acme, &other], &base(), PlatformAddressing::Flat);
        assert_eq!(
            table.resolve(&host(&format!("wiki-{}.zero.test", acme.platform_label))),
            tenant_of(&acme)
        );
        assert_eq!(
            table.resolve(&host(&format!("wiki-{}.zero.test", other.platform_label))),
            tenant_of(&other)
        );
        for name in [
            "wiki-unknown.zero.test".to_owned(),
            format!("wiki.{}.zero.test", acme.platform_label),
        ] {
            assert_eq!(table.resolve(&host(&name)), HostResolution::Unknown);
        }
    }

    /// Disabling platform addressing leaves random and readable aliases unknown
    /// while the tenant's custom domain still resolves.
    #[test]
    fn disabled_addresses_leave_only_custom_domains() {
        let mut acme = hosted("acme", "main", &["shop.acme.com"]);
        acme.readable_address = ReadableAddress::On;
        let table = HostTable::build([&acme], &base(), PlatformAddressing::Disabled);
        assert_eq!(table.resolve(&host("shop.acme.com")), tenant_of(&acme));
        assert_eq!(
            table.resolve(&host(&format!("{}.zero.test", acme.platform_label))),
            HostResolution::Unknown
        );
        assert_eq!(
            table.resolve(&host("wiki.main.acme.zero.test")),
            HostResolution::Unknown
        );
    }

    #[test]
    fn a_tenant_listing_a_name_twice_still_owns_it() {
        let acme = hosted("acme", "prod", &["shop.acme.com", "shop.acme.com"]);
        let table = HostTable::build([&acme], &base(), PlatformAddressing::Nested);

        assert_eq!(table.resolve(&host("shop.acme.com")), tenant_of(&acme));
    }

    proptest! {
        /// However many tenants claim names from a small pool, a name
        /// resolves to a tenant exactly when one tenant alone claims it.
        #[test]
        fn a_name_resolves_only_when_one_tenant_claims_it(
            claims in proptest::collection::vec(proptest::collection::vec(0usize..4, 0..4), 1..5),
        ) {
            let pool = ["a.acme.com", "b.acme.com", "c.acme.com", "d.acme.com"];
            let tenants: Vec<HostedTenant> = claims
                .iter()
                .enumerate()
                .map(|(i, picked)| {
                    let names: Vec<&str> = picked.iter().map(|p| pool[*p]).collect();
                    hosted(&format!("org{i}"), "prod", &names)
                })
                .collect();
            let table = HostTable::build(&tenants, &base(), PlatformAddressing::Nested);

            for (at, name) in pool.iter().enumerate() {
                let holders: Vec<&HostedTenant> = tenants
                    .iter()
                    .zip(&claims)
                    .filter(|(_, picked)| picked.contains(&at))
                    .map(|(tenant, _)| tenant)
                    .collect();
                let expected = match holders.as_slice() {
                    [] => HostResolution::Unknown,
                    [only] => tenant_of(only),
                    _ => HostResolution::Ambiguous,
                };
                prop_assert_eq!(table.resolve(&host(name)), expected);
            }
        }
    }
}
