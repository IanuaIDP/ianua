//! Tenant hostnames shared by provisioning, DNS, the API and the gateway.

mod certificate;
mod label;

pub use certificate::{PlatformCertificate, PlatformCertificateRow};
pub use label::PlatformLabel;

use crate::types::{DomainName, TenantSlug};

/// The address shape a deployment can serve with its certificates.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PlatformAddressing {
    /// Only tenants' custom domains are served.
    #[default]
    Disabled,
    /// An operator's wildcard covers `app-label.base` and `label.base`.
    Flat,
    /// Per-tenant certificates cover `label.base` and `*.label.base`.
    Nested,
}

/// Whether a tenant publishes its organization and tenant names in DNS and
/// publicly trusted certificate transparency logs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ReadableAddress {
    /// Only the random platform label is served.
    #[default]
    Off,
    /// The tenant explicitly chose to publish its readable name.
    On,
}

impl ReadableAddress {
    /// The stable spelling used in audit records.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
        }
    }
}

/// A tenant's random address and its explicitly enabled readable address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformHosts {
    readable: Option<DomainName>,
    stable: Option<DomainName>,
}

/// Stored facts used to construct the tenant's platform names.
#[derive(Debug, Clone, Copy)]
pub struct PlatformHostParts<'a> {
    /// The permanent opaque label.
    pub label: &'a PlatformLabel,
    /// The organization's slug.
    pub organization_slug: &'a TenantSlug,
    /// The tenant's slug within the organization.
    pub tenant_slug: &'a TenantSlug,
    /// Whether the tenant consented to publishing its readable name.
    pub readable: ReadableAddress,
}

impl PlatformHosts {
    /// Builds only names enabled by the deployment and tenant. Readable
    /// addresses require nested certificates; an operator's single wildcard
    /// never covers them. Names exceeding DNS bounds are never shortened.
    #[must_use]
    pub fn under(
        base: &DomainName,
        parts: PlatformHostParts<'_>,
        shape: PlatformAddressing,
    ) -> Self {
        if shape == PlatformAddressing::Disabled {
            return Self {
                readable: None,
                stable: None,
            };
        }
        let readable = match (shape, parts.readable) {
            (PlatformAddressing::Nested, ReadableAddress::On) => DomainName::new(format!(
                "{}.{}.{}",
                parts.tenant_slug.as_str(),
                parts.organization_slug.as_str(),
                base.as_str()
            ))
            .ok(),
            _ => None,
        };
        Self {
            readable,
            stable: DomainName::new(format!("{}.{}", parts.label.as_str(), base.as_str())).ok(),
        }
    }

    /// The opted-in readable address, when the deployment supports it.
    #[must_use]
    pub fn readable(&self) -> Option<&DomainName> {
        self.readable.as_ref()
    }

    /// The random platform address, when platform addressing is enabled.
    #[must_use]
    pub fn stable(&self) -> Option<&DomainName> {
        self.stable.as_ref()
    }

    /// Every enabled tenant address, random first.
    pub fn names(&self) -> impl Iterator<Item = &DomainName> {
        self.stable.iter().chain(self.readable.iter())
    }

    /// Whether an exact name or one-label wildcard belongs to these enabled addresses.
    #[must_use]
    pub fn serves(&self, host: &DomainName, shape: PlatformAddressing) -> bool {
        self.names().any(|root| {
            if root == host {
                return true;
            }
            let separator = match shape {
                PlatformAddressing::Disabled => return false,
                PlatformAddressing::Flat => '-',
                PlatformAddressing::Nested => '.',
            };
            host.as_str()
                .strip_suffix(root.as_str())
                .and_then(|prefix| prefix.strip_suffix(separator))
                .is_some_and(|prefix| {
                    !prefix.is_empty()
                        && !prefix.contains('.')
                        && (shape == PlatformAddressing::Nested || !host.is_wildcard())
                })
        })
    }

    /// The random app address in the deployment shape. Invalid or overlong
    /// names have no address, rather than a truncated alias.
    #[must_use]
    pub fn app(&self, app: &TenantSlug, shape: PlatformAddressing) -> Option<DomainName> {
        let root = self.stable.as_ref()?;
        let separator = match shape {
            PlatformAddressing::Disabled => return None,
            PlatformAddressing::Flat => '-',
            PlatformAddressing::Nested => '.',
        };
        DomainName::new(format!("{}{separator}{}", app.as_str(), root.as_str())).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::config::SlugLimits;

    /// Builds Acme's main tenant using a fixed opaque label.
    fn hosts(shape: PlatformAddressing, readable: ReadableAddress) -> PlatformHosts {
        PlatformHosts::under(
            &DomainName::new("apps.example.com").unwrap(),
            PlatformHostParts {
                label: &PlatformLabel::new("k7f3q9").unwrap(),
                organization_slug: &slug("acme"),
                tenant_slug: &slug("main"),
                readable,
            },
            shape,
        )
    }

    /// A valid slug with the deployment's ordinary bounds.
    fn slug(value: &str) -> TenantSlug {
        TenantSlug::new(value, &SlugLimits::default()).unwrap()
    }

    /// The default hides readable names while apps sit beneath the random
    /// label in deployments issuing per-tenant certificates.
    #[test]
    fn nested_addresses_publish_only_the_random_label_by_default() {
        let names = hosts(PlatformAddressing::Nested, ReadableAddress::Off);
        assert_eq!(names.stable().unwrap().as_str(), "k7f3q9.apps.example.com");
        assert_eq!(names.readable(), None);
        assert_eq!(
            names
                .app(&slug("wiki"), PlatformAddressing::Nested)
                .unwrap()
                .as_str(),
            "wiki.k7f3q9.apps.example.com"
        );
    }

    /// Opting in adds tenant then organization names without replacing the
    /// permanent random address. Turning it off removes the alias.
    #[test]
    fn readable_addresses_are_an_explicit_addition() {
        let names = hosts(PlatformAddressing::Nested, ReadableAddress::On);
        assert_eq!(
            names.readable().unwrap().as_str(),
            "main.acme.apps.example.com"
        );
        assert_eq!(names.names().count(), 2);
        assert_eq!(
            hosts(PlatformAddressing::Nested, ReadableAddress::Off)
                .names()
                .count(),
            1
        );
    }

    /// Flat addressing places apps in one label beneath the platform base
    /// and omits readable names even when the tenant enables them.
    #[test]
    fn flat_addresses_fit_one_wildcard() {
        let names = hosts(PlatformAddressing::Flat, ReadableAddress::On);
        assert_eq!(
            names
                .app(&slug("wiki"), PlatformAddressing::Flat)
                .unwrap()
                .as_str(),
            "wiki-k7f3q9.apps.example.com"
        );
        assert!(names.readable().is_none());
    }

    /// Disabled platform addressing produces no tenant or app names,
    /// even when readable addressing is enabled for the tenant.
    #[test]
    fn disabled_platform_addresses_publish_nothing() {
        let names = hosts(PlatformAddressing::Disabled, ReadableAddress::On);
        assert_eq!(names.names().count(), 0);
        assert!(
            names
                .app(&slug("wiki"), PlatformAddressing::Disabled)
                .is_none()
        );
    }
}
