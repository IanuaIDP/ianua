//! The names a client resolves: the domain tenants' apps sit under and the
//! domain customers bring names under, at the stack's gateway; every other
//! name under the stack's own domain at its ingress; nothing else.

use std::net::SocketAddr;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// A name outside the stack's domains, which no client of the stack may
/// reach.
#[derive(Debug, thiserror::Error)]
#[error("{0} is not a name of the stack")]
struct NotTheStacks(String);

/// Where a name of the stack is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Front {
    /// The ingress in front of the API.
    Ingress,
    /// The gateway in front of tenants' apps.
    Gateway,
}

/// Resolves the stack's names to its ingress and its gateway.
#[derive(Debug, Clone)]
pub(crate) struct StackNames {
    base_domain: String,
    ingress: SocketAddr,
    gateway_domains: Vec<String>,
    gateway: SocketAddr,
}

/// Where each of a stack's names is served.
pub(crate) struct Fronts<'a> {
    /// The stack's own domain.
    pub(crate) base_domain: &'a str,
    /// Socket receiving resolved requests for the stack's API domain.
    pub(crate) ingress: SocketAddr,
    /// The domains served at its gateway: tenants' apps and customers'
    /// own names.
    pub(crate) gateway_domains: &'a [String],
    /// Socket receiving resolved requests for tenants' application domains.
    pub(crate) gateway: SocketAddr,
}

impl StackNames {
    /// The names `fronts` describes.
    pub(crate) fn new(fronts: &Fronts<'_>) -> Self {
        Self {
            base_domain: fronts.base_domain.to_ascii_lowercase(),
            ingress: fronts.ingress,
            gateway_domains: fronts
                .gateway_domains
                .iter()
                .map(|domain| domain.to_ascii_lowercase())
                .collect(),
            gateway: fronts.gateway,
        }
    }

    /// Where `host` is served, when it is a name of the stack.
    pub(crate) fn front_of(&self, host: &str) -> Option<Front> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self
            .gateway_domains
            .iter()
            .any(|domain| under(&host, domain))
        {
            return Some(Front::Gateway);
        }
        under(&host, &self.base_domain).then_some(Front::Ingress)
    }

    /// The address `host` resolves to, when it is a name of the stack.
    fn address_of(&self, host: &str) -> Option<SocketAddr> {
        match self.front_of(host)? {
            Front::Ingress => Some(self.ingress),
            Front::Gateway => Some(self.gateway),
        }
    }
}

/// Whether `host` is `domain` or a name under it.
fn under(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

impl Resolve for StackNames {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let found = self.address_of(&host);
        Box::pin(async move {
            let Some(address) = found else {
                return Err(
                    Box::new(NotTheStacks(host)) as Box<dyn std::error::Error + Send + Sync>
                );
            };
            let addrs: Addrs = Box::new(std::iter::once(address));
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> StackNames {
        StackNames::new(&Fronts {
            base_domain: "s1.test",
            ingress: "127.0.0.1:443".parse().unwrap(),
            gateway_domains: &["apps.s1.test".to_owned(), "s1.example".to_owned()],
            gateway: "127.0.0.1:8443".parse().unwrap(),
        })
    }

    /// The domain and every name under it are the stack's; a name that
    /// merely ends the same is not.
    #[test]
    fn only_the_domain_and_names_under_it_are_the_stacks() {
        let names = names();

        assert_eq!(names.front_of("s1.test"), Some(Front::Ingress));
        assert_eq!(names.front_of("App.S1.test"), Some(Front::Ingress));
        assert_eq!(names.front_of("evils1.test"), None);
        assert_eq!(names.front_of("example.com"), None);
    }

    /// Tenants' apps and customers' own names are at the gateway.
    #[test]
    fn apps_and_customer_names_are_at_the_gateway() {
        let names = names();

        assert_eq!(
            names.front_of("acme-prod.apps.s1.test"),
            Some(Front::Gateway)
        );
        assert_eq!(names.front_of("shop.s1.example"), Some(Front::Gateway));
        assert_eq!(names.front_of("shop.s2.example"), None);
    }
}
