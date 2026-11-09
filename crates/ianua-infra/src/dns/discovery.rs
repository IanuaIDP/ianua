//! Finding a service's backends by asking DNS what is behind a name.
//!
//! `SRV` records serve a registry that publishes a port and a weight per
//! target; `A` and `AAAA` records serve a Kubernetes headless service,
//! whose port is the one the service's own upstream URL names. A name with
//! no records, or no name at all, is an answer with no backends: a
//! deployment scaled to zero reads that way, and the proxy then refuses the
//! route. A resolver that cannot be reached, or does not answer in time, is
//! an error, so the caller keeps the last answer it had.
//!
//! The resolver's own cache does not decide freshness: the service's
//! refresh interval does, since that is the number an operator set.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::rdata::SRV;
use hickory_resolver::proto::rr::{RData, Record};
use ianua_app::ports::routing::BackendDiscovery;
use ianua_domain::domains::routing::backend::discovery::{
    DiscoveredBackend, DiscoveredBackends, Discovery, DiscoveryKind,
};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::HttpUrl;
use tokio::sync::OnceCell;

/// The weight of every address of an `A` or `AAAA` answer, and of an `SRV`
/// target that declares zero. A target published with weight zero is meant
/// to be picked rarely, never to be left out.
const LEAST_WEIGHT: u32 = 1;

/// How many times one lookup is sent before it is a failure. The next
/// refresh asks again, so waiting longer buys nothing.
const LOOKUP_ATTEMPTS: usize = 1;

/// Asks the system's resolver, which inside a cluster is the cluster's own
/// DNS, what is behind a service's name.
///
/// The resolver is built on the first question, not at start: building one
/// reads the system configuration and may probe its nameservers, which a
/// deployment where no service names its backends should not pay for.
pub struct DnsBackendDiscovery {
    resolver: OnceCell<TokioResolver>,
    lookup_timeout: Duration,
}

impl DnsBackendDiscovery {
    /// A discovery whose every lookup gives up after `lookup_timeout`.
    #[must_use]
    pub fn new(lookup_timeout: Duration) -> Self {
        Self {
            resolver: OnceCell::new(),
            lookup_timeout,
        }
    }

    /// The resolver, built if this is the first question.
    async fn resolver(&self) -> Result<&TokioResolver, DomainError> {
        self.resolver
            .get_or_try_init(|| async { built(self.lookup_timeout) })
            .await
    }

    /// The `SRV` targets behind `name`, spoken to with `scheme`.
    async fn by_service(
        &self,
        name: &str,
        scheme: &str,
    ) -> Result<Vec<DiscoveredBackend>, DomainError> {
        let resolver = self.resolver().await?;
        let answer = self.bounded(resolver.srv_lookup(name)).await?;
        Ok(answer.map_or_else(Vec::new, |lookup| {
            service_backends(lookup.answers(), scheme)
        }))
    }

    /// The addresses behind `name`, spoken to with `scheme` on `port`.
    async fn by_address(
        &self,
        name: &str,
        scheme: &str,
        port: u16,
    ) -> Result<Vec<DiscoveredBackend>, DomainError> {
        let resolver = self.resolver().await?;
        let answer = self.bounded(resolver.lookup_ip(name)).await?;
        Ok(answer.map_or_else(Vec::new, |lookup| {
            address_backends(lookup.iter(), scheme, port)
        }))
    }

    /// What `lookup` answered within the timeout: `None` when the name has
    /// no records or does not exist.
    async fn bounded<T>(
        &self,
        lookup: impl Future<Output = Result<T, NetError>>,
    ) -> Result<Option<T>, DomainError> {
        let answered = tokio::time::timeout(self.lookup_timeout, lookup)
            .await
            .map_err(|_| DomainError::infra_msg("the resolver did not answer in time"))?;
        match answered {
            Ok(answer) => Ok(Some(answer)),
            Err(error) if error.is_no_records_found() || error.is_nx_domain() => Ok(None),
            Err(error) => Err(DomainError::infra(error)),
        }
    }
}

#[async_trait]
impl BackendDiscovery for DnsBackendDiscovery {
    async fn resolve(
        &self,
        discovery: &Discovery,
        configured: &HttpUrl,
    ) -> Result<DiscoveredBackends, DomainError> {
        let name = discovery.name().as_str();
        let scheme = scheme_of(configured);
        let backends = match discovery.kind() {
            DiscoveryKind::Srv => self.by_service(name, scheme).await?,
            DiscoveryKind::Address => self.by_address(name, scheme, configured.port()).await?,
        };
        Ok(DiscoveredBackends::new(backends))
    }
}

/// A resolver from the system configuration, each lookup held to
/// `lookup_timeout` and sent once.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when the configuration cannot be
/// read.
fn built(lookup_timeout: Duration) -> Result<TokioResolver, DomainError> {
    let mut builder = TokioResolver::builder_tokio().map_err(DomainError::infra)?;
    builder.options_mut().timeout = lookup_timeout;
    builder.options_mut().attempts = LOOKUP_ATTEMPTS;
    builder.build().map_err(DomainError::infra)
}

/// The scheme every discovered backend is spoken to with: the configured
/// one, so a service written as `https://` stays encrypted.
fn scheme_of(configured: &HttpUrl) -> &'static str {
    if configured.is_https() {
        return "https";
    }
    "http"
}

/// The backends of an `SRV` answer.
///
/// Only the targets of the lowest priority are kept: the others are
/// fallbacks a client tries only when those fail, and the proxy weighs
/// every backend it holds alike. A target of `.` says the service is not
/// offered there, and a target that is not a usable address is skipped.
fn service_backends(records: &[Record], scheme: &str) -> Vec<DiscoveredBackend> {
    let targets: Vec<&SRV> = records.iter().filter_map(service_target).collect();
    let Some(first) = targets.iter().map(|target| target.priority).min() else {
        return Vec::new();
    };
    targets
        .into_iter()
        .filter(|target| target.priority == first)
        .filter_map(|target| service_backend(target, scheme))
        .collect()
}

/// The `SRV` data of `record`, when it holds one.
fn service_target(record: &Record) -> Option<&SRV> {
    let RData::SRV(target) = &record.data else {
        return None;
    };
    Some(target)
}

/// The backend `target` names, or `None` when it names none.
fn service_backend(target: &SRV, scheme: &str) -> Option<DiscoveredBackend> {
    let host = target.target.to_utf8();
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    let Ok(url) = HttpUrl::new(format!("{scheme}://{host}:{}", target.port)) else {
        tracing::warn!(host, "an SRV target is not a usable address; skipped");
        return None;
    };
    Some(DiscoveredBackend {
        url,
        weight: u32::from(target.weight).max(LEAST_WEIGHT),
    })
}

/// The backends of an address answer, each on `port`.
fn address_backends(
    addresses: impl Iterator<Item = IpAddr>,
    scheme: &str,
    port: u16,
) -> Vec<DiscoveredBackend> {
    addresses
        .filter_map(|address| address_backend(address, scheme, port))
        .collect()
}

/// The backend at `address` on `port`, an IPv6 address in brackets.
fn address_backend(address: IpAddr, scheme: &str, port: u16) -> Option<DiscoveredBackend> {
    let authority = match address {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    };
    let Ok(url) = HttpUrl::new(format!("{scheme}://{authority}")) else {
        tracing::warn!(%address, "a resolved address is not usable; skipped");
        return None;
    };
    Some(DiscoveredBackend {
        url,
        weight: LEAST_WEIGHT,
    })
}

#[cfg(test)]
mod tests {
    use hickory_resolver::proto::rr::Name;
    use ianua_domain::domains::routing::backend::discovery::DiscoveryName;
    use ianua_domain::types::Seconds;

    use super::*;

    fn srv(priority: u16, weight: u16, port: u16, target: &str) -> Record {
        let name = Name::from_ascii("_http._tcp.orders.internal.").unwrap();
        Record::from_rdata(
            name,
            30,
            RData::SRV(SRV::new(
                priority,
                weight,
                port,
                Name::from_ascii(target).unwrap(),
            )),
        )
    }

    fn urls(backends: &[DiscoveredBackend]) -> Vec<&str> {
        backends
            .iter()
            .map(|backend| backend.url.as_str())
            .collect()
    }

    /// Two SRV targets come back with their own ports and weights, spoken
    /// to with the service's scheme.
    #[test]
    fn srv_targets_keep_their_ports_and_weights() {
        let records = [
            srv(10, 60, 8080, "a.orders.internal."),
            srv(10, 40, 8081, "b.orders.internal."),
        ];

        let backends = service_backends(&records, "https");

        assert_eq!(
            urls(&backends),
            [
                "https://a.orders.internal:8080",
                "https://b.orders.internal:8081"
            ]
        );
        assert_eq!(
            backends.iter().map(|b| b.weight).collect::<Vec<_>>(),
            [60, 40]
        );
    }

    /// A fallback target of a higher priority is left out while a target
    /// of the lowest priority is there.
    #[test]
    fn only_the_lowest_priority_is_kept() {
        let records = [
            srv(20, 10, 8080, "backup.orders.internal."),
            srv(10, 10, 8080, "main.orders.internal."),
        ];

        let backends = service_backends(&records, "http");

        assert_eq!(urls(&backends), ["http://main.orders.internal:8080"]);
    }

    /// A target published with weight zero is still picked, rarely.
    #[test]
    fn a_zero_weight_target_is_kept_at_the_least_weight() {
        let backends = service_backends(&[srv(10, 0, 8080, "a.orders.internal.")], "http");

        assert_eq!(backends.first().map(|b| b.weight), Some(LEAST_WEIGHT));
    }

    /// A target of `.` says the service is not offered, so it is no
    /// backend.
    #[test]
    fn a_root_target_is_no_backend() {
        let backends = service_backends(&[srv(10, 10, 8080, ".")], "http");

        assert!(backends.is_empty());
    }

    /// An IPv6 address is written in brackets, on the service's port, and
    /// an IPv4 one without.
    #[test]
    fn addresses_take_the_services_port() {
        let addresses = ["10.0.0.1".parse().unwrap(), "fd00::1".parse().unwrap()];

        let backends = address_backends(addresses.into_iter(), "http", 9443);

        assert_eq!(
            urls(&backends),
            ["http://10.0.0.1:9443", "http://[fd00::1]:9443"]
        );
    }

    /// A name every machine agrees on resolves, through the hosts file, to
    /// backends on the port and scheme the service names.
    #[tokio::test]
    async fn localhost_resolves_on_the_services_port_and_scheme() {
        let discovery = Discovery::new(
            DiscoveryKind::Address,
            DiscoveryName::new("localhost").unwrap(),
            Seconds::new(30),
        )
        .unwrap();
        let configured = HttpUrl::new("https://shop.internal:9443").unwrap();

        let resolved = DnsBackendDiscovery::new(Duration::from_secs(3))
            .resolve(&discovery, &configured)
            .await
            .unwrap();

        assert!(!resolved.is_empty());
        assert!(
            resolved
                .as_slice()
                .iter()
                .all(|backend| backend.url.as_str().starts_with("https://")
                    && backend.url.as_str().ends_with(":9443"))
        );
    }
}
