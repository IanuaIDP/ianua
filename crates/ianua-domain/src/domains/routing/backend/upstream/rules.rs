//! The rules between an upstream's settings.

use crate::domains::routing::backend::balancing::StickyKeyNeed;
use crate::domains::routing::backend::upstream::{Upstream, UpstreamTimeout};
use crate::domains::routing::connector::scope::UpstreamReach;
use crate::message;
use crate::shared::errors::DomainError;

/// Refuses `upstream` when two of its settings contradict each other.
pub(crate) fn check(upstream: &Upstream) -> Result<(), DomainError> {
    tls_fits(upstream)?;
    sticky_key_fits(upstream)?;
    retries_fit(upstream)?;
    reach_fits(upstream)
}

/// TLS settings speak to HTTPS backends only. On a plain `http://` address
/// they would read as protecting a connection that is sent in the clear.
fn tls_fits(upstream: &Upstream) -> Result<(), DomainError> {
    let plain = upstream
        .all_target_urls()
        .into_iter()
        .any(|url| !url.is_https());
    if upstream.tls.value().is_some() && plain {
        return Err(DomainError::invalid(message!(
            "routing-upstream-tls-settings-need-every-backend",
            "upstream TLS settings need every backend reached over https"
        )));
    }
    Ok(())
}

/// The way backends are picked gets the sticky key it asks for.
fn sticky_key_fits(upstream: &Upstream) -> Result<(), DomainError> {
    let has_key = upstream.sticky_session.value().is_some();
    match (upstream.balancing.sticky_key(), has_key) {
        (StickyKeyNeed::Required, false) => Err(DomainError::invalid(message!(
            "routing-consistent-hashing-needs-a-sticky-session",
            "consistent hashing needs a sticky session key to hash"
        ))),
        (StickyKeyNeed::Refused, true) => Err(DomainError::invalid(message!(
            "routing-least-connections-picks-the-least-busy",
            "least connections picks the least busy backend, so it takes no sticky key"
        ))),
        (StickyKeyNeed::Either | StickyKeyNeed::Required | StickyKeyNeed::Refused, _) => Ok(()),
    }
}

/// Every try of one request, each waiting up to the timeout, waits no
/// longer together than one request may. A backend that hangs must not hold
/// a client's connection for many timeouts in a row.
fn retries_fit(upstream: &Upstream) -> Result<(), DomainError> {
    let Some(retry) = upstream.retry.value() else {
        return Ok(());
    };
    let longest = upstream
        .timeout_secs
        .as_secs()
        .saturating_mul(u32::from(retry.attempts()));
    if longest > UpstreamTimeout::MAX_SECS {
        return Err(DomainError::invalid(message!(
            "routing-tries-of-seconds-each-could-hold",
            format!(
                "{} tries of {} seconds each could hold a request longer than {} seconds",
                retry.attempts(),
                upstream.timeout_secs.as_secs(),
                UpstreamTimeout::MAX_SECS
            )
        )));
    }
    Ok(())
}

/// Backends behind a connector are found by the connector, inside its
/// network. The gateway's own resolver cannot see those names.
fn reach_fits(upstream: &Upstream) -> Result<(), DomainError> {
    let behind_connector = matches!(upstream.reach, UpstreamReach::Connector(_));
    if behind_connector && upstream.discovery.value().is_some() {
        return Err(DomainError::invalid(message!(
            "routing-backends-reached-through-a-connector-are",
            "backends reached through a connector are listed, not found by the gateway's DNS"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::routing::backend::balancing::LoadBalancing;
    use crate::domains::routing::backend::discovery::{Discovery, DiscoveryKind, DiscoveryName};
    use crate::domains::routing::backend::retry::{
        RetriedMethods, RetryOn, RetryPolicy, UpstreamRetryParams,
    };
    use crate::domains::routing::backend::tls::{UpstreamTls, UpstreamTlsParams, UpstreamTrust};
    use crate::domains::routing::backend::upstream::{HostHeader, StickySession};
    use crate::types::{ConnectorId, HttpUrl, Seconds, Setting};

    fn upstream(url: &str) -> Upstream {
        Upstream::new(
            HttpUrl::new(url).unwrap(),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
    }

    fn tls() -> UpstreamTls {
        UpstreamTls::new(UpstreamTlsParams {
            trust: UpstreamTrust::PublicRoots,
            client_certificate: Setting::Unset,
            server_name: Setting::Unset,
        })
        .unwrap()
    }

    fn retries(attempts: u8) -> RetryPolicy {
        RetryPolicy::new(UpstreamRetryParams {
            attempts,
            retry_on: vec![RetryOn::Unavailable],
            methods: RetriedMethods::IdempotentOnly,
            base_backoff_ms: 100,
            max_backoff_ms: 1_000,
        })
        .unwrap()
    }

    /// A plain upstream with nothing extra set passes.
    #[test]
    fn a_plain_upstream_is_consistent() {
        assert!(check(&upstream("http://a:8080")).is_ok());
    }

    /// Explicit TLS settings are invalid on a plain HTTP backend and valid
    /// on an HTTPS backend.
    #[test]
    fn tls_settings_need_https_backends() {
        assert!(check(&upstream("http://payroll:8080").with_tls(tls())).is_err());
        assert!(check(&upstream("https://payroll:8443").with_tls(tls())).is_ok());
    }

    /// Consistent hashing with no sticky key has nothing to hash, and least
    /// connections with one would ignore it. Both are refused.
    #[test]
    fn the_way_backends_are_picked_gets_the_sticky_key_it_asks_for() {
        let hashing = upstream("http://a:8080").with_balancing(LoadBalancing::ConsistentHash);
        let least = upstream("http://a:8080")
            .with_sticky(StickySession::UserId)
            .with_balancing(LoadBalancing::LeastConnections);

        assert!(check(&hashing).is_err());
        assert!(check(&least).is_err());
        assert!(check(&hashing.with_sticky(StickySession::UserId)).is_ok());
    }

    /// Five attempts with a 300-second timeout exceed the request bound.
    /// Three attempts with the default timeout pass validation.
    #[test]
    fn every_try_together_waits_no_longer_than_one_request_may() {
        let slow = Upstream::new(
            HttpUrl::new("http://a:8080").unwrap(),
            UpstreamTimeout::seconds(300).unwrap(),
            HostHeader::Rewrite,
        )
        .with_retries(retries(5));

        assert!(check(&slow).is_err());
        assert!(check(&upstream("http://a:8080").with_retries(retries(3))).is_ok());
    }

    /// An upstream found by DNS and reached through a connector is refused:
    /// the gateway cannot resolve names inside the connector's network.
    #[test]
    fn a_connector_upstream_lists_its_backends() {
        let discovery = Discovery::new(
            DiscoveryKind::Address,
            DiscoveryName::new("orders.internal").unwrap(),
            Seconds::new(60),
        )
        .unwrap();
        let found = upstream("http://a:8080")
            .with_discovery(discovery)
            .through_connector(ConnectorId::new());

        assert!(check(&found).is_err());
        assert!(check(&upstream("http://a:8080").through_connector(ConnectorId::new())).is_ok());
    }
}
