//! An upstream as stored, read back through the rules between its settings.

use crate::domains::routing::backend::assertion::AssertionAudience;
use crate::domains::routing::backend::balancing::LoadBalancing;
use crate::domains::routing::backend::circuit_breaker::CircuitBreaker;
use crate::domains::routing::backend::discovery::Discovery;
use crate::domains::routing::backend::retry::RetryPolicy;
use crate::domains::routing::backend::tls::UpstreamTls;
use crate::domains::routing::backend::upstream::{
    HostHeader, PlaintextHttp2, RouteIdentity, StickySession, TokenAudience, Upstream,
    UpstreamTimeout, WeightedBackend,
};
use crate::domains::routing::connector::scope::UpstreamReach;
use crate::shared::errors::DomainError;
use crate::types::{HttpUrl, Setting};

/// [`Upstream`] as JSON spells it, before the rules between its settings
/// are checked.
///
/// The audience and identity fields have no default. A row that lost them
/// would load as a token route open to any token, so it does not load.
#[derive(serde::Deserialize)]
pub(crate) struct UpstreamRecord {
    url: HttpUrl,
    timeout_secs: UpstreamTimeout,
    preserve_host: HostHeader,
    #[serde(default)]
    backends: Vec<WeightedBackend>,
    #[serde(default)]
    discovery: Setting<Discovery>,
    #[serde(default)]
    sticky_session: Setting<StickySession>,
    expected_audience: TokenAudience,
    identity: RouteIdentity,
    #[serde(default)]
    plaintext_http2: PlaintextHttp2,
    #[serde(default)]
    tls: Setting<UpstreamTls>,
    #[serde(default)]
    retry: Setting<RetryPolicy>,
    #[serde(default)]
    balancing: LoadBalancing,
    #[serde(default)]
    circuit_breaker: CircuitBreaker,
    #[serde(default)]
    assertion_audience: AssertionAudience,
    #[serde(default)]
    reach: UpstreamReach,
}

impl TryFrom<UpstreamRecord> for Upstream {
    type Error = DomainError;

    fn try_from(record: UpstreamRecord) -> Result<Self, Self::Error> {
        let upstream = Self {
            url: record.url,
            timeout_secs: record.timeout_secs,
            preserve_host: record.preserve_host,
            backends: record.backends,
            discovery: record.discovery,
            sticky_session: record.sticky_session,
            expected_audience: record.expected_audience,
            identity: record.identity,
            plaintext_http2: record.plaintext_http2,
            tls: record.tls,
            retry: record.retry,
            balancing: record.balancing,
            circuit_breaker: record.circuit_breaker,
            assertion_audience: record.assertion_audience,
            reach: record.reach,
        };
        upstream.ensure_consistent()?;
        Ok(upstream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored upstream at `http://` with TLS settings is refused when
    /// read, as building it would be.
    #[test]
    fn a_stored_upstream_is_held_to_the_rules_between_its_settings() {
        let stored = serde_json::json!({
            "url": "http://payroll:8080",
            "timeout_secs": 30,
            "preserve_host": false,
            "expected_audience": "no_token_accepted",
            "identity": "token",
            "tls": { "trust": "public_roots" },
        });

        assert!(serde_json::from_value::<Upstream>(stored).is_err());
    }

    /// An upstream with retries, a breaker, least connections and a named
    /// assertion audience is written and read back equal.
    #[test]
    fn every_new_setting_survives_a_round_trip() {
        let upstream = Upstream::new(
            HttpUrl::new("https://payroll:8443").unwrap(),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
        .with_balancing(LoadBalancing::LeastConnections)
        .with_circuit_breaker(CircuitBreaker::Off)
        .with_assertion_audience(AssertionAudience::Named(
            crate::types::Audience::new("payroll").unwrap(),
        ));

        let json = serde_json::to_value(&upstream).unwrap();

        assert_eq!(serde_json::from_value::<Upstream>(json).unwrap(), upstream);
    }
}
