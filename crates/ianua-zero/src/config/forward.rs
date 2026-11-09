//! Where the gateway may forward to, how it finds the backends a service
//! names by DNS, and how its connections to backends are opened and kept.

use std::time::Duration;

use ianua_boot::env::{Env, Read};
use ianua_domain::shared::security::ssrf::UpstreamNetworks;

/// Where the gateway may forward to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForwardConfig {
    /// `UPSTREAM_NETWORKS`: the internal networks route upstreams may
    /// resolve into, as CIDR blocks, beside public addresses. The server
    /// reads the same setting to check upstreams when they are written.
    pub upstream_networks: UpstreamNetworks,
    /// `GATEWAY_DISCOVERY_REFRESH_SECONDS` (5): how often the services
    /// that name their backends by DNS are checked for a lookup that is
    /// due. Each is looked up on its own interval; this bounds how late.
    pub discovery_refresh: Duration,
    /// `GATEWAY_DNS_LOOKUP_TIMEOUT_SECONDS` (3): one backend lookup.
    pub dns_lookup_timeout: Duration,
    /// How connections to backends are opened and kept.
    pub connections: UpstreamConnections,
}

/// How connections to backends are opened, kept, and how long an answer
/// may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UpstreamConnections {
    /// `GATEWAY_CONNECT_TIMEOUT_SECONDS` (5): opening one connection.
    pub connect_timeout: Duration,
    /// `GATEWAY_RESPONSE_DEADLINE_SECONDS` (300): the longest a whole
    /// answer may take to arrive, its body included. A service's own
    /// timeout bounds its first byte.
    pub response_deadline: Duration,
    /// `GATEWAY_LONG_LIVED_IDLE_SECONDS` (60): how long a long-lived answer,
    /// such as server-sent events, may send nothing before it is cut off.
    /// It is held to this instead of the response deadline.
    pub long_lived_idle: Duration,
    /// `GATEWAY_POOL_IDLE_SECONDS` (90): how long an idle connection to a
    /// backend is kept for reuse.
    pub pool_idle: Duration,
    /// `GATEWAY_POOL_MAX_IDLE_PER_BACKEND` (32): idle connections kept per
    /// backend.
    pub pool_max_idle_per_backend: usize,
    /// `GATEWAY_MAX_TUNNELS` (4096): upgraded connections, such as
    /// WebSockets, open at once across every route.
    pub max_tunnels: usize,
}

impl ForwardConfig {
    /// The forwarding settings `vars` holds.
    ///
    /// # Errors
    ///
    /// An upstream network that is no CIDR range, or a time or count out of
    /// its range.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            connections: connections(vars)?,
            upstream_networks: vars.networks("UPSTREAM_NETWORKS")?,
            discovery_refresh: vars.seconds_in(
                "GATEWAY_DISCOVERY_REFRESH_SECONDS",
                Duration::from_secs(5),
                1..=3600,
            )?,
            dns_lookup_timeout: vars.seconds_in(
                "GATEWAY_DNS_LOOKUP_TIMEOUT_SECONDS",
                Duration::from_secs(3),
                1..=30,
            )?,
        })
    }
}

/// How connections to backends are opened and kept.
fn connections(vars: &Env) -> Read<UpstreamConnections> {
    Ok(UpstreamConnections {
        connect_timeout: vars.seconds_in(
            "GATEWAY_CONNECT_TIMEOUT_SECONDS",
            Duration::from_secs(5),
            1..=60,
        )?,
        response_deadline: vars.seconds_in(
            "GATEWAY_RESPONSE_DEADLINE_SECONDS",
            Duration::from_secs(300),
            1..=86_400,
        )?,
        long_lived_idle: vars.seconds_in(
            "GATEWAY_LONG_LIVED_IDLE_SECONDS",
            Duration::from_secs(60),
            1..=86_400,
        )?,
        pool_idle: vars.seconds_in(
            "GATEWAY_POOL_IDLE_SECONDS",
            Duration::from_secs(90),
            1..=3600,
        )?,
        pool_max_idle_per_backend: vars.number_in(
            "GATEWAY_POOL_MAX_IDLE_PER_BACKEND",
            32,
            0..=1024,
        )?,
        max_tunnels: vars.number_in("GATEWAY_MAX_TUNNELS", 4096, 1..=1_000_000)?,
    })
}

#[cfg(test)]
mod tests {
    use ianua_boot::env::ConfigError;

    use super::*;

    /// With nothing set, upstreams reach public addresses only and the
    /// documented times hold.
    #[test]
    fn with_nothing_set_upstreams_reach_public_addresses_only() {
        let config = ForwardConfig::read(&Env::of([])).unwrap();

        assert_eq!(config.upstream_networks, UpstreamNetworks::public_only());
        assert_eq!(config.discovery_refresh, Duration::from_secs(5));
        assert_eq!(config.dns_lookup_timeout, Duration::from_secs(3));
        assert_eq!(config.connections.connect_timeout, Duration::from_secs(5));
        assert_eq!(
            config.connections.response_deadline,
            Duration::from_secs(300)
        );
        assert_eq!(config.connections.long_lived_idle, Duration::from_secs(60));
        assert_eq!(config.connections.max_tunnels, 4096);
    }

    /// A zero response deadline is rejected with the deadline setting named.
    #[test]
    fn a_response_deadline_of_nothing_is_refused() {
        let read = ForwardConfig::read(&Env::of([("GATEWAY_RESPONSE_DEADLINE_SECONDS", "0")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_RESPONSE_DEADLINE_SECONDS")
        );
    }

    /// The configured private CIDRs become the forwarding allowance without discarding entries.
    #[test]
    fn internal_networks_listed_are_taken() {
        let config = ForwardConfig::read(&Env::of([(
            "UPSTREAM_NETWORKS",
            "10.0.0.0/8, 172.16.0.0/12",
        )]))
        .unwrap();

        assert_ne!(config.upstream_networks, UpstreamNetworks::public_only());
    }

    /// An upstream network that is no range is refused.
    #[test]
    fn an_upstream_network_that_is_no_range_is_refused() {
        let read = ForwardConfig::read(&Env::of([("UPSTREAM_NETWORKS", "10.0.0.0/8, 10.0.0.0")]));

        assert!(
            matches!(read, Err(ConfigError::Rejected { name, .. }) if name == "UPSTREAM_NETWORKS")
        );
    }

    /// A zero DNS lookup timeout is rejected with the lookup setting named.
    #[test]
    fn a_lookup_timeout_of_nothing_is_refused() {
        let read = ForwardConfig::read(&Env::of([("GATEWAY_DNS_LOOKUP_TIMEOUT_SECONDS", "0")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_DNS_LOOKUP_TIMEOUT_SECONDS")
        );
    }
}
