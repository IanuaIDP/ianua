//! What one request and the gateway as a whole may take on: how much of a
//! body each stage reads, the largest body taken, how many connections and
//! headers, how long the checks and the shared counters may take, and how
//! long an upgraded connection stays open.
//!
//! Every read of a body is a prefix held in memory, so each cap is bounded
//! here, before anything starts.

use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_domain::domains::proxy::request::body::{BodyReadSettings, ByteCap};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// The most of a body any one stage holds in memory.
const LARGEST_READ: u64 = 16 * MIB;

/// How much of a response the stages that look at one read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponseReads {
    /// `GATEWAY_CANARY_SCAN_MAX_BYTES` (65536): how much of a response is
    /// scanned for a leaked canary token. A longer answer on a route that
    /// scans is withheld, since its rest could carry one.
    pub canary_scan: ByteCap,
    /// `GATEWAY_RESPONSE_STAGE_MAX_BYTES` (65536): how much of a response
    /// the other response stages read: redaction, transforms, signing,
    /// token charges and the cache. The gateway reads an answer up to the
    /// larger of the two caps the route's stages ask for and refuses a
    /// longer one; a route with no response stage streams any length.
    pub response_stages: ByteCap,
}

/// Bounds each stored response and the number retained before new entries are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResponseCache {
    /// `GATEWAY_CACHE_MAX_BODY_BYTES` (1048576): the largest response
    /// stored.
    pub largest_body: ByteCap,
    /// `GATEWAY_CACHE_MAX_ENTRIES` (50000): responses held at once. Past it
    /// nothing is stored, and nothing held is pushed out.
    pub entries: usize,
}

/// How many connections the gateway serves at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectionPermits {
    /// `GATEWAY_MAX_CONNECTIONS` (10000): connections on the main listener;
    /// more wait.
    pub connections: usize,
    /// `GATEWAY_STREAM_MAX_CONNECTIONS` (512): connections each TCP stream
    /// route carries.
    pub per_stream_route: usize,
}

impl ConnectionPermits {
    /// Reads bounded connection counts for the main listener and each stream route.
    fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            connections: vars.number_in("GATEWAY_MAX_CONNECTIONS", 10_000, 1..=1_000_000)?,
            per_stream_route: vars.number_in("GATEWAY_STREAM_MAX_CONNECTIONS", 512, 1..=100_000)?,
        })
    }
}

/// How long an upgraded connection, such as a WebSocket, stays open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TunnelLimits {
    /// `GATEWAY_TUNNEL_MAX_LIFETIME_SECONDS` (3600): the longest it stays
    /// open.
    pub lifetime: Duration,
    /// `GATEWAY_TUNNEL_IDLE_SECONDS` (300): how long it may carry nothing.
    pub idle: Duration,
}

impl TunnelLimits {
    /// Reads the total and idle deadlines applied to upgraded connections.
    fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            lifetime: vars.seconds_in(
                "GATEWAY_TUNNEL_MAX_LIFETIME_SECONDS",
                Duration::from_secs(3600),
                1..=86_400,
            )?,
            idle: vars.seconds_in(
                "GATEWAY_TUNNEL_IDLE_SECONDS",
                Duration::from_secs(300),
                1..=86_400,
            )?,
        })
    }
}

/// What one request and the gateway as a whole may take on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LimitsConfig {
    /// `GATEWAY_DEFAULT_MAX_BODY_BYTES` (10485760),
    /// `GATEWAY_WAF_BODY_SCAN_MAX_BYTES` (65536),
    /// `GATEWAY_REQUEST_SIGN_MAX_BYTES` (65536),
    /// `GATEWAY_MCP_BODY_MAX_BYTES` (262144),
    /// `GATEWAY_GRAPHQL_BODY_MAX_BYTES` (262144) and
    /// `GATEWAY_PARAMETER_RULES_MAX_BYTES` (262144).
    pub request_bodies: BodyReadSettings,
    /// How much of a response is read.
    pub response_reads: ResponseReads,
    /// Storage limits applied when responses are admitted to the local cache.
    pub response_cache: ResponseCache,
    /// How many connections are served at once.
    pub permits: ConnectionPermits,
    /// `GATEWAY_MAX_HEADERS` (100): headers one request may carry.
    pub max_headers: usize,
    /// `GATEWAY_PIPELINE_TIMEOUT_MS` (10000): the longest the checks may
    /// run on one request before it is refused.
    pub pipeline_timeout: Duration,
    /// `GATEWAY_COUNTER_TIMEOUT_MS` (250): the longest one request waits on
    /// a shared counter (rate limits, budgets, DPoP replay) before it is
    /// refused.
    pub counter_timeout: Duration,
    /// How long an upgraded connection stays open.
    pub tunnels: TunnelLimits,
}

impl LimitsConfig {
    /// The limits `vars` holds.
    ///
    /// # Errors
    ///
    /// A number that does not read or lies out of its range, a body cap of
    /// nothing, or a counter wait as long as the whole check.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        let config = Self {
            request_bodies: request_bodies(vars)?,
            response_reads: ResponseReads {
                canary_scan: read_cap(vars, "GATEWAY_CANARY_SCAN_MAX_BYTES", 64 * KIB)?,
                response_stages: read_cap(vars, "GATEWAY_RESPONSE_STAGE_MAX_BYTES", 64 * KIB)?,
            },
            response_cache: ResponseCache {
                largest_body: read_cap(vars, "GATEWAY_CACHE_MAX_BODY_BYTES", MIB)?,
                entries: vars.number_in("GATEWAY_CACHE_MAX_ENTRIES", 50_000, 1..=10_000_000)?,
            },
            permits: ConnectionPermits::read(vars)?,
            max_headers: vars.number_in("GATEWAY_MAX_HEADERS", 100, 1..=1000)?,
            pipeline_timeout: vars.millis_in(
                "GATEWAY_PIPELINE_TIMEOUT_MS",
                Duration::from_secs(10),
                1..=300_000,
            )?,
            counter_timeout: vars.millis_in(
                "GATEWAY_COUNTER_TIMEOUT_MS",
                Duration::from_millis(250),
                1..=5000,
            )?,
            tunnels: TunnelLimits::read(vars)?,
        };
        config.ensure_counter_within_pipeline()?;
        Ok(config)
    }

    /// Refuses a counter wait no shorter than the whole check: a slow
    /// counter would then end every request at the check's timeout instead
    /// of its own.
    fn ensure_counter_within_pipeline(&self) -> Read<()> {
        if self.counter_timeout < self.pipeline_timeout {
            return Ok(());
        }
        Err(ConfigError::contradicts(
            "GATEWAY_COUNTER_TIMEOUT_MS",
            "is not shorter than GATEWAY_PIPELINE_TIMEOUT_MS",
        ))
    }
}

/// How much of a request body each reader reads, and the largest body taken
/// where no stage sets one.
fn request_bodies(vars: &Env) -> Read<BodyReadSettings> {
    Ok(BodyReadSettings {
        default_limit: byte_cap(vars, "GATEWAY_DEFAULT_MAX_BODY_BYTES", 10 * MIB, 16 * GIB)?,
        waf: read_cap(vars, "GATEWAY_WAF_BODY_SCAN_MAX_BYTES", 64 * KIB)?,
        request_sign: read_cap(vars, "GATEWAY_REQUEST_SIGN_MAX_BYTES", 64 * KIB)?,
        mcp: read_cap(vars, "GATEWAY_MCP_BODY_MAX_BYTES", 256 * KIB)?,
        graphql: read_cap(vars, "GATEWAY_GRAPHQL_BODY_MAX_BYTES", 256 * KIB)?,
        parameter_rules: read_cap(vars, "GATEWAY_PARAMETER_RULES_MAX_BYTES", 256 * KIB)?,
    })
}

/// The cap on a read held in memory that `name` sets, from one byte to
/// [`LARGEST_READ`], or `default`.
fn read_cap(vars: &Env, name: &str, default: u64) -> Read<ByteCap> {
    byte_cap(vars, name, default, LARGEST_READ)
}

/// The cap `name` sets, from one byte to `most`, or `default`.
fn byte_cap(vars: &Env, name: &str, default: u64, most: u64) -> Read<ByteCap> {
    let bytes = vars.number_in(name, default, 1..=most)?;
    ByteCap::new(bytes).map_err(|cause| ConfigError::rejected(name, cause))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::proxy::request::body::BodyReader;

    use super::*;

    /// With nothing set, the documented caps and permits hold.
    #[test]
    fn with_nothing_set_the_documented_defaults_hold() {
        let config = LimitsConfig::read(&Env::of([])).unwrap();

        let bodies = config.request_bodies;
        assert_eq!(bodies.default_limit.get(), 10 * MIB);
        assert_eq!(bodies.cap_for(BodyReader::Waf).get(), 64 * KIB);
        assert_eq!(bodies.cap_for(BodyReader::RequestSign).get(), 64 * KIB);
        assert_eq!(bodies.cap_for(BodyReader::Mcp).get(), 256 * KIB);
        assert_eq!(bodies.cap_for(BodyReader::GraphQl).get(), 256 * KIB);
        assert_eq!(bodies.cap_for(BodyReader::ParameterRules).get(), 256 * KIB);
        assert_eq!(config.response_reads.canary_scan.get(), 64 * KIB);
        assert_eq!(config.response_reads.response_stages.get(), 64 * KIB);
        assert_eq!(config.response_cache.largest_body.get(), MIB);
        assert_eq!(config.response_cache.entries, 50_000);
        assert_eq!(config.permits.connections, 10_000);
        assert_eq!(config.permits.per_stream_route, 512);
        assert_eq!(config.max_headers, 100);
        assert_eq!(config.pipeline_timeout, Duration::from_secs(10));
        assert_eq!(config.counter_timeout, Duration::from_millis(250));
        assert_eq!(config.tunnels.lifetime, Duration::from_secs(3600));
        assert_eq!(config.tunnels.idle, Duration::from_secs(300));
    }

    /// Each reader's cap is read from its own setting.
    #[test]
    fn each_reader_takes_its_own_setting() {
        let vars = Env::of([
            ("GATEWAY_WAF_BODY_SCAN_MAX_BYTES", "1000"),
            ("GATEWAY_PARAMETER_RULES_MAX_BYTES", "2000"),
        ]);

        let bodies = LimitsConfig::read(&vars).unwrap().request_bodies;

        assert_eq!(bodies.cap_for(BodyReader::Waf).get(), 1000);
        assert_eq!(bodies.cap_for(BodyReader::ParameterRules).get(), 2000);
    }

    /// A zero WAF body scan cap is rejected with the scan setting named.
    #[test]
    fn a_body_cap_of_nothing_is_refused() {
        let read = LimitsConfig::read(&Env::of([("GATEWAY_WAF_BODY_SCAN_MAX_BYTES", "0")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_WAF_BODY_SCAN_MAX_BYTES")
        );
    }

    /// A one-gigabyte MCP read exceeds the 16 MiB ceiling and is rejected.
    #[test]
    fn a_read_past_sixteen_mebibytes_is_refused() {
        let read = LimitsConfig::read(&Env::of([("GATEWAY_MCP_BODY_MAX_BYTES", "1073741824")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_MCP_BODY_MAX_BYTES")
        );
    }

    /// The largest body taken may be far larger than any read, since it
    /// streams.
    #[test]
    fn the_largest_body_may_exceed_any_read() {
        let config =
            LimitsConfig::read(&Env::of([("GATEWAY_DEFAULT_MAX_BODY_BYTES", "1073741824")]))
                .unwrap();

        assert_eq!(config.request_bodies.default_limit.get(), GIB);
    }

    /// Zero connection permits are rejected with the connection setting named.
    #[test]
    fn no_connection_permits_are_refused() {
        let read = LimitsConfig::read(&Env::of([("GATEWAY_MAX_CONNECTIONS", "0")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_MAX_CONNECTIONS")
        );
    }

    /// A counter timeout equal to the whole pipeline timeout is rejected as contradictory.
    #[test]
    fn a_counter_wait_as_long_as_the_check_is_refused() {
        let vars = Env::of([
            ("GATEWAY_PIPELINE_TIMEOUT_MS", "500"),
            ("GATEWAY_COUNTER_TIMEOUT_MS", "500"),
        ]);

        let read = LimitsConfig::read(&vars);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_COUNTER_TIMEOUT_MS")
        );
    }

    /// A zero tunnel lifetime is rejected while reading the gateway limits.
    #[test]
    fn a_tunnel_lifetime_of_nothing_is_refused() {
        let read = LimitsConfig::read(&Env::of([("GATEWAY_TUNNEL_MAX_LIFETIME_SECONDS", "0")]));

        assert!(read.is_err());
    }
}
