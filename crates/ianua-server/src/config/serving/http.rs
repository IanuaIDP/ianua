//! The listeners and what they take on, whom they believe, how long a stop
//! waits, and how long calls out of the deployment may take.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use ianua_api::state::http::{ApiDocs, ListenerLimits};
use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::request::forwarded::TrustedProxies;
use ianua_domain::shared::security::ssrf::UpstreamNetworks;

use super::integrations::data_ceiling;

/// The listeners and the calls out.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// `HOST` (`0.0.0.0`) and `PORT` (3000): the public API.
    pub public: SocketAddr,
    /// `HOST` and `INTERNAL_PORT` (3001): the internal listener, for the
    /// gateway's app sign-in relay, the metrics and the health checks.
    pub internal: SocketAddr,
    /// `API_MAX_CONCURRENCY` (500), `API_MAX_BODY_BYTES` (1048576) and
    /// `API_REQUEST_TIMEOUT_SECONDS` (30).
    pub public_limits: ListenerLimits,
    /// `INTERNAL_MAX_CONCURRENCY` (200), `INTERNAL_MAX_BODY_BYTES` (16384)
    /// and `INTERNAL_REQUEST_TIMEOUT_SECONDS` (15).
    pub internal_limits: ListenerLimits,
    /// `TRUSTED_PROXIES`: the proxies whose `X-Forwarded-For` is believed;
    /// empty trusts nobody.
    pub trusted_proxies: TrustedProxies,
    /// `CORS_ORIGIN`: the one browser origin that may call the API, `*`
    /// for any without credentials; unset allows none.
    pub cors_origin: Option<String>,
    /// `ENABLE_API_DOCS` (off): whether the OpenAPI docs are served.
    pub api_docs: ApiDocs,
    /// `UPSTREAM_NETWORKS`: the internal networks routes, identity
    /// providers and other addresses tenants chose may reach, beside
    /// public addresses. The gateway reads the same setting.
    pub upstream_networks: UpstreamNetworks,
    /// `SHUTDOWN_GRACE_SECONDS` (30): how long a stop waits for requests
    /// and jobs in flight.
    pub shutdown_grace: Duration,
    /// `WS_MAX_STREAMS_PER_OWNER` (32): live streams one person may hold
    /// open on a node.
    pub streams_per_owner: usize,
    /// `STREAM_RECHECK_SECONDS` (30): how often a live stream asks again
    /// whether its caller may still read it.
    pub stream_recheck: Duration,
    /// `STREAM_LIFETIME_SECONDS` (1800): the longest a live stream stays
    /// open before its client connects again.
    pub stream_lifetime: Duration,
    /// `CREDENTIAL_USE_INTERVAL_SECONDS` (60): how often a credential's
    /// last use is written down, at most. A tenant key's new country is
    /// written at once, whatever this says.
    pub credential_use_interval: Duration,
    /// `OUTBOUND_DELIVERY_TIMEOUT_SECONDS` (10): one webhook try, signal
    /// push, audit stream post or log shipment.
    pub delivery_timeout: Duration,
    /// `OIDC_PROVIDER_TIMEOUT_SECONDS` (10): one call to an identity
    /// provider.
    pub oidc_timeout: Duration,
    /// `OIDC_PROVIDER_CA_FILE`: a private PEM authority to trust instead of
    /// public roots for OIDC discovery, keys and token exchanges.
    pub oidc_authority: Option<PathBuf>,
    /// `SAML_METADATA_CA_FILE`: a private PEM authority to trust instead of
    /// public roots for SAML providers' metadata addresses.
    pub saml_metadata_authority: Option<PathBuf>,
    /// `OUTBOUND_DELIVERY_CA_FILE`: a PEM authority trusted beside the
    /// public roots for webhooks, signal pushes, audit streams, message
    /// pushes, notification destinations and integrations, with names
    /// looked up through `DNS_RESOLVERS`. Refused in production.
    pub delivery_authority: Option<PathBuf>,
    /// `GEOIP_DB_PATH`: the MaxMind City database for sign-in risk by
    /// country; none reads no country.
    pub geoip_database: Option<PathBuf>,
    /// A workflow's HTTP request step.
    pub(crate) workflow_requests: WorkflowRequests,
}

/// What a workflow's HTTP request step may do.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WorkflowRequests {
    /// `WORKFLOW_HTTP_TIMEOUT_SECONDS` (10): one call.
    pub timeout: Duration,
    /// `WORKFLOW_HTTP_MAX_ANSWER_BYTES` (349000, at most that): the most of
    /// an answer read, so its text fits in the workflow's data.
    pub most_answer: usize,
    /// `WORKFLOW_HTTP_DATA_CEILING` (`internal`): the most sensitive data a
    /// step may send, `public`, `internal`, `confidential` or `restricted`;
    /// an answer counts as that sensitive, since it may echo what it was
    /// sent.
    pub ceiling: DataClassLevel,
}

impl HttpConfig {
    /// The listener settings `vars` holds.
    ///
    /// # Errors
    ///
    /// A setting that does not read, a trusted proxy or upstream network
    /// that is no address or range, or a CORS origin that is no origin.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        let addresses = ListenerAddresses::read(vars)?;
        Ok(Self {
            public: addresses.public,
            internal: addresses.internal,
            public_limits: listener_limits(vars, ListenerKind::Public)?,
            internal_limits: listener_limits(vars, ListenerKind::Internal)?,
            trusted_proxies: vars.peers("TRUSTED_PROXIES")?,
            cors_origin: cors_origin(vars)?,
            api_docs: api_docs(vars)?,
            upstream_networks: vars.networks("UPSTREAM_NETWORKS")?,
            shutdown_grace: vars.seconds("SHUTDOWN_GRACE_SECONDS", Duration::from_secs(30))?,
            streams_per_owner: vars.number_in("WS_MAX_STREAMS_PER_OWNER", 32, 1..=10_000)?,
            stream_recheck: vars.seconds("STREAM_RECHECK_SECONDS", Duration::from_secs(30))?,
            stream_lifetime: vars
                .seconds("STREAM_LIFETIME_SECONDS", Duration::from_secs(30 * 60))?,
            credential_use_interval: vars
                .seconds("CREDENTIAL_USE_INTERVAL_SECONDS", Duration::from_secs(60))?,
            delivery_timeout: vars
                .seconds("OUTBOUND_DELIVERY_TIMEOUT_SECONDS", Duration::from_secs(10))?,
            oidc_timeout: vars.seconds("OIDC_PROVIDER_TIMEOUT_SECONDS", Duration::from_secs(10))?,
            oidc_authority: vars.path("OIDC_PROVIDER_CA_FILE")?,
            saml_metadata_authority: vars.path("SAML_METADATA_CA_FILE")?,
            delivery_authority: delivery_authority(vars)?,
            geoip_database: vars.path("GEOIP_DB_PATH")?,
            workflow_requests: workflow_requests(vars)?,
        })
    }
}

/// The sockets checked together before either listener starts.
struct ListenerAddresses {
    public: SocketAddr,
    internal: SocketAddr,
}

impl ListenerAddresses {
    /// Reads a numeric host and refuses two listeners on the same fixed port.
    fn read(vars: &Env) -> Read<Self> {
        let host = vars
            .parsed("HOST", |host| host.parse::<IpAddr>())?
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let port = vars.number("PORT", 3000_u16)?;
        let internal_port = vars.number("INTERNAL_PORT", 3001_u16)?;
        if port == internal_port && port != 0 {
            return Err(ConfigError::contradicts(
                "INTERNAL_PORT",
                "is the same port as PORT",
            ));
        }
        Ok(Self {
            public: SocketAddr::new(host, port),
            internal: SocketAddr::new(host, internal_port),
        })
    }
}

/// Selects the setting names and defaults for one HTTP listener.
#[derive(Clone, Copy)]
enum ListenerKind {
    Public,
    Internal,
}

/// Reads the concurrency, body and timeout limits for one listener.
fn listener_limits(vars: &Env, kind: ListenerKind) -> Read<ListenerLimits> {
    let (prefix, concurrency, body_bytes, seconds) = match kind {
        ListenerKind::Public => ("API", 500, 1024 * 1024, 30),
        ListenerKind::Internal => ("INTERNAL", 200, 16 * 1024, 15),
    };
    Ok(ListenerLimits {
        max_concurrency: vars.number_in(
            &format!("{prefix}_MAX_CONCURRENCY"),
            concurrency,
            1..=100_000,
        )?,
        max_body_bytes: vars.number_in(
            &format!("{prefix}_MAX_BODY_BYTES"),
            body_bytes,
            1..=1024 * 1024 * 1024,
        )?,
        timeout: vars.seconds(
            &format!("{prefix}_REQUEST_TIMEOUT_SECONDS"),
            Duration::from_secs(seconds),
        )?,
    })
}

/// The workflow HTTP request step's settings.
fn workflow_requests(vars: &Env) -> Read<WorkflowRequests> {
    Ok(WorkflowRequests {
        timeout: vars.seconds("WORKFLOW_HTTP_TIMEOUT_SECONDS", Duration::from_secs(10))?,
        most_answer: vars.number_in("WORKFLOW_HTTP_MAX_ANSWER_BYTES", 349_000, 1..=349_000)?,
        ceiling: data_ceiling(vars, "WORKFLOW_HTTP_DATA_CEILING")?,
    })
}

/// `CORS_ORIGIN`: `*`, or one origin with no path.
fn cors_origin(vars: &Env) -> Read<Option<String>> {
    let name = "CORS_ORIGIN";
    let Some(value) = vars.optional(name)? else {
        return Ok(None);
    };
    if value == "*" {
        return Ok(Some(value));
    }
    let origin = url::Url::parse(&value)
        .ok()
        .filter(|url| {
            matches!(url.scheme(), "http" | "https") && url.path() == "/" && url.query().is_none()
        })
        .map(|url| url.origin().ascii_serialization())
        .ok_or_else(|| {
            ConfigError::invalid(
                name,
                format!("must be * or an origin such as https://app.example.com, got {value:?}"),
            )
        })?;
    Ok(Some(origin))
}

fn api_docs(vars: &Env) -> Read<ApiDocs> {
    let served = vars.flag("ENABLE_API_DOCS", false)?;
    Ok(if served {
        ApiDocs::Served
    } else {
        ApiDocs::Hidden
    })
}

/// `OUTBOUND_DELIVERY_CA_FILE`: an authority trusted beside the public
/// roots for outgoing deliveries, so a test deployment can prove what an
/// outside receiver gets. Refused in production, where a certificate of
/// a private authority must never pass for a tenant's webhook endpoint.
fn delivery_authority(vars: &Env) -> Read<Option<PathBuf>> {
    let name = "OUTBOUND_DELIVERY_CA_FILE";
    let path = vars.path(name)?;
    if path.is_some() && Environment::read(vars)?.is_production() {
        return Err(ConfigError::contradicts(
            name,
            "is set, and it lets deliveries trust a private authority, which only a test deployment may do",
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Left unset, no authority beside the public roots is held and nothing
    /// about outgoing deliveries changes.
    #[test]
    fn an_unset_delivery_authority_is_none() {
        let config = HttpConfig::read(&Env::of([])).unwrap();

        assert!(config.delivery_authority.is_none());
    }

    /// A deployment in development names the extra authority it trusts.
    #[test]
    fn a_development_deployment_may_name_a_delivery_authority() {
        let vars = Env::of([
            ("APP_ENV", "development"),
            ("OUTBOUND_DELIVERY_CA_FILE", "/run/ianua/test-authority.pem"),
        ]);

        let config = HttpConfig::read(&vars).unwrap();

        assert_eq!(
            config.delivery_authority.as_deref(),
            Some(std::path::Path::new("/run/ianua/test-authority.pem"))
        );
    }

    /// Production refuses an extra delivery authority by name.
    #[test]
    fn a_delivery_authority_in_production_is_refused() {
        let vars = Env::of([("OUTBOUND_DELIVERY_CA_FILE", "/run/ianua/test-authority.pem")]);

        let read = HttpConfig::read(&vars);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "OUTBOUND_DELIVERY_CA_FILE")
        );
    }

    /// With nothing set, the listeners take the documented addresses and
    /// limits, trust no proxy, and reach public addresses only.
    #[test]
    fn with_nothing_set_the_documented_defaults_hold() {
        let config = HttpConfig::read(&Env::of([])).unwrap();

        assert_eq!(config.public.to_string(), "0.0.0.0:3000");
        assert_eq!(config.internal.to_string(), "0.0.0.0:3001");
        assert_eq!(config.public_limits.max_body_bytes, 1024 * 1024);
        assert!(config.trusted_proxies.is_empty());
        assert_eq!(config.upstream_networks, UpstreamNetworks::public_only());
        assert_eq!(config.api_docs, ApiDocs::Hidden);
    }

    /// A trusted proxy list containing a malformed network is refused,
    /// naming the trusted proxy setting.
    #[test]
    fn a_trusted_proxy_that_is_no_address_is_refused() {
        let read = HttpConfig::read(&Env::of([("TRUSTED_PROXIES", "10.0.0.0/8, 10.0.0/8")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "TRUSTED_PROXIES")
        );
    }

    /// Trusted proxies take addresses and CIDR blocks.
    #[test]
    fn trusted_proxies_take_addresses_and_blocks() {
        let config =
            HttpConfig::read(&Env::of([("TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.1")])).unwrap();

        assert!(config.trusted_proxies.contains("10.1.2.3".parse().unwrap()));
        assert!(
            config
                .trusted_proxies
                .contains("192.168.1.1".parse().unwrap())
        );
    }

    /// An upstream network that is no range is refused.
    #[test]
    fn an_upstream_network_that_is_no_range_is_refused() {
        let read = HttpConfig::read(&Env::of([("UPSTREAM_NETWORKS", "10.0.0.0/8, 10.0.0.0")]));

        assert!(
            matches!(read, Err(ConfigError::Rejected { name, .. }) if name == "UPSTREAM_NETWORKS")
        );
    }

    /// A CORS origin is kept as an origin, and anything else is refused.
    #[test]
    fn a_cors_origin_must_be_an_origin() {
        let good =
            HttpConfig::read(&Env::of([("CORS_ORIGIN", "https://app.example.com")])).unwrap();
        let path = HttpConfig::read(&Env::of([(
            "CORS_ORIGIN",
            "https://app.example.com/dashboard",
        )]));

        assert_eq!(good.cors_origin.as_deref(), Some("https://app.example.com"));
        assert!(path.is_err());
    }

    /// The internal listener cannot use the public listener's port;
    /// configuration names the conflicting internal port setting.
    #[test]
    fn the_internal_listener_on_the_public_port_is_refused() {
        let read = HttpConfig::read(&Env::of([("PORT", "8080"), ("INTERNAL_PORT", "8080")]));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "INTERNAL_PORT")
        );
    }

    /// A hostname is refused as the listener host because binding requires
    /// a numeric address.
    #[test]
    fn a_host_that_is_no_address_is_refused() {
        assert!(HttpConfig::read(&Env::of([("HOST", "localhost")])).is_err());
    }
}
