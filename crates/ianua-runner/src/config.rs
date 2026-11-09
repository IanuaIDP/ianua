//! Every setting the runner reads, read once from the environment and
//! checked together before anything starts.
//!
//! The runner acts for one agent. It holds no secret of the platform's: no
//! database login, no root and no sealing key, so a runner taken over gives
//! away the agent it serves and nothing else. Every setting is read through
//! [`Env`], each reader naming the variable it reads.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::logging::LoggingConfig;
use ianua_domain::domains::agents::runner::{GatewayAddress, GatewayTransport};
use ianua_domain::domains::crypto::signing_key::SigningAlgorithm;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{AgentId, Audience, DomainName, KeyId, Seconds};
use ianua_infra::http::{RunnerAgent, SvidFiles, TokenAsk};
use url::Url;

/// The secrets and logins a runner must never hold: none of them is the
/// agent's, and each would give whoever takes the runner far more than the
/// one agent it serves.
const PLATFORM_ONLY: [(&str, &str); 8] = [
    ("EVENT_SIGNING_SECRET", "is the control plane's root"),
    (
        "HMAC_SECRET",
        "is the root the platform's digests and seals are made from",
    ),
    ("ENCRYPTION_KEY", "seals every secret the platform keeps"),
    ("DATABASE_URL", "is the app's database login"),
    ("GATEWAY_DATABASE_URL", "is the data plane's database login"),
    ("MIGRATION_DATABASE_URL", "is the database owner's login"),
    (
        "AUDIT_PURGE_DATABASE_URL",
        "is the login that may remove audit records",
    ),
    ("CACHE_URL", "reaches the counters every gateway shares"),
];

/// How the runner proves it acts for its agent.
#[derive(Debug, Clone)]
pub enum Identity {
    /// Attest the runner's workload with its SPIFFE SVID and hold the key
    /// the platform enrols for it in memory only. The agent's attestation
    /// policy names the runner's SPIFFE ID, so nothing started any other
    /// way gets a token.
    Spiffe(SvidFiles),
    /// A key enrolled on the agent's credential and mounted into the
    /// runner, for clusters without SPIRE. Whoever holds the file can act
    /// as the agent from anywhere.
    Mounted {
        /// The key's id on the credential.
        kid: KeyId,
        /// The key's algorithm.
        algorithm: SigningAlgorithm,
        /// The key, PKCS#8 PEM.
        key: Secret,
    },
}

/// The internal authority the gateway's certificate chains to.
#[derive(Debug, Clone)]
pub(crate) struct GatewayAuthority {
    /// `RUNNER_GATEWAY_CA_FILE`: the authority's certificate.
    pub file: PathBuf,
    /// `RUNNER_GATEWAY_NAME`: the name the gateway's certificate is for,
    /// when `RUNNER_GATEWAY_URL` names it by address; none checks the
    /// address's own host.
    pub name: Option<DomainName>,
}

/// What one request and the runner as a whole may take on.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// `RUNNER_REQUEST_TIMEOUT_SECONDS` (60): the longest one request may
    /// take, its answer streamed to the end included.
    pub request: Duration,
    /// `RUNNER_CALL_TIMEOUT_SECONDS` (10): the longest an attestation or a
    /// token exchange may take.
    pub call: Duration,
    /// `RUNNER_HEADER_TIMEOUT_SECONDS` (10): how long the agent may take to
    /// send a request's head.
    pub header: Duration,
    /// `RUNNER_MAX_IN_FLIGHT` (64): the most requests in flight at once; one
    /// past it is answered busy.
    pub in_flight: usize,
    /// `RUNNER_MAX_CONNECTIONS` (128): the most connections held at once;
    /// one past it is closed.
    pub connections: usize,
    /// `RUNNER_SHUTDOWN_GRACE_SECONDS` (10): how long a stop waits for
    /// requests in flight.
    pub shutdown_grace: Duration,
}

/// Every setting the runner runs with.
#[derive(Debug, Clone)]
pub struct Config {
    /// `APP_ENV`.
    pub environment: Environment,
    /// What is logged and how.
    pub logging: LoggingConfig,
    /// `RUNNER_LISTEN` (`127.0.0.1:8480`): where the agent talks to the
    /// runner. In Kubernetes the runner listens on its pod's address and a
    /// network policy lets only its agent's pod connect.
    pub listen: SocketAddr,
    /// `RUNNER_AGENT_ID` and `RUNNER_API_URL`: the agent, and the tenant's
    /// agents collection on the platform's API.
    pub agent: RunnerAgent,
    /// `RUNNER_GATEWAY_URL`: where the gateway is reached, always over TLS
    /// in production.
    pub gateway_url: Url,
    /// `RUNNER_GATEWAY_CA_FILE` and `RUNNER_GATEWAY_NAME`: the internal
    /// authority the gateway's certificate chains to, and the name it is
    /// for; none checks it against the public roots.
    pub(crate) gateway_authority: Option<GatewayAuthority>,
    /// `RUNNER_UPSTREAM_HOST` and the scheme of `RUNNER_GATEWAY_URL`: the
    /// tenant's host the agent's requests name, and how the gateway is
    /// reached.
    pub gateway: GatewayAddress,
    /// `RUNNER_TOKEN_AUDIENCE`, `RUNNER_GRANTED` and
    /// `RUNNER_TOKEN_TTL_SECONDS` (600): what the runner asks for when it
    /// exchanges a task token.
    pub ask: TokenAsk,
    /// `RUNNER_IDENTITY` (`spiffe`): how the runner proves it acts for the
    /// agent.
    pub identity: Identity,
    /// What one request and the runner may take on.
    pub limits: Limits,
}

impl Config {
    /// Every setting `vars` holds, checked together.
    ///
    /// # Errors
    ///
    /// The first setting refused: a secret of the platform's, a setting
    /// missing or not of its kind, or plain HTTP in production.
    pub fn read(vars: &Env) -> Read<Self> {
        ensure_no_platform_secret(vars)?;
        let environment = Environment::read(vars)?;
        let plain = Plain::read(vars, environment)?;
        let gateway_url = address(vars, "RUNNER_GATEWAY_URL", plain.for_the_gateway())?;
        let gateway_authority = gateway_authority(vars, &gateway_url)?;
        let host = vars.required_parsed("RUNNER_UPSTREAM_HOST", DomainName::new)?;
        Ok(Self {
            logging: LoggingConfig::read(vars, environment)?,
            listen: vars
                .parsed("RUNNER_LISTEN", |text| text.parse::<SocketAddr>())?
                .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8480))),
            agent: RunnerAgent {
                agent: vars.required_parsed("RUNNER_AGENT_ID", |text| {
                    text.parse().map(AgentId::from_uuid)
                })?,
                agents_url: address(vars, "RUNNER_API_URL", plain)?,
            },
            gateway: GatewayAddress::new(host, transport_of(&gateway_url)),
            gateway_url,
            gateway_authority,
            ask: token_ask(vars)?,
            identity: identity(vars)?,
            limits: limits(vars)?,
            environment,
        })
    }
}

/// Reads the audience, granted rights and bounded lifetime of exchanged tokens.
fn token_ask(vars: &Env) -> Read<TokenAsk> {
    Ok(TokenAsk {
        audience: vars.required_parsed("RUNNER_TOKEN_AUDIENCE", Audience::new)?,
        granted: vars.required_parsed("RUNNER_GRANTED", |text| {
            serde_json::from_str::<serde_json::Value>(&text)
        })?,
        lifetime: Seconds::new(vars.number_in("RUNNER_TOKEN_TTL_SECONDS", 600, 60..=86_400)?),
    })
}

/// Whether the platform's addresses may be plain HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plain {
    /// Only `https`: production, unless told the traffic stays inside the
    /// cluster.
    Refused,
    /// In production with `RUNNER_PLAIN_HTTP=in_cluster`: the API may be
    /// reached in the clear inside the cluster, where a network policy
    /// lets only runners reach it. The gateway never is.
    InCluster,
    /// In development, where every address may be plain HTTP.
    Development,
}

impl Plain {
    /// `RUNNER_PLAIN_HTTP`: `refused`, the default in production, or
    /// `in_cluster`. Development takes plain HTTP whatever it says.
    fn read(vars: &Env, environment: Environment) -> Read<Self> {
        let asked = vars.choice(
            "RUNNER_PLAIN_HTTP",
            Self::Refused,
            &[("refused", Self::Refused), ("in_cluster", Self::InCluster)],
        )?;
        match environment {
            Environment::Production => Ok(asked),
            Environment::Development => Ok(Self::Development),
        }
    }

    /// What the gateway's address may be: in production always `https`,
    /// since every request sent there carries a key-bound token.
    fn for_the_gateway(self) -> Self {
        match self {
            Self::InCluster => Self::Refused,
            other => other,
        }
    }
}

/// The address `name` holds, which must be `https` unless `plain` takes
/// plain HTTP: the runner sends the agent's tokens to it.
fn address(vars: &Env, name: &str, plain: Plain) -> Read<Url> {
    let url = vars.url(name)?.ok_or_else(|| ConfigError::missing(name))?;
    if plain == Plain::Refused && url.scheme() != "https" {
        return Err(ConfigError::invalid(
            name,
            "must be an https URL in production, where only RUNNER_API_URL may stay in the clear inside the cluster with RUNNER_PLAIN_HTTP=in_cluster: the runner sends the agent's tokens to it",
        ));
    }
    Ok(url)
}

/// `RUNNER_GATEWAY_CA_FILE` with `RUNNER_GATEWAY_NAME`, refused beside a
/// gateway reached in the clear: an authority meant to check the gateway
/// and silently unused would leave its owner believing the link
/// protected. A name without the authority is refused too.
fn gateway_authority(vars: &Env, gateway_url: &Url) -> Read<Option<GatewayAuthority>> {
    let file = vars.path("RUNNER_GATEWAY_CA_FILE")?;
    let name = vars.parsed("RUNNER_GATEWAY_NAME", DomainName::new)?;
    let Some(file) = file else {
        return match name {
            Some(_) => Err(ConfigError::missing(
                "RUNNER_GATEWAY_CA_FILE, which RUNNER_GATEWAY_NAME is checked under,",
            )),
            None => Ok(None),
        };
    };
    if gateway_url.scheme() != "https" {
        return Err(ConfigError::contradicts(
            "RUNNER_GATEWAY_CA_FILE",
            "is set beside an http RUNNER_GATEWAY_URL, which no certificate protects",
        ));
    }
    Ok(Some(GatewayAuthority { file, name }))
}

/// How the gateway at `url` is reached.
fn transport_of(url: &Url) -> GatewayTransport {
    match url.scheme() {
        "https" => GatewayTransport::Tls,
        _ => GatewayTransport::Plain,
    }
}

/// `RUNNER_IDENTITY`: `spiffe`, the default, with `RUNNER_SVID_FILE` and
/// `RUNNER_SVID_KEY_FILE`; or `key`, with `RUNNER_KEY` (or
/// `RUNNER_KEY_FILE`), `RUNNER_KEY_ID` and `RUNNER_KEY_ALGORITHM`
/// (`EdDSA`).
fn identity(vars: &Env) -> Read<Identity> {
    let proof = vars.choice(
        "RUNNER_IDENTITY",
        Proof::Spiffe,
        &[("spiffe", Proof::Spiffe), ("key", Proof::MountedKey)],
    )?;
    match proof {
        Proof::Spiffe => Ok(Identity::Spiffe(SvidFiles {
            chain: required_path(vars, "RUNNER_SVID_FILE")?,
            key: required_path(vars, "RUNNER_SVID_KEY_FILE")?,
        })),
        Proof::MountedKey => Ok(Identity::Mounted {
            kid: vars.required_parsed("RUNNER_KEY_ID", KeyId::new)?,
            algorithm: vars.choice(
                "RUNNER_KEY_ALGORITHM",
                SigningAlgorithm::EdDsa,
                &[
                    ("eddsa", SigningAlgorithm::EdDsa),
                    ("es256", SigningAlgorithm::Es256),
                ],
            )?,
            key: vars.required_secret("RUNNER_KEY")?,
        }),
    }
}

/// The proof `RUNNER_IDENTITY` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proof {
    /// The workload's SPIFFE SVID.
    Spiffe,
    /// A key mounted into the runner.
    MountedKey,
}

/// The path `name` holds, which must be set.
fn required_path(vars: &Env, name: &str) -> Read<PathBuf> {
    vars.path(name)?.ok_or_else(|| ConfigError::missing(name))
}

/// What one request and the runner may take on.
fn limits(vars: &Env) -> Read<Limits> {
    Ok(Limits {
        request: vars.seconds("RUNNER_REQUEST_TIMEOUT_SECONDS", Duration::from_secs(60))?,
        call: vars.seconds("RUNNER_CALL_TIMEOUT_SECONDS", Duration::from_secs(10))?,
        header: vars.seconds("RUNNER_HEADER_TIMEOUT_SECONDS", Duration::from_secs(10))?,
        in_flight: vars.number_in("RUNNER_MAX_IN_FLIGHT", 64, 1..=10_000)?,
        connections: vars.number_in("RUNNER_MAX_CONNECTIONS", 128, 1..=10_000)?,
        shutdown_grace: vars.seconds("RUNNER_SHUTDOWN_GRACE_SECONDS", Duration::from_secs(10))?,
    })
}

/// Refuses any secret or login of the platform's, given in its variable or
/// as a file.
fn ensure_no_platform_secret(vars: &Env) -> Read<()> {
    for (name, why) in PLATFORM_ONLY {
        let file = format!("{name}_FILE");
        let held = vars.optional(name)?.is_some() || vars.optional(&file)?.is_some();
        if held {
            return Err(ConfigError::contradicts(
                name,
                format!("is set on the runner, which must never hold it: it {why}"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "0190a6f0-0000-7000-8000-000000000001";

    /// A complete environment for a runner attesting with SPIFFE, with
    /// `overrides` laid over it.
    fn vars(overrides: &[(&'static str, &'static str)]) -> Env {
        let mut pairs: Vec<(&str, &str)> = vec![
            ("RUNNER_AGENT_ID", AGENT),
            (
                "RUNNER_API_URL",
                "https://ianua.test/api/v1/organizations/o/tenants/t/agents",
            ),
            ("RUNNER_GATEWAY_URL", "https://zero.ianua.test"),
            ("RUNNER_UPSTREAM_HOST", "api.acme.test"),
            ("RUNNER_SVID_FILE", "/run/spiffe/svid.pem"),
            ("RUNNER_SVID_KEY_FILE", "/run/spiffe/svid_key.pem"),
            ("RUNNER_TOKEN_AUDIENCE", "https://ianua.test"),
            ("RUNNER_GRANTED", r#"{"http":["routing:view"]}"#),
        ];
        for &(name, value) in overrides {
            pairs.retain(|(kept, _)| *kept != name);
            pairs.push((name, value));
        }
        Env::of(pairs)
    }

    /// A complete environment reads with safe defaults: loopback, SPIFFE,
    /// ten-minute tokens, and the gateway reached over TLS.
    #[test]
    fn a_complete_environment_reads_with_safe_defaults() {
        let config = Config::read(&vars(&[])).unwrap();

        assert!(config.listen.ip().is_loopback());
        assert!(matches!(config.identity, Identity::Spiffe(_)));
        assert_eq!(config.ask.lifetime, Seconds::new(600));
        assert_eq!(config.limits.in_flight, 64);
        assert_eq!(
            config.gateway.proof_target("/reports"),
            "https://api.acme.test/reports"
        );
    }

    /// A mounted key is used only when asked for, with its id and key.
    #[test]
    fn a_mounted_key_is_used_only_when_asked_for() {
        let config = Config::read(&vars(&[
            ("RUNNER_IDENTITY", "key"),
            ("RUNNER_KEY", "-----BEGIN PRIVATE KEY-----"),
            ("RUNNER_KEY_ID", "k1"),
        ]))
        .unwrap();

        let Identity::Mounted { kid, algorithm, .. } = config.identity else {
            panic!("the runner holds a mounted key");
        };
        assert_eq!(kid.as_str(), "k1");
        assert_eq!(algorithm, SigningAlgorithm::EdDsa);
    }

    /// A production gateway URL using plain HTTP is refused by setting name.
    #[test]
    fn plain_http_is_refused_in_production() {
        let read = Config::read(&vars(&[("RUNNER_GATEWAY_URL", "http://zero.ianua.test")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "RUNNER_GATEWAY_URL")
        );
    }

    /// A production runner told its traffic stays inside the cluster may
    /// reach the API in the clear, and still reaches the gateway over TLS
    /// checked against the internal authority alone.
    #[test]
    fn plain_http_is_taken_for_the_api_in_the_cluster_when_asked_for() {
        let config = Config::read(&vars(&[
            ("RUNNER_PLAIN_HTTP", "in_cluster"),
            ("RUNNER_GATEWAY_URL", "https://ianua-zero-internal:8082"),
            ("RUNNER_GATEWAY_CA_FILE", "/run/ianua/internal/ca-cert.pem"),
            (
                "RUNNER_API_URL",
                "http://10.0.0.8:3000/api/v1/organizations/o/tenants/t/agents",
            ),
        ]))
        .unwrap();

        assert_eq!(config.agent.agents_url.scheme(), "http");
        assert_eq!(
            config.gateway.proof_target("/reports"),
            "https://api.acme.test/reports"
        );
        assert!(config.gateway_authority.is_some());
    }

    /// Permitting plain API traffic inside the cluster still refuses a
    /// production gateway URL using plain HTTP.
    #[test]
    fn the_gateway_is_never_reached_in_the_clear_in_production() {
        let read = Config::read(&vars(&[
            ("RUNNER_PLAIN_HTTP", "in_cluster"),
            ("RUNNER_GATEWAY_URL", "http://10.0.0.7:8082"),
        ]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "RUNNER_GATEWAY_URL")
        );
    }

    /// A gateway authority beside a plain HTTP URL is refused even in
    /// development, naming the unused authority setting.
    #[test]
    fn a_gateway_authority_beside_plain_http_is_refused() {
        let read = Config::read(&vars(&[
            ("APP_ENV", "development"),
            ("RUNNER_GATEWAY_URL", "http://127.0.0.1:8080"),
            ("RUNNER_GATEWAY_CA_FILE", "/run/ianua/internal/ca-cert.pem"),
        ]));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "RUNNER_GATEWAY_CA_FILE")
        );
    }

    /// A development runner may reach a gateway beside it in the clear, and
    /// its proofs then name the scheme the gateway sees.
    #[test]
    fn plain_http_is_taken_in_development() {
        let config = Config::read(&vars(&[
            ("APP_ENV", "development"),
            ("RUNNER_GATEWAY_URL", "http://127.0.0.1:8080"),
        ]))
        .unwrap();

        assert_eq!(
            config.gateway.proof_target("/reports"),
            "http://api.acme.test/reports"
        );
    }

    /// Platform roots, sealing keys and gateway database credentials are
    /// refused in runner configuration, with each setting named.
    #[test]
    fn a_platform_secret_is_refused() {
        for name in ["HMAC_SECRET", "ENCRYPTION_KEY", "GATEWAY_DATABASE_URL"] {
            let read = Config::read(&vars(&[(name, "anything")]));

            assert!(
                matches!(read, Err(ConfigError::Contradicts { name: refused, .. }) if refused == name),
                "{name}"
            );
        }
    }

    /// A missing or malformed setting is refused, naming it.
    #[test]
    fn a_missing_or_malformed_setting_is_named() {
        let missing = Config::read(&vars(&[("RUNNER_SVID_FILE", "")])).unwrap_err();
        let malformed = Config::read(&vars(&[("RUNNER_MAX_IN_FLIGHT", "0")])).unwrap_err();
        let unread = Config::read(&vars(&[("RUNNER_LISTEN", "nowhere")])).unwrap_err();

        assert!(missing.to_string().contains("RUNNER_SVID_FILE"));
        assert!(malformed.to_string().contains("RUNNER_MAX_IN_FLIGHT"));
        assert!(unread.to_string().contains("RUNNER_LISTEN"));
    }
}
