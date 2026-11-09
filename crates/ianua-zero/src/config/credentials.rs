//! How the gateway checks the credentials requests present: how long a
//! rotated-out signing key is still believed, how the keys a consumer's
//! own issuer publishes are fetched and kept, and the device service asked
//! for a device's posture.

use std::fmt;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::Lifetime;
use url::Url;

/// The day a rotated-out key is believed by default.
const DAY: Duration = Duration::from_secs(86_400);

/// How the keys a consumer's own token issuer publishes are fetched and
/// kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsumerIssuerKeys {
    /// `GATEWAY_CONSUMER_KEYS_TTL_SECONDS` (600): how long a fetched key
    /// set is used before it is fetched again.
    pub keep_for: Duration,
    /// `GATEWAY_CONSUMER_KEYS_RENEW_SECONDS` (60): the shortest time between
    /// two fetches of one issuer's keys, even for a token naming a key the
    /// kept set lacks.
    pub renew_after: Duration,
    /// `GATEWAY_CONSUMER_KEYS_TIMEOUT_SECONDS` (5): one fetch.
    pub timeout: Duration,
}

/// The device service a route's device posture is asked of. `Debug` shows
/// no token.
#[derive(Clone)]
pub(crate) struct PostureService {
    /// `DEVICE_POSTURE_URL`: where a device's posture is asked.
    pub endpoint: Url,
    /// `DEVICE_POSTURE_TOKEN`: the bearer token the gateway asks under.
    pub token: Secret,
    /// `DEVICE_POSTURE_TIMEOUT_MS` (2000): one question, two seconds at
    /// most.
    pub timeout: Duration,
}

impl fmt::Debug for PostureService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostureService")
            .field("endpoint", &self.endpoint.as_str())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// How the gateway checks presented credentials.
#[derive(Debug, Clone)]
pub(crate) struct CredentialsConfig {
    /// `JWKS_ROTATION_GRACE_SECONDS` (86400): how long a token signed with a
    /// key rotated out is still believed. The server reads the same
    /// setting, with the same value.
    pub key_grace: Lifetime,
    /// How consumers' issuers' keys are fetched and kept.
    pub consumer_issuer_keys: ConsumerIssuerKeys,
    /// The device service, when `DEVICE_POSTURE_URL` is set. Without it a
    /// route asking for a device's posture is answered unavailable.
    pub posture: Option<PostureService>,
}

impl CredentialsConfig {
    /// The credential settings `vars` holds, in `environment`.
    ///
    /// # Errors
    ///
    /// A time out of its range, a device service address that is no URL or
    /// plain HTTP in production, or an address and token not given
    /// together.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        let grace = vars.seconds_in("JWKS_ROTATION_GRACE_SECONDS", DAY, 1..=30 * 86_400)?;
        Ok(Self {
            key_grace: lifetime("JWKS_ROTATION_GRACE_SECONDS", grace)?,
            consumer_issuer_keys: consumer_issuer_keys(vars)?,
            posture: posture(vars, environment)?,
        })
    }
}

/// `duration` as the lifetime the domain counts in, for `name`.
fn lifetime(name: &str, duration: Duration) -> Read<Lifetime> {
    let span =
        time::Duration::try_from(duration).map_err(|cause| ConfigError::rejected(name, cause))?;
    Lifetime::new(span).map_err(|cause| ConfigError::rejected(name, cause))
}

/// How consumers' issuers' keys are fetched and kept.
fn consumer_issuer_keys(vars: &Env) -> Read<ConsumerIssuerKeys> {
    Ok(ConsumerIssuerKeys {
        keep_for: vars.seconds_in(
            "GATEWAY_CONSUMER_KEYS_TTL_SECONDS",
            Duration::from_secs(600),
            1..=86_400,
        )?,
        renew_after: vars.seconds_in(
            "GATEWAY_CONSUMER_KEYS_RENEW_SECONDS",
            Duration::from_secs(60),
            1..=3600,
        )?,
        timeout: vars.seconds_in(
            "GATEWAY_CONSUMER_KEYS_TIMEOUT_SECONDS",
            Duration::from_secs(5),
            1..=30,
        )?,
    })
}

/// The device service, when its address and token are both set.
fn posture(vars: &Env, environment: Environment) -> Read<Option<PostureService>> {
    let address = vars.url("DEVICE_POSTURE_URL")?;
    let token = vars.secret("DEVICE_POSTURE_TOKEN")?;
    let timeout = vars.millis_in(
        "DEVICE_POSTURE_TIMEOUT_MS",
        Duration::from_secs(2),
        1..=2000,
    )?;
    match (address, token) {
        (Some(endpoint), Some(token)) => {
            ensure_sealed_in_production(&endpoint, environment)?;
            Ok(Some(PostureService {
                endpoint,
                token,
                timeout,
            }))
        }
        (Some(_), None) => Err(ConfigError::missing(
            "DEVICE_POSTURE_TOKEN or DEVICE_POSTURE_TOKEN_FILE, which DEVICE_POSTURE_URL needs,",
        )),
        (None, Some(_)) => Err(ConfigError::contradicts(
            "DEVICE_POSTURE_TOKEN",
            "is set without DEVICE_POSTURE_URL",
        )),
        (None, None) => Ok(None),
    }
}

/// Refuses a device service over plain HTTP in production: the token
/// travels with every question.
fn ensure_sealed_in_production(endpoint: &Url, environment: Environment) -> Read<()> {
    if environment.is_production() && endpoint.scheme() != "https" {
        return Err(ConfigError::invalid(
            "DEVICE_POSTURE_URL",
            "must be https in production, since the token is sent with every question",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use Environment::{Development, Production};

    use super::*;

    /// With nothing set, a rotated-out key is believed for a day, consumer
    /// keys are kept ten minutes, and no device service is asked.
    #[test]
    fn with_nothing_set_the_documented_defaults_hold() {
        let config = CredentialsConfig::read(&Env::of([]), Production).unwrap();

        assert_eq!(config.key_grace.duration(), time::Duration::days(1));
        assert_eq!(
            config.consumer_issuer_keys.keep_for,
            Duration::from_secs(600)
        );
        assert!(config.posture.is_none());
    }

    /// A device service is read with its token, never printed.
    #[test]
    fn a_device_service_is_read_with_its_token_never_printed() {
        let vars = Env::of([
            ("DEVICE_POSTURE_URL", "https://mdm.internal/posture"),
            ("DEVICE_POSTURE_TOKEN", "mdm t0ken"),
        ]);

        let config = CredentialsConfig::read(&vars, Production).unwrap();

        assert!(config.posture.is_some());
        assert!(!format!("{config:?}").contains("mdm t0ken"));
    }

    /// A device service using plain HTTP is rejected in production but accepted
    /// in development with the same token settings.
    #[test]
    fn a_plain_http_device_service_is_refused_in_production() {
        let vars = Env::of([
            ("DEVICE_POSTURE_URL", "http://mdm.internal/posture"),
            ("DEVICE_POSTURE_TOKEN", "mdm t0ken"),
        ]);

        assert!(matches!(
            CredentialsConfig::read(&vars, Production),
            Err(ConfigError::Invalid { name, .. }) if name == "DEVICE_POSTURE_URL"
        ));
        assert!(CredentialsConfig::read(&vars, Development).is_ok());
    }

    /// A device service without its token is refused.
    #[test]
    fn a_device_service_without_its_token_is_refused() {
        let read = CredentialsConfig::read(
            &Env::of([("DEVICE_POSTURE_URL", "https://mdm.internal/posture")]),
            Production,
        );

        assert!(
            matches!(read, Err(ConfigError::Missing { name }) if name.starts_with("DEVICE_POSTURE_TOKEN"))
        );
    }
}
