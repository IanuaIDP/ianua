//! App sign-in: the API's relay listener the gateway relays sign-in
//! actions to, over mutual TLS, and how long a confirmed app session is
//! trusted.
//!
//! The same sealed channel carries agents' approval requests, so the
//! approval broker is built on this address and timeout too. Without the
//! address, apps' sign-in addresses answer unavailable and every action
//! waiting for an approval is refused.

use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_boot::internal_link::LinkSettings;
use ianua_infra::http::client::InternalLink;
use url::Url;

/// The settings the gateway's link to the API's relay listener is read
/// from.
const RELAY_LINK: LinkSettings = LinkSettings {
    url: "API_INTERNAL_URL",
    authority: "API_INTERNAL_CA_FILE",
    certificate: "API_INTERNAL_CLIENT_CERT_FILE",
    key: "API_INTERNAL_CLIENT_KEY_FILE",
};

/// The API's relay listener, reached over the sealed channel.
#[derive(Debug, Clone)]
pub(crate) struct ApiChannel {
    /// `API_INTERNAL_URL`, such as `https://ianua-server-relay:3002`.
    pub url: Url,
    /// How calls to it are protected: mutual TLS with
    /// `API_INTERNAL_CA_FILE`, `API_INTERNAL_CLIENT_CERT_FILE` and
    /// `API_INTERNAL_CLIENT_KEY_FILE`, or plain HTTP outside production.
    pub link: InternalLink,
    /// `API_INTERNAL_TIMEOUT_SECONDS` (10): one call to it.
    pub timeout: Duration,
}

/// Configures the API relay and bounds trust in cached application sessions.
#[derive(Debug, Clone)]
pub(crate) struct AppSignInConfig {
    /// The API's internal listener, when `API_INTERNAL_URL` is set.
    pub api: Option<ApiChannel>,
    /// `GATEWAY_APP_SESSION_CACHE_SECONDS` (5): how long a confirmed app
    /// session is trusted before it is checked again, so the longest a
    /// signed-out session still works; `0` checks every request.
    pub session_cache: Duration,
    /// `GATEWAY_APP_SESSION_CHECK_TIMEOUT_MS` (2000): how long one check may
    /// take before the request is refused.
    pub session_check_timeout: Duration,
}

impl AppSignInConfig {
    /// The app sign-in settings `vars` holds.
    ///
    /// # Errors
    ///
    /// An address that is no `http` or `https` URL or carries a credential,
    /// plain HTTP in production, an `https` address without its
    /// certificates, a timeout set with no address, or a time out of its
    /// range.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        Ok(Self {
            api: api(vars, environment)?,
            session_cache: vars.seconds_in(
                "GATEWAY_APP_SESSION_CACHE_SECONDS",
                Duration::from_secs(5),
                0..=60,
            )?,
            session_check_timeout: vars.millis_in(
                "GATEWAY_APP_SESSION_CHECK_TIMEOUT_MS",
                Duration::from_secs(2),
                1..=30_000,
            )?,
        })
    }
}

/// The API's relay listener, when `API_INTERNAL_URL` is set.
fn api(vars: &Env, environment: Environment) -> Read<Option<ApiChannel>> {
    let timeout_name = "API_INTERNAL_TIMEOUT_SECONDS";
    let timeout_set = vars.optional(timeout_name)?.is_some();
    let timeout = vars.seconds_in(timeout_name, Duration::from_secs(10), 1..=60)?;
    let Some(caller) = vars.internal_caller(&RELAY_LINK, environment)? else {
        if timeout_set {
            return Err(ConfigError::contradicts(
                timeout_name,
                "is set without API_INTERNAL_URL",
            ));
        }
        return Ok(None);
    };
    Ok(Some(ApiChannel {
        url: caller.url,
        link: caller.link,
        timeout,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app sign-in settings `vars` holds, read outside production.
    fn development(vars: &Env) -> Read<AppSignInConfig> {
        AppSignInConfig::read(vars, Environment::Development)
    }

    /// With nothing set, no API is reached and app sessions are trusted for
    /// 5 seconds, each check held to 2.
    #[test]
    fn with_nothing_set_no_api_is_reached() {
        let config = development(&Env::of([])).unwrap();

        assert!(config.api.is_none());
        assert_eq!(config.session_cache, Duration::from_secs(5));
        assert_eq!(config.session_check_timeout, Duration::from_secs(2));
    }

    /// The API is reached at the address given, with the documented
    /// timeout.
    #[test]
    fn the_api_is_reached_at_the_address_given() {
        let config = development(&Env::of([(
            "API_INTERNAL_URL",
            "http://ianua-server-internal:3001",
        )]))
        .unwrap();

        let api = config.api.unwrap();
        assert_eq!(api.url.as_str(), "http://ianua-server-internal:3001/");
        assert_eq!(api.timeout, Duration::from_secs(10));
    }

    /// An address that is no http URL is refused.
    #[test]
    fn an_address_that_is_no_http_url_is_refused() {
        let read = development(&Env::of([("API_INTERNAL_URL", "ianua-server:3001")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "API_INTERNAL_URL")
        );
    }

    /// A timeout with no address is refused: nothing would use it.
    #[test]
    fn a_timeout_without_an_address_is_refused() {
        let read = development(&Env::of([("API_INTERNAL_TIMEOUT_SECONDS", "5")]));

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "API_INTERNAL_TIMEOUT_SECONDS")
        );
    }

    /// An hour of cached session trust exceeds the allowed minute and is rejected.
    #[test]
    fn a_session_trusted_past_a_minute_is_refused() {
        let read = development(&Env::of([("GATEWAY_APP_SESSION_CACHE_SECONDS", "3600")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_APP_SESSION_CACHE_SECONDS")
        );
    }

    /// A session cache of nothing checks every request, and is taken.
    #[test]
    fn a_session_cache_of_nothing_is_taken() {
        let config = development(&Env::of([("GATEWAY_APP_SESSION_CACHE_SECONDS", "0")])).unwrap();

        assert_eq!(config.session_cache, Duration::ZERO);
    }
}
