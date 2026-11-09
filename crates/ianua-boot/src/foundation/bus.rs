//! Where the message bus lives: in this process for a deployment of one
//! node, or on a bus server every node reaches.

use std::time::Duration;

use ianua_domain::shared::security::secret::Secret;
use ianua_infra::bus::BusSignIn;

use crate::env::{ConfigError, Env, Read};

/// Where the message bus lives.
#[derive(Debug, Clone)]
pub enum BusPlace {
    /// In this process, keeping at most `events` events.
    Memory {
        /// `BUS_MEMORY_EVENTS` (10000).
        events: usize,
    },
    /// On the bus server at `url`.
    Server {
        /// `BUS_URL`, such as `nats://bus.internal:4222`.
        url: String,
        /// `BUS_TOKEN` or `BUS_CREDENTIALS_FILE`, or neither.
        sign_in: BusSignIn,
    },
}

/// The message bus.
#[derive(Debug, Clone)]
pub struct BusConfig {
    /// Where it lives: on a server when `BUS_URL` is set.
    pub place: BusPlace,
    /// `BUS_TIMEOUT_SECONDS` (5): the longest one call to the bus server
    /// may take.
    pub timeout: Duration,
}

impl BusConfig {
    /// The bus `vars` names.
    ///
    /// # Errors
    ///
    /// A `BUS_URL` that is no bus address or carries a password, both a
    /// token and a credentials file, or either with no `BUS_URL`.
    pub fn read(vars: &Env) -> Read<Self> {
        let token = vars.secret("BUS_TOKEN")?;
        let credentials = vars.path("BUS_CREDENTIALS_FILE")?;
        let place = match bus_url(vars)? {
            Some(url) => BusPlace::Server {
                url,
                sign_in: sign_in(token, credentials)?,
            },
            None => memory(vars, token.is_some(), credentials.is_some())?,
        };
        Ok(Self {
            place,
            timeout: vars.seconds("BUS_TIMEOUT_SECONDS", Duration::from_secs(5))?,
        })
    }

    /// Whether the bus lives in this process.
    #[must_use]
    pub fn in_process(&self) -> bool {
        matches!(self.place, BusPlace::Memory { .. })
    }
}

/// `BUS_URL`, refused when it is no bus address or holds a password.
fn bus_url(vars: &Env) -> Read<Option<String>> {
    let name = "BUS_URL";
    let Some(value) = vars.optional(name)? else {
        return Ok(None);
    };
    let refused =
        || ConfigError::invalid(name, "must be a nats://, tls://, ws:// or wss:// address");
    let url = url::Url::parse(&value).map_err(|_| refused())?;
    if !matches!(url.scheme(), "nats" | "tls" | "ws" | "wss") || url.host_str().is_none() {
        return Err(refused());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::invalid(
            name,
            "must not hold a user or password; set BUS_TOKEN or BUS_CREDENTIALS_FILE",
        ));
    }
    Ok(Some(value))
}

/// How the platform signs in to the bus server.
fn sign_in(token: Option<Secret>, credentials: Option<std::path::PathBuf>) -> Read<BusSignIn> {
    match (token, credentials) {
        (Some(_), Some(_)) => Err(ConfigError::contradicts(
            "BUS_TOKEN",
            "and BUS_CREDENTIALS_FILE are both set; set one",
        )),
        (Some(token), None) => Ok(BusSignIn::Token(token)),
        (None, Some(path)) => Ok(BusSignIn::CredentialsFile(path)),
        (None, None) => Ok(BusSignIn::Open),
    }
}

/// The bus in this process, refusing a sign-in nothing would use.
fn memory(vars: &Env, token: bool, credentials: bool) -> Read<BusPlace> {
    if token {
        return Err(ConfigError::contradicts(
            "BUS_TOKEN",
            "is set without BUS_URL",
        ));
    }
    if credentials {
        return Err(ConfigError::contradicts(
            "BUS_CREDENTIALS_FILE",
            "is set without BUS_URL",
        ));
    }
    Ok(BusPlace::Memory {
        events: vars.number_in("BUS_MEMORY_EVENTS", 10_000, 1..=10_000_000)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no bus server named, the bus lives in this process.
    #[test]
    fn with_no_server_the_bus_lives_in_this_process() {
        let config = BusConfig::read(&Env::of([])).unwrap();

        assert!(config.in_process());
    }

    /// A bus server is reached with the token given.
    #[test]
    fn a_bus_server_is_reached_with_its_token() {
        let config = BusConfig::read(&Env::of([
            ("BUS_URL", "nats://bus.internal:4222"),
            ("BUS_TOKEN", "t0ken"),
        ]))
        .unwrap();

        assert!(matches!(
            config.place,
            BusPlace::Server {
                sign_in: BusSignIn::Token(_),
                ..
            }
        ));
        assert!(!format!("{config:?}").contains("t0ken"));
    }

    /// A bus URL containing credentials is refused as an invalid address.
    #[test]
    fn a_password_in_the_bus_address_is_refused() {
        let read = BusConfig::read(&Env::of([("BUS_URL", "nats://user:pw@bus.internal:4222")]));

        assert!(matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "BUS_URL"));
    }

    /// An address that is no bus address is refused.
    #[test]
    fn an_address_that_is_no_bus_address_is_refused() {
        assert!(BusConfig::read(&Env::of([("BUS_URL", "https://bus.internal")])).is_err());
    }

    /// Supplying both a bus token and a credentials file is contradictory.
    #[test]
    fn a_token_and_a_credentials_file_are_refused() {
        let vars = Env::of([
            ("BUS_URL", "nats://bus.internal:4222"),
            ("BUS_TOKEN", "t0ken"),
            ("BUS_CREDENTIALS_FILE", "/run/secrets/bus.creds"),
        ]);

        assert!(matches!(
            BusConfig::read(&vars),
            Err(ConfigError::Contradicts { .. })
        ));
    }

    /// A token without a bus server is refused, naming the unused token setting.
    #[test]
    fn a_sign_in_without_a_bus_server_is_refused() {
        let read = BusConfig::read(&Env::of([("BUS_TOKEN", "t0ken")]));

        assert!(matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "BUS_TOKEN"));
    }
}
