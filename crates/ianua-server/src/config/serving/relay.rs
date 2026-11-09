//! The API's relay listener, which the gateway asks its sealed questions
//! on: app sign-in and agents' approvals. It is apart from the internal
//! listener, which keeps the probes and the scrape the cluster reaches
//! without a certificate, so the relay can ask one of every caller.
//!
//! It serves mutual TLS with `RELAY_CA_FILE`, `RELAY_TLS_CERT_FILE` and
//! `RELAY_TLS_KEY_FILE`, taking only the gateway, whose certificate chains
//! to the internal authority. Plain HTTP is taken outside production only,
//! with none of them set.

use std::net::{IpAddr, SocketAddr};

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::environment::Environment;
use ianua_domain::shared::security::secret::Secret;

/// The settings naming the relay's three files.
const FILES: [&str; 3] = ["RELAY_CA_FILE", "RELAY_TLS_CERT_FILE", "RELAY_TLS_KEY_FILE"];

/// The relay listener.
#[derive(Debug, Clone)]
pub(crate) struct RelayConfig {
    /// `HOST` and `RELAY_PORT` (3002): where it listens.
    pub address: SocketAddr,
    /// How its connections are protected.
    pub tls: RelayTls,
}

/// How the relay listener protects its connections.
#[derive(Debug, Clone)]
pub(crate) enum RelayTls {
    /// Mutual TLS: it serves `chain` with `key`, and takes only clients
    /// whose certificate chains to `authority`.
    Mutual {
        /// `RELAY_CA_FILE`: the internal authority, as PEM.
        authority: String,
        /// `RELAY_TLS_CERT_FILE`: the certificate chain it serves.
        chain: String,
        /// `RELAY_TLS_KEY_FILE`: its key.
        key: Secret,
    },
    /// Plain HTTP, outside production, with no file set.
    PlainInDevelopment,
}

impl RelayConfig {
    /// The relay listener `vars` describes in `environment`.
    ///
    /// # Errors
    ///
    /// - [`ConfigError::Contradicts`] when `RELAY_PORT` is the public or
    ///   internal port, or no file is set in production.
    /// - [`ConfigError::Missing`] when only some of the files are set.
    /// - A setting that does not read.
    pub(crate) fn read(vars: &Env, environment: Environment) -> Read<Self> {
        let host: IpAddr = vars
            .parsed("HOST", |host| host.parse::<IpAddr>())?
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let port = vars.number("RELAY_PORT", 3002_u16)?;
        ensure_apart(vars, port)?;
        Ok(Self {
            address: SocketAddr::new(host, port),
            tls: tls(vars, environment)?,
        })
    }
}

/// Refuses a relay port another listener of the node takes.
fn ensure_apart(vars: &Env, port: u16) -> Read<()> {
    if port == 0 {
        return Ok(());
    }
    for name in ["PORT", "INTERNAL_PORT"] {
        if vars
            .optional(name)?
            .is_some_and(|taken| taken == port.to_string())
        {
            return Err(ConfigError::contradicts(
                "RELAY_PORT",
                format!("is the same port as {name}"),
            ));
        }
    }
    Ok(())
}

/// Mutual TLS from the three files, or plain HTTP outside production.
fn tls(vars: &Env, environment: Environment) -> Read<RelayTls> {
    let [authority, chain, key] = FILES.map(|name| vars.file_text(name));
    match (authority?, chain?, key?) {
        (Some(authority), Some(chain), Some(key)) => Ok(RelayTls::Mutual {
            authority,
            chain,
            key: Secret::new(key),
        }),
        (None, None, None) if environment.is_production() => Err(ConfigError::contradicts(
            "RELAY_CA_FILE",
            "and the relay's certificate are unset in production, where the relay listener serves mutual TLS",
        )),
        (None, None, None) => Ok(RelayTls::PlainInDevelopment),
        _ => Err(ConfigError::missing(
            "RELAY_CA_FILE, RELAY_TLS_CERT_FILE and RELAY_TLS_KEY_FILE, which mutual TLS on the relay listener needs together,",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn file(text: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(text.as_bytes()).unwrap();
        file
    }

    /// With nothing set outside production, the relay listens in plain HTTP
    /// on port 3002 of every address.
    #[test]
    fn with_nothing_set_the_relay_listens_on_3002() {
        let relay = RelayConfig::read(&Env::of([]), Environment::Development).unwrap();

        assert_eq!(relay.address.to_string(), "0.0.0.0:3002");
        assert!(matches!(relay.tls, RelayTls::PlainInDevelopment));
    }

    /// The three files read as mutual TLS.
    #[test]
    fn the_three_files_read_as_mutual_tls() {
        let (authority, chain, key) = (file("CA"), file("CHAIN"), file("KEY"));
        let path = |file: &tempfile::NamedTempFile| file.path().display().to_string();
        let vars = Env::of([
            ("RELAY_CA_FILE", path(&authority).as_str()),
            ("RELAY_TLS_CERT_FILE", path(&chain).as_str()),
            ("RELAY_TLS_KEY_FILE", path(&key).as_str()),
        ]);

        let relay = RelayConfig::read(&vars, Environment::Production).unwrap();

        let RelayTls::Mutual {
            authority, chain, ..
        } = relay.tls
        else {
            panic!("the relay serves mutual TLS");
        };
        assert_eq!((authority.as_str(), chain.as_str()), ("CA", "CHAIN"));
    }

    /// Relay configuration refuses missing production TLS, an incomplete
    /// TLS file set and a port shared with the internal listener.
    #[test]
    fn an_unprotected_or_crowded_relay_is_refused() {
        let authority = file("CA");
        let path = authority.path().display().to_string();

        let production = RelayConfig::read(&Env::of([]), Environment::Production);
        let partial = RelayConfig::read(
            &Env::of([("RELAY_CA_FILE", path.as_str())]),
            Environment::Development,
        );
        let crowded = RelayConfig::read(
            &Env::of([("INTERNAL_PORT", "3002")]),
            Environment::Development,
        );

        assert!(matches!(production, Err(ConfigError::Contradicts { .. })));
        assert!(matches!(partial, Err(ConfigError::Missing { .. })));
        assert!(
            matches!(crowded, Err(ConfigError::Contradicts { name, .. }) if name == "RELAY_PORT")
        );
    }
}
