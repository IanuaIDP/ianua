//! Where the gateway takes the links of the connectors tenants run inside
//! their own networks, and what those links are held to.
//!
//! The listener is off unless `GATEWAY_CONNECTOR_LISTEN` names an address.
//! With it off, no connector can link, and every service reached through
//! one is answered as unavailable. With it on, it takes connections only
//! from a client certificate the connector authority signed, so the
//! authority's certificate and the listener's own certificate and key are
//! required with it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};
use ianua_boot::network::PemFiles;

/// The connector listener's address and certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectorListen {
    /// `GATEWAY_CONNECTOR_LISTEN`: where connectors dial in.
    pub address: SocketAddr,
    /// `GATEWAY_CONNECTOR_CA_FILE`: the connector authority's certificate,
    /// the only one a connector's certificate may chain to.
    pub authority: PathBuf,
    /// `GATEWAY_CONNECTOR_TLS_CERT_FILE` and `GATEWAY_CONNECTOR_TLS_KEY_FILE`:
    /// the certificate the listener serves, which `ianua connector-pki`
    /// issues under the same authority.
    pub certificate: PemFiles,
}

/// What connector links are held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectorLimits {
    /// `GATEWAY_CONNECTOR_MAX_LINKS` (4096): links open at once across every
    /// connector; one past it is closed.
    pub max_links: usize,
    /// `GATEWAY_CONNECTOR_LINKS_PER_CONNECTOR` (16): links one connector may
    /// hold at once; one past it is closed.
    pub links_per_connector: usize,
    /// `GATEWAY_CONNECTOR_STREAMS_PER_LINK` (256): connections to backends
    /// one link carries at once.
    pub streams_per_link: usize,
    /// `GATEWAY_CONNECTOR_HANDSHAKE_TIMEOUT_SECONDS` (10): the TLS
    /// handshake and the HTTP/2 one after it.
    pub handshake: Duration,
    /// `GATEWAY_CONNECTOR_OPEN_TIMEOUT_SECONDS` (10): opening one connection
    /// to a backend down a link.
    pub open: Duration,
    /// `GATEWAY_CONNECTOR_KEEPALIVE_SECONDS` (20): how often a link is
    /// pinged, and how long the answer may take before the link is closed.
    pub keepalive: Duration,
    /// `GATEWAY_CONNECTOR_SIGHTING_SECONDS` (300): how often a link that
    /// stays open is noted as seen.
    pub sighting: Duration,
}

/// Where connectors link in, and what their links are held to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectorsConfig {
    /// The listener, or none when connectors are not taken.
    pub listen: Option<ConnectorListen>,
    /// What the links are held to.
    pub limits: ConnectorLimits,
}

impl ConnectorsConfig {
    /// The connector settings `vars` holds.
    ///
    /// # Errors
    ///
    /// - [`ConfigError::Missing`] when the listener is set without the
    ///   authority's certificate or its own certificate and key.
    /// - [`ConfigError::Contradicts`] when a certificate is set without
    ///   the listener.
    /// - A count or time out of its range.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            listen: listen(vars)?,
            limits: limits(vars)?,
        })
    }
}

/// The listener `vars` asks for, its certificates with it.
fn listen(vars: &Env) -> Read<Option<ConnectorListen>> {
    let address = vars.parsed("GATEWAY_CONNECTOR_LISTEN", |text| {
        text.parse::<SocketAddr>()
    })?;
    let authority = vars.path("GATEWAY_CONNECTOR_CA_FILE")?;
    let certificate = vars.pem_files(
        "GATEWAY_CONNECTOR_TLS_CERT_FILE",
        "GATEWAY_CONNECTOR_TLS_KEY_FILE",
    )?;
    let Some(address) = address else {
        return without_listener(authority.is_some() || certificate.is_some());
    };
    let authority = authority.ok_or_else(|| {
        ConfigError::missing("GATEWAY_CONNECTOR_CA_FILE, which the connector listener needs,")
    })?;
    let certificate = certificate.ok_or_else(|| {
        ConfigError::missing(
            "GATEWAY_CONNECTOR_TLS_CERT_FILE and GATEWAY_CONNECTOR_TLS_KEY_FILE, which the \
             connector listener needs,",
        )
    })?;
    Ok(Some(ConnectorListen {
        address,
        authority,
        certificate,
    }))
}

/// No listener, refused when a certificate meant for one is set: a
/// listener that was meant to be on and silently is not leaves every
/// connector unlinked.
fn without_listener(certificates_set: bool) -> Read<Option<ConnectorListen>> {
    if certificates_set {
        return Err(ConfigError::contradicts(
            "GATEWAY_CONNECTOR_CA_FILE",
            "or a connector listener certificate is set without GATEWAY_CONNECTOR_LISTEN",
        ));
    }
    Ok(None)
}

/// What the links are held to.
fn limits(vars: &Env) -> Read<ConnectorLimits> {
    Ok(ConnectorLimits {
        max_links: vars.number_in("GATEWAY_CONNECTOR_MAX_LINKS", 4096, 1..=100_000)?,
        links_per_connector: vars.number_in(
            "GATEWAY_CONNECTOR_LINKS_PER_CONNECTOR",
            16,
            1..=256,
        )?,
        streams_per_link: vars.number_in("GATEWAY_CONNECTOR_STREAMS_PER_LINK", 256, 1..=10_000)?,
        handshake: vars.seconds_in(
            "GATEWAY_CONNECTOR_HANDSHAKE_TIMEOUT_SECONDS",
            Duration::from_secs(10),
            1..=120,
        )?,
        open: vars.seconds_in(
            "GATEWAY_CONNECTOR_OPEN_TIMEOUT_SECONDS",
            Duration::from_secs(10),
            1..=120,
        )?,
        keepalive: vars.seconds_in(
            "GATEWAY_CONNECTOR_KEEPALIVE_SECONDS",
            Duration::from_secs(20),
            1..=600,
        )?,
        sighting: vars.seconds_in(
            "GATEWAY_CONNECTOR_SIGHTING_SECONDS",
            Duration::from_secs(300),
            10..=86_400,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With nothing set, no connector listener opens and the documented
    /// bounds hold.
    #[test]
    fn with_nothing_set_no_listener_opens() {
        let config = ConnectorsConfig::read(&Env::of([])).unwrap();

        assert_eq!(config.listen, None);
        assert_eq!(config.limits.max_links, 4096);
        assert_eq!(config.limits.links_per_connector, 16);
        assert_eq!(config.limits.streams_per_link, 256);
        assert_eq!(config.limits.open, Duration::from_secs(10));
        assert_eq!(config.limits.sighting, Duration::from_secs(300));
    }

    /// The listener with its authority and certificate reads whole.
    #[test]
    fn a_listener_with_its_certificates_reads() {
        let config = ConnectorsConfig::read(&Env::of([
            ("GATEWAY_CONNECTOR_LISTEN", "0.0.0.0:8444"),
            ("GATEWAY_CONNECTOR_CA_FILE", "/run/connectors/ca.pem"),
            (
                "GATEWAY_CONNECTOR_TLS_CERT_FILE",
                "/run/connectors/cert.pem",
            ),
            ("GATEWAY_CONNECTOR_TLS_KEY_FILE", "/run/connectors/key.pem"),
        ]))
        .unwrap();

        let listen = config.listen.unwrap();
        assert_eq!(listen.address.port(), 8444);
        assert_eq!(listen.authority, PathBuf::from("/run/connectors/ca.pem"));
    }

    /// A connector listener with its own certificate but no client authority is
    /// rejected with the missing authority setting named.
    #[test]
    fn a_listener_without_its_authority_is_refused() {
        let read = ConnectorsConfig::read(&Env::of([
            ("GATEWAY_CONNECTOR_LISTEN", "0.0.0.0:8444"),
            (
                "GATEWAY_CONNECTOR_TLS_CERT_FILE",
                "/run/connectors/cert.pem",
            ),
            ("GATEWAY_CONNECTOR_TLS_KEY_FILE", "/run/connectors/key.pem"),
        ]));

        assert!(
            read.unwrap_err()
                .to_string()
                .contains("GATEWAY_CONNECTOR_CA_FILE")
        );
    }

    /// A listener without its own certificate is refused.
    #[test]
    fn a_listener_without_its_certificate_is_refused() {
        let read = ConnectorsConfig::read(&Env::of([
            ("GATEWAY_CONNECTOR_LISTEN", "0.0.0.0:8444"),
            ("GATEWAY_CONNECTOR_CA_FILE", "/run/connectors/ca.pem"),
        ]));

        assert!(
            read.unwrap_err()
                .to_string()
                .contains("GATEWAY_CONNECTOR_TLS_CERT_FILE")
        );
    }

    /// A connector authority configured without a listener is rejected as contradictory.
    #[test]
    fn certificates_without_a_listener_are_refused() {
        let read = ConnectorsConfig::read(&Env::of([(
            "GATEWAY_CONNECTOR_CA_FILE",
            "/run/connectors/ca.pem",
        )]));

        assert!(matches!(read, Err(ConfigError::Contradicts { .. })));
    }
}
