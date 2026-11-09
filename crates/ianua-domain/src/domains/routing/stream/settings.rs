//! What a stream route is set up with: the protocol, who may pass, the
//! port, the backends and the timeouts.

use crate::shared::errors::DomainError;
use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;
use crate::types::{HostName, Seconds};

/// The shortest a stream may sit idle before the proxy closes it.
///
/// A minute is generous for a connection that has gone quiet. A lower value
/// would close healthy long-lived connections the moment they paused, and
/// those are most of what layer 4 carries.
pub(crate) const MIN_IDLE_TIMEOUT_SECS: u32 = 60;

/// The longest a stream may sit idle.
///
/// Twelve hours. Past this a connection is leaked, not idle. Each one still
/// open holds a file descriptor, and rests on a policy decision so old that
/// the grant behind it may be revoked by now.
pub(crate) const MAX_IDLE_TIMEOUT_SECS: u32 = 43_200;

/// The longest the proxy will wait to reach a backend.
pub(crate) const MAX_CONNECT_TIMEOUT_SECS: u32 = 60;

/// How the proxy speaks on a listening port.
///
/// Each variant fixes what the proxy can learn about the client. So it also
/// fixes which policies can be set. See [`StreamPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum StreamProtocol {
    /// Raw TCP, forwarded byte for byte.
    ///
    /// No handshake happens at the proxy. So there is no certificate, no SNI,
    /// and nothing to know the client by but its address.
    Tcp,
    /// TLS terminated at the proxy, then forwarded in the clear.
    ///
    /// This is the only variant where the proxy verifies a client
    /// certificate. So it is the only one that can carry a proven identity.
    TlsTerminate,
    /// TLS forwarded untouched, with only the SNI read in passing.
    ///
    /// Encryption stays end to end. In exchange, the client certificate is
    /// inside the tunnel, where the proxy cannot see it.
    TlsPassthrough,
    /// UDP datagrams.
    ///
    /// UDP has no connection. There is no handshake to check and no stream
    /// to hold open. So every policy decision is made per flow, on the
    /// address alone.
    Udp,
}

impl StreamProtocol {
    /// Whether the proxy completes the TLS handshake, so it can verify a
    /// client certificate.
    #[must_use]
    pub fn terminates_tls(self) -> bool {
        matches!(self, Self::TlsTerminate)
    }

    /// Whether a handshake on this protocol carries an SNI the proxy can read.
    #[must_use]
    pub fn carries_sni(self) -> bool {
        matches!(self, Self::TlsTerminate | Self::TlsPassthrough)
    }

    /// The stored form, such as `tcp` or `tls_passthrough`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::TlsTerminate => "tls_terminate",
            Self::TlsPassthrough => "tls_passthrough",
            Self::Udp => "udp",
        }
    }

    /// Reads a protocol from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for a value this version does not
    ///   know. The row is corrupt or from a newer version, not input a caller
    ///   got wrong.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "tls_terminate" => Ok(Self::TlsTerminate),
            "tls_passthrough" => Ok(Self::TlsPassthrough),
            "udp" => Ok(Self::Udp),
            _ => Err(DomainError::corrupt_row(
                "stream route",
                "an unknown protocol",
            )),
        }
    }
}

/// What a stream route checks on the wire before it lets a connection in.
///
/// A bearer token lives in a request, and a raw port has no requests. So on
/// a port the only identity the wire can carry is a client certificate, and
/// only when the proxy terminates the handshake. A signed-in person comes
/// through the tunnel instead, which carries their token. Who by name may
/// pass is the route's
/// [`StreamAccess`](crate::domains::routing::stream::access::StreamAccess).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum StreamPolicy {
    /// A verified client certificate, checked against the tenant's trusted
    /// CAs before the connection is spliced.
    MutualTls,
    /// The signed-in tunnel: the client opens an HTTPS `CONNECT` to the
    /// gateway carrying the caller's token, and the stream runs inside it.
    /// The token is checked like any other, and checked again while the
    /// tunnel stays open.
    Tunnel,
    /// Anyone who can reach the port.
    ///
    /// It must be chosen by name, never implied. A stream route that cannot
    /// tell who is calling lets anyone in, so opening one takes an explicit
    /// choice.
    Public,
}

impl StreamPolicy {
    /// The stored form, `mutual_tls`, `tunnel` or `public`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MutualTls => "mutual_tls",
            Self::Tunnel => "tunnel",
            Self::Public => "public",
        }
    }

    /// Reads a policy from storage.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] for an unknown value.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "mutual_tls" => Ok(Self::MutualTls),
            "tunnel" => Ok(Self::Tunnel),
            "public" => Ok(Self::Public),
            _ => Err(DomainError::corrupt_row(
                "stream route",
                "an unknown policy",
            )),
        }
    }
}

/// A port the proxy listens on for a tenant.
///
/// Zero is not a port. Ports below 1024 are refused too. The data plane does
/// not run as root, so it could never bind them. The route would then fail at
/// start-up instead of when it is set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ListenPort(u16);

impl ListenPort {
    /// The lowest port a stream route may claim.
    pub const MIN: u16 = 1024;

    /// A checked listening port.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] outside `1024..=65535`.
    pub fn new(port: u16) -> Result<Self, ValidationError> {
        validate_range("listen_port", port, Self::MIN..=u16::MAX)?;
        Ok(Self(port))
    }

    /// The port number.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Rebuilt through the constructor, for the reason given on
/// [`StreamBackend`]'s implementation.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ListenPort {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = u16::deserialize(deserializer)?;
        Self::new(raw).map_err(<D::Error as serde::de::Error>::custom)
    }
}

/// Where a stream route sends what it accepts.
///
/// It is a host and a port, not a URL. Layer 4 has no scheme, and a made-up
/// one would have to be parsed off again in the data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct StreamBackend {
    host: HostName,
    port: u16,
    weight: u32,
}

impl StreamBackend {
    /// The heaviest a single backend may be weighted.
    pub const MAX_WEIGHT: u32 = 1_000;

    /// A checked backend target.
    ///
    /// `host` may be a DNS name or an IP literal. Which one only matters at
    /// connect time. Whether this deployment may dial that host is decided in
    /// the application layer, where the operator's setting for private
    /// addresses lives.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the host is not a [`HostName`].
    /// - [`ValidationError`] if the port is zero.
    /// - [`ValidationError`] if the weight is outside `1..=1000`.
    pub fn new(host: impl Into<String>, port: u16, weight: u32) -> Result<Self, ValidationError> {
        let host = HostName::new(host)?;
        validate_range("backend_port", port, 1..=u16::MAX)?;
        validate_range("backend_weight", weight, 1..=Self::MAX_WEIGHT)?;

        Ok(Self { host, port, weight })
    }

    /// The host to dial.
    #[must_use]
    pub fn host(&self) -> &HostName {
        &self.host
    }

    /// The port to dial.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Relative traffic weight against the other backends.
    #[must_use]
    pub fn weight(&self) -> u32 {
        self.weight
    }

    /// The dial target as `host:port`, with an IPv6 host in brackets.
    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.as_str().contains(':') {
            return format!("[{}]:{}", self.host, self.port);
        }
        format!("{}:{}", self.host, self.port)
    }
}

/// Rebuilt through the constructor, not field by field.
///
/// A derived implementation would fill the private fields directly. Then a
/// host with a newline, or a weight of zero, would arrive intact from an API
/// request or an old row. So reading goes through the same checks as
/// creating.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for StreamBackend {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Wire {
            host: String,
            port: u16,
            weight: u32,
        }

        let wire = Wire::deserialize(deserializer)?;

        Self::new(wire.host, wire.port, wire.weight).map_err(<D::Error as serde::de::Error>::custom)
    }
}

/// How long a stream may take to start, and how long it may say nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct StreamTimeouts {
    connect_secs: Seconds,
    idle_secs: Seconds,
}

impl StreamTimeouts {
    /// Checked timeouts.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if the connect timeout is zero or beyond
    ///   `MAX_CONNECT_TIMEOUT_SECS`.
    /// - [`ValidationError`] if the idle timeout is outside
    ///   `MIN_IDLE_TIMEOUT_SECS..=MAX_IDLE_TIMEOUT_SECS`.
    pub fn new(connect_secs: Seconds, idle_secs: Seconds) -> Result<Self, ValidationError> {
        validate_range(
            "connect_timeout_secs",
            connect_secs.get(),
            1..=MAX_CONNECT_TIMEOUT_SECS,
        )?;
        validate_range(
            "idle_timeout_secs",
            idle_secs.get(),
            MIN_IDLE_TIMEOUT_SECS..=MAX_IDLE_TIMEOUT_SECS,
        )?;
        Ok(Self {
            connect_secs,
            idle_secs,
        })
    }

    /// Seconds the proxy waits to reach a backend.
    #[must_use]
    pub fn connect_secs(self) -> Seconds {
        self.connect_secs
    }

    /// Seconds a spliced stream may carry nothing before it is closed.
    #[must_use]
    pub fn idle_secs(self) -> Seconds {
        self.idle_secs
    }
}

impl Default for StreamTimeouts {
    /// Ten seconds to connect, an hour idle.
    fn default() -> Self {
        Self {
            connect_secs: Seconds::new(10),
            idle_secs: Seconds::new(3_600),
        }
    }
}

/// Rebuilt through the constructor, for the reason given on
/// [`StreamBackend`]'s implementation.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for StreamTimeouts {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Wire {
            connect_secs: Seconds,
            idle_secs: Seconds,
        }

        let wire = Wire::deserialize(deserializer)?;

        Self::new(wire.connect_secs, wire.idle_secs).map_err(<D::Error as serde::de::Error>::custom)
    }
}
