//! Who calls out through the egress gateway and where to: the calling
//! service, the destinations a policy lists, and the target a connection
//! asks for.

use crate::domains::routing::egress::{AgentMark, EgressRequest};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::security::ssrf::{is_blocked_ip, is_never_public};
use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{Rule, TextValue, ValidationError, Validator, text_value};
use crate::types::DomainName;

text_value! {
    /// A calling service, as its client certificate names it. That is a
    /// SPIFFE ID, or the certificate's SHA-256 fingerprint for a service
    /// without one.
    pub struct ServiceIdentity;
}

impl TextValue for ServiceIdentity {
    const FIELD: &'static str = "service";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check
            .not_empty()
            .char_length(1..=512)
            .no_control_chars()
            .no_whitespace()
            .rule(&SpiffeOrFingerprint)
    }
}

/// One host and port a service may reach.
///
/// Read back from storage through [`EgressDestination::new`], so a stored
/// wildcard or port zero never becomes a destination.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "EgressDestinationWire"))]
pub struct EgressDestination {
    host: DomainName,
    port: u16,
}

impl EgressDestination {
    /// A checked destination.
    ///
    /// Egress reaches the public internet only. An address inside the
    /// deployment's network is refused here, whatever networks the operator
    /// lets route upstreams reach. That covers private, loopback and
    /// link-local addresses and cloud metadata services.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for a wildcard host. Over a public
    ///   suffix it would be the whole internet.
    /// - [`DomainError::Validation`] for an internal IP address.
    /// - [`DomainError::Validation`] for a name that can only be internal,
    ///   such as `metadata.google.internal` or `db.svc.cluster.local`.
    /// - [`DomainError::Validation`] for port zero.
    pub fn new(host: DomainName, port: u16) -> Result<Self, DomainError> {
        if host.is_wildcard() {
            return Err(DomainError::invalid(message!(
                "routing-an-egress-destination-names-one-host",
                "an egress destination names one host; wildcards are not accepted"
            )));
        }
        let internal = match host.as_str().parse::<std::net::IpAddr>() {
            Ok(ip) => is_blocked_ip(ip),
            Err(_) => is_never_public(host.as_str()),
        };
        if internal {
            return Err(DomainError::invalid(message!(
                "routing-is-internal-egress-reaches-public-destinations",
                format!("{host} is internal; egress reaches public destinations only")
            )));
        }
        validate_range("port", port, 1..=u16::MAX)?;
        Ok(Self { host, port })
    }

    /// The validated public destination compared without case.
    #[must_use]
    pub fn host(&self) -> &DomainName {
        &self.host
    }

    /// The nonzero TCP endpoint paired with the allowed host.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether this is `host:port`. Host names compare without case.
    #[must_use]
    pub fn is(&self, host: &str, port: u16) -> bool {
        self.port == port && self.host.as_str().eq_ignore_ascii_case(host)
    }
}

/// The stored shape of an [`EgressDestination`], before validation.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
pub(crate) struct EgressDestinationWire {
    host: String,
    port: u16,
}

impl std::fmt::Display for EgressDestination {
    /// `host:port`, as an audit record names a destination.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host.as_str(), self.port)
    }
}

#[cfg(feature = "serde")]
impl TryFrom<EgressDestinationWire> for EgressDestination {
    type Error = DomainError;

    fn try_from(wire: EgressDestinationWire) -> Result<Self, Self::Error> {
        let host = DomainName::new(wire.host)?;
        Self::new(host, wire.port)
    }
}

/// Where an outbound connection asks to go, read strictly: the host and
/// port a `CONNECT` or an absolute-form request names.
///
/// The host must read as a domain name, so no user info, percent escape or
/// bracketed address gets past the comparison with a policy's list as a
/// host other than the one compared. A wildcard is no host, and an internal
/// address named directly is refused here, as a destination naming one is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressTarget {
    host: DomainName,
    port: u16,
}

impl EgressTarget {
    /// The target `host:port`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for a host that is no domain name or
    ///   address, a wildcard, an internal address, or port zero.
    pub fn new(host: &str, port: u16) -> Result<Self, DomainError> {
        let host = DomainName::new(host)?;
        if host.is_wildcard() {
            return Err(DomainError::invalid(message!(
                "routing-an-egress-target-names-one-host",
                "an egress target names one host"
            )));
        }
        let internal = host
            .as_str()
            .parse::<std::net::IpAddr>()
            .is_ok_and(is_blocked_ip);
        if internal {
            return Err(DomainError::invalid(message!(
                "routing-an-egress-target-names-an-internal",
                "an egress target names an internal address"
            )));
        }
        validate_range("port", port, 1..=u16::MAX)?;
        Ok(Self { host, port })
    }

    /// The validated public destination used for the outbound connection.
    #[must_use]
    pub fn host(&self) -> &DomainName {
        &self.host
    }

    /// The nonzero TCP endpoint used for the outbound connection.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The connection to this target, for a call carrying `agent_mark`.
    #[must_use]
    pub fn request(&self, agent_mark: AgentMark) -> EgressRequest<'_> {
        EgressRequest {
            host: self.host.as_str(),
            port: self.port,
            agent_mark,
        }
    }
}

impl std::fmt::Display for EgressTarget {
    /// `host:port`, as an audit record names a target.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host.as_str(), self.port)
    }
}

/// A SPIFFE ID with a path, or `sha256:` and the 64 lower-case hex digits of
/// a certificate's fingerprint.
struct SpiffeOrFingerprint;

impl Rule for SpiffeOrFingerprint {
    fn check(&self, field: &'static str, value: &str) -> Option<ValidationError> {
        let spiffe = value
            .strip_prefix("spiffe://")
            .is_some_and(|rest| rest.contains('/') && !rest.contains('*'));
        let fingerprint = value.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        });
        if spiffe || fingerprint {
            return None;
        }
        Some(ValidationError::Custom {
            field,
            code: "invalid_service_identity".to_owned(),
            message: message!(
                "routing-a-service-is-named-by-its",
                "a service is named by its SPIFFE ID or `sha256:<fingerprint>` of its certificate"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Egress destinations reject metadata, private and loopback addresses
    /// and internal hostnames. A public IP address is accepted.
    #[test]
    fn an_internal_address_is_never_a_destination() {
        for internal in [
            "169.254.169.254",
            "10.0.0.5",
            "127.0.0.1",
            "metadata.google.internal",
            "db.svc.cluster.local",
            "printer.local",
        ] {
            assert!(
                EgressDestination::new(DomainName::new(internal).unwrap(), 80).is_err(),
                "{internal}"
            );
        }
        assert!(EgressDestination::new(DomainName::new("93.184.216.34").unwrap(), 443).is_ok());
    }

    /// A stored destination reads `*.example.com:443`. Reading it back is
    /// refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_wildcard_never_becomes_a_destination() {
        let stored = serde_json::json!({ "host": "*.example.com", "port": 443 });

        assert!(serde_json::from_value::<EgressDestination>(stored).is_err());
    }

    /// A SPIFFE ID with a path and a `sha256:` fingerprint of 64 hex digits
    /// are accepted. A bare name, a SPIFFE ID with no path or a wildcard, and
    /// a bad fingerprint are refused.
    #[test]
    fn a_service_is_named_by_spiffe_id_or_certificate_fingerprint() {
        assert!(ServiceIdentity::new("spiffe://td/ns/a").is_ok());
        assert!(ServiceIdentity::new(format!("sha256:{}", "a".repeat(64))).is_ok());
        for bad in ["", "fetcher", "spiffe://td", "spiffe://td/*", "sha256:XYZ"] {
            assert!(ServiceIdentity::new(bad).is_err(), "{bad}");
        }
    }
}
