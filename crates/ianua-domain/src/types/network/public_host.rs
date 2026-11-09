use std::fmt;
use std::net::IpAddr;

use crate::message;
use crate::shared::security::ssrf::{is_blocked_ip, is_never_public};
use crate::shared::validation::ValidationError;
use crate::types::HostName;

/// A host on the public internet the platform connects to, such as a
/// tenant's syslog collector or mail server.
///
/// A tenant names it and the platform dials it from inside the deployment.
/// So on top of the [`HostName`] rules it must be a host only the public
/// internet answers for. Refused are single-label names such as `redis`,
/// names under a suffix kept for internal networks such as `.internal` or
/// `.svc.cluster.local`, and IP addresses in the loopback, private,
/// link-local and other internal ranges.
///
/// This checks what the tenant wrote, not where it leads. A public name can
/// resolve to an internal address, so the outbound adapter checks every
/// resolved address again before it connects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicHost(HostName);

impl PublicHost {
    /// Checks that `host` is one only the public internet answers for.
    ///
    /// # Errors
    ///
    /// - [`ValidationError::Custom`] when `host` is a single label, a name
    ///   under an internal suffix, or an internal IP address.
    pub fn new(host: HostName) -> Result<Self, ValidationError> {
        let internal = match host.as_str().parse::<IpAddr>() {
            Ok(ip) => is_blocked_ip(ip),
            Err(_) => is_never_public(host.as_str()),
        };
        if internal {
            return Err(ValidationError::Custom {
                field: "host",
                code: "internal_host".to_owned(),
                message: message!(
                    "values-the-host-must-be-reachable-on",
                    "the host must be reachable on the public internet"
                ),
            });
        }
        Ok(Self(host))
    }

    /// The host as it was written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for PublicHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(value: &str) -> Result<PublicHost, ValidationError> {
        PublicHost::new(HostName::new(value).unwrap())
    }

    /// `logs.acme.com` and `203.0.113.7` are hosts on the public internet,
    /// and are accepted.
    #[test]
    fn a_public_name_or_address_is_accepted() {
        assert!(host("logs.acme.com").is_ok());
        assert!(host("203.0.113.7").is_ok());
    }

    /// Private and loopback addresses, internal suffixes and single-label
    /// service names are refused as public destinations.
    #[test]
    fn an_internal_host_is_refused() {
        for internal in ["10.0.0.5", "127.0.0.1", "metadata.google.internal", "redis"] {
            assert!(host(internal).is_err(), "{internal} was accepted");
        }
    }
}
