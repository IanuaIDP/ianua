//! What a private-network connector may be asked to reach, and how an
//! upstream says it is reached through one.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::shared::validation::rules::url::UrlHost;
use crate::types::{CidrRange, ConnectorId, DomainName, HttpUrl};

/// How the gateway reaches an upstream's backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum UpstreamReach {
    /// The gateway dials the backends itself.
    #[default]
    Direct,
    /// Through the tenant's connector inside its private network, which
    /// dials the backends from there.
    Connector(ConnectorId),
}

/// The hosts a connector may be asked to dial: named networks and domains
/// inside the tenant's private network.
///
/// A connector sits inside a network the gateway cannot see. Without a
/// scope, any route of the tenant could ask it to dial anything in there,
/// such as the domain controller. So it dials only what is named here, and
/// the gateway asks again before every connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "ConnectorScopeRecord", into = "ConnectorScopeRecord")
)]
pub struct ConnectorScope {
    networks: Vec<CidrRange>,
    domains: Vec<DomainName>,
}

impl ConnectorScope {
    /// The most networks and domains a scope names together.
    pub const MAX_ENTRIES: usize = 64;

    /// A scope naming `networks` and `domains`. A domain may be a wildcard,
    /// such as `*.corp.internal`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when it names nothing, so the connector
    ///   could reach nothing, or more than 64 entries.
    pub fn new(networks: Vec<CidrRange>, domains: Vec<DomainName>) -> Result<Self, DomainError> {
        validate_count(
            "scope",
            networks.len().saturating_add(domains.len()),
            1..=Self::MAX_ENTRIES,
        )?;
        Ok(Self { networks, domains })
    }

    /// The networks named, such as `10.20.0.0/16`.
    #[must_use]
    pub fn networks(&self) -> &[CidrRange] {
        &self.networks
    }

    /// The domains named, such as `payroll.corp.internal`.
    #[must_use]
    pub fn domains(&self) -> &[DomainName] {
        &self.domains
    }

    /// Whether the connector may dial `host`: an address inside a named
    /// network, or a name a named domain serves.
    #[must_use]
    pub fn permits(&self, host: UrlHost<'_>) -> bool {
        match host {
            UrlHost::Address(address) => self
                .networks
                .iter()
                .any(|network| network.contains_addr(address)),
            UrlHost::Name(name) => self.domains.iter().any(|domain| domain.serves(name)),
        }
    }

    /// Refuses `urls` unless the connector may dial every one of them.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] naming the first address outside the
    ///   scope.
    pub fn ensure_permits<'a>(
        &self,
        urls: impl IntoIterator<Item = &'a HttpUrl>,
    ) -> Result<(), DomainError> {
        let outside = urls.into_iter().find(|url| !self.permits(url.host()));
        let Some(url) = outside else {
            return Ok(());
        };
        Err(DomainError::invalid(message!(
            "routing-the-connector-may-not-dial-add",
            format!(
                "the connector may not dial {}; add its network or domain to the connector's scope",
                url.as_str()
            )
        )))
    }
}

/// [`ConnectorScope`] as stored, read back through [`ConnectorScope::new`].
#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct ConnectorScopeRecord {
    #[serde(default)]
    networks: Vec<CidrRange>,
    #[serde(default)]
    domains: Vec<DomainName>,
}

#[cfg(feature = "serde")]
impl TryFrom<ConnectorScopeRecord> for ConnectorScope {
    type Error = DomainError;

    fn try_from(record: ConnectorScopeRecord) -> Result<Self, Self::Error> {
        Self::new(record.networks, record.domains)
    }
}

#[cfg(feature = "serde")]
impl From<ConnectorScope> for ConnectorScopeRecord {
    fn from(scope: ConnectorScope) -> Self {
        Self {
            networks: scope.networks,
            domains: scope.domains,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> ConnectorScope {
        ConnectorScope::new(
            vec![CidrRange::new("10.20.0.0/16").unwrap()],
            vec![DomainName::new("*.corp.internal").unwrap()],
        )
        .unwrap()
    }

    fn url(value: &str) -> HttpUrl {
        HttpUrl::new(value).unwrap()
    }

    /// The connector names `10.20.0.0/16` and `*.corp.internal`. It may dial
    /// `10.20.4.7` and `payroll.corp.internal`.
    #[test]
    fn a_connector_dials_what_its_scope_names() {
        let scope = scope();

        assert!(
            scope
                .ensure_permits([
                    &url("https://10.20.4.7:8443"),
                    &url("https://payroll.corp.internal")
                ])
                .is_ok()
        );
    }

    /// Scope validation refuses an address outside the allowed network and
    /// a hostname outside the allowed domain.
    #[test]
    fn a_connector_never_dials_outside_its_scope() {
        let scope = scope();

        assert!(scope.ensure_permits([&url("https://10.0.0.5")]).is_err());
        assert!(
            scope
                .ensure_permits([&url("https://vault.example.com")])
                .is_err()
        );
    }

    /// A scope naming nothing is refused, since the connector could reach
    /// nothing.
    #[test]
    fn a_scope_names_something() {
        assert!(ConnectorScope::new(Vec::new(), Vec::new()).is_err());
    }

    /// An upstream that says nothing about reach is dialled directly.
    #[test]
    fn an_upstream_is_reached_directly_by_default() {
        assert_eq!(UpstreamReach::default(), UpstreamReach::Direct);
    }
}
