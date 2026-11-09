//! Which of a tenant's domains a route answers on.

use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_count;
use crate::types::DomainName;

/// The domains a route is reachable on.
///
/// A tenant answers on several hostnames: its platform subdomain and every
/// domain it has registered. Any of them leads to the same tenant, since the
/// hostname names the tenant. This type lets a tenant bind a route to some
/// of those names. Ann puts the admin pages on `admin.acme.com` only, and
/// they do not match on `app.acme.com`.
///
/// [`Any`](Self::Any) is the default, so a route answers on every domain
/// unless told otherwise.
///
/// Restricting a route does not replace its policy. Whoever sends the
/// request picks the domain. So the domain decides which route is selected,
/// never who is let through. That stays with
/// [`RoutePolicy`](crate::domains::routing::policy::RoutePolicy).
///
/// Stream routes use the same restriction for the server name a TLS
/// handshake asks for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RouteHosts {
    /// Every domain the tenant answers on.
    #[default]
    Any,
    /// Only these. A request on any other domain does not match this route
    /// and goes to whichever other route matches.
    Only(HostNames),
}

/// The names a route is restricted to. Never empty.
///
/// A route reachable on no name could never be requested. Disabling the
/// route is how to do that.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "Vec<DomainName>", into = "Vec<DomainName>")
)]
pub struct HostNames(Vec<DomainName>);

impl HostNames {
    /// A checked list of names.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if `names` is empty.
    pub fn new(names: Vec<DomainName>) -> Result<Self, DomainError> {
        validate_count("hosts", names.len(), 1..=usize::MAX)?;
        Ok(Self(names))
    }

    /// The names, in the order given.
    #[must_use]
    pub fn as_slice(&self) -> &[DomainName] {
        &self.0
    }
}

impl TryFrom<Vec<DomainName>> for HostNames {
    type Error = DomainError;

    fn try_from(names: Vec<DomainName>) -> Result<Self, Self::Error> {
        Self::new(names)
    }
}

impl From<HostNames> for Vec<DomainName> {
    fn from(names: HostNames) -> Self {
        names.0
    }
}

impl RouteHosts {
    /// Restricts a route to the given domains.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] if `domains` is empty. Such a route could
    ///   never be requested, and disabling it does that.
    pub fn only(domains: Vec<DomainName>) -> Result<Self, DomainError> {
        HostNames::new(domains).map(Self::Only)
    }

    /// Reads a restriction from storage. No list means unrestricted.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] if a stored list is empty. Nothing
    ///   writes one, so the row is corrupt.
    pub fn from_stored(domains: Option<Vec<DomainName>>) -> Result<Self, DomainError> {
        let Some(domains) = domains else {
            return Ok(Self::Any);
        };
        Self::only(domains).map_err(|_| DomainError::corrupt_row("route", "an empty list of hosts"))
    }

    /// Whether a request arriving on `host` reaches this route.
    ///
    /// Matching uses [`DomainName::serves`]. So a route restricted to
    /// `*.acme.com` answers for `api.acme.com`. It answers for exactly the
    /// names the certificate on that connection covers. So it agrees with
    /// the TLS handshake on every name, in both directions.
    #[must_use]
    pub fn accepts(&self, host: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Only(domains) => {
                let host = host.trim();
                domains.as_slice().iter().any(|d| d.serves(host))
            }
        }
    }

    /// The domains this is restricted to, or `None` when unrestricted. This
    /// is the shape storage keeps.
    #[must_use]
    pub fn as_stored(&self) -> Option<&[DomainName]> {
        match self {
            Self::Any => None,
            Self::Only(domains) => Some(domains.as_slice()),
        }
    }

    /// Whether this route answers on every domain of its tenant.
    #[must_use]
    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(value: &str) -> DomainName {
        DomainName::new(value).unwrap()
    }

    /// A route with no host restriction accepts `app.acme.com`,
    /// `admin.acme.com` and any other name.
    #[test]
    fn an_unrestricted_route_accepts_every_host() {
        let hosts = RouteHosts::Any;

        assert!(hosts.accepts("app.acme.com"));
        assert!(hosts.accepts("admin.acme.com"));
        assert!(hosts.accepts("anything.at.all"));
    }

    /// A stored restriction to no hosts is refused when read from JSON. One
    /// to `admin.acme.com` reads fine.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_empty_restriction_is_refused() {
        assert!(serde_json::from_str::<RouteHosts>(r#"{"Only":[]}"#).is_err());
        assert!(serde_json::from_str::<RouteHosts>(r#"{"Only":["admin.acme.com"]}"#).is_ok());
    }

    /// A route restricted to `admin.acme.com` accepts that host and refuses
    /// `app.acme.com`.
    #[test]
    fn a_restricted_route_accepts_only_what_it_names() {
        let hosts = RouteHosts::only(vec![domain("admin.acme.com")]).unwrap();

        assert!(hosts.accepts("admin.acme.com"));
        assert!(!hosts.accepts("app.acme.com"));
    }

    /// A route restricted to `admin.acme.com` and `ops.acme.com` accepts
    /// both and refuses `app.acme.com`.
    #[test]
    fn a_restricted_route_accepts_any_of_several() {
        let hosts =
            RouteHosts::only(vec![domain("admin.acme.com"), domain("ops.acme.com")]).unwrap();

        assert!(hosts.accepts("admin.acme.com"));
        assert!(hosts.accepts("ops.acme.com"));
        assert!(!hosts.accepts("app.acme.com"));
    }

    /// A client sends `ADMIN.ACME.COM` or `Admin.Acme.Com` to a route on
    /// `admin.acme.com`. Both match, since the `Host` header carries whatever
    /// the client typed.
    #[test]
    fn matching_ignores_the_casing_the_client_used() {
        let hosts = RouteHosts::only(vec![domain("admin.acme.com")]).unwrap();

        assert!(hosts.accepts("ADMIN.ACME.COM"));
        assert!(hosts.accepts("Admin.Acme.Com"));
    }

    /// An admin restricts a route to an empty list of hosts. It is refused
    /// as invalid.
    #[test]
    fn a_restriction_to_nothing_is_refused() {
        let result = RouteHosts::only(Vec::new());

        assert!(matches!(result, Err(DomainError::Validation(_))));
    }

    /// A stored route has no host list. It reads back as answering on every
    /// host.
    #[test]
    fn an_absent_restriction_reads_back_as_unrestricted() {
        assert_eq!(RouteHosts::from_stored(None).unwrap(), RouteHosts::Any);
    }

    /// A stored route lists `admin.acme.com`. It reads back restricted to
    /// that one host.
    #[test]
    fn a_stored_restriction_reads_back_as_itself() {
        let stored = Some(vec![domain("admin.acme.com")]);

        let hosts = RouteHosts::from_stored(stored).unwrap();

        assert_eq!(hosts.as_stored().map(<[DomainName]>::len), Some(1));
        assert!(!hosts.is_any());
    }

    /// A stored route has an empty host list, which nothing writes. Reading
    /// it is an infrastructure error, not a mistake the caller can fix.
    #[test]
    fn an_empty_stored_restriction_is_corrupt_data() {
        let result = RouteHosts::from_stored(Some(Vec::new()));

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A route given no host setting answers on every host.
    #[test]
    fn the_default_is_unrestricted() {
        assert_eq!(RouteHosts::default(), RouteHosts::Any);
    }

    /// An unrestricted route reads as answering on any host, and one bound
    /// to `admin.acme.com` does not. Otherwise the restriction would vanish
    /// from the dashboard and from storage.
    #[test]
    fn only_an_unrestricted_route_reads_as_answering_on_any_host() {
        assert!(RouteHosts::Any.is_any());
        assert!(
            !RouteHosts::only(vec![domain("admin.acme.com")])
                .unwrap()
                .is_any()
        );
    }
}
