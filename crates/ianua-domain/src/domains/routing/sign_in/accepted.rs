//! A service accepting another service's app sign-in.
//!
//! A person signs in once, on the hosts of the service that owns the sign-in.
//! Another service accepts that sign-in only when told to. It is also told how
//! the sign-in reaches it. That is on the owner's own hosts, as a cookie of its
//! own on hosts of its own, or as short-lived tokens the owner's pages fetch.

use crate::domains::routing::sign_in::invalid;
use crate::shared::validation::ValidationError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::validate_count;
use crate::types::{DomainName, ServiceId};

/// How a signed-in person's session reaches a service accepting another's
/// sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SignInDelivery {
    /// On the owner's hosts, with the owner's session cookie. The service is
    /// served on those hosts too, for example under `/api`.
    SameHost,
    /// A session cookie of its own, on hosts of its own. Signing in on the
    /// owner's host sets it there as well, by a short hop through each host.
    OwnCookie(CookieHosts),
    /// Bearer tokens for this service, a few minutes long, which the owner's
    /// pages fetch from the owner's token address while signed in.
    Tokens,
}

/// The hosts a service's own session cookie is set on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(try_from = "Vec<DomainName>", into = "Vec<DomainName>")
)]
pub struct CookieHosts(Vec<DomainName>);

impl CookieHosts {
    /// A checked list of cookie hosts.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] when no host is named.
    /// - [`ValidationError`] when a host is a wildcard, since a cookie
    ///   belongs to one host.
    /// - [`ValidationError`] when a host is named twice.
    pub fn new(hosts: Vec<DomainName>) -> Result<Self, ValidationError> {
        validate_count("hosts", hosts.len(), 1..=usize::MAX)?;
        if hosts.iter().any(DomainName::is_wildcard) {
            return Err(invalid(
                "hosts",
                "a session cookie cannot be set on a wildcard host; name each host",
            ));
        }
        if first_repeat(hosts.iter().map(DomainName::as_str)).is_some() {
            return Err(invalid("hosts", "a host is named more than once"));
        }
        Ok(Self(hosts))
    }

    /// The validated names allowed to accept the other service's sign-in.
    #[must_use]
    pub fn hosts(&self) -> &[DomainName] {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl TryFrom<Vec<DomainName>> for CookieHosts {
    type Error = ValidationError;

    fn try_from(hosts: Vec<DomainName>) -> Result<Self, Self::Error> {
        Self::new(hosts)
    }
}

#[cfg(feature = "serde")]
impl From<CookieHosts> for Vec<DomainName> {
    fn from(hosts: CookieHosts) -> Self {
        hosts.0
    }
}

/// Which service's sign-in a service accepts, and how it reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedSignIn {
    owner: ServiceId,
    delivery: SignInDelivery,
}

impl AcceptedSignIn {
    /// Accepts `owner`'s sign-in, delivered by `delivery`.
    #[must_use]
    pub fn new(owner: ServiceId, delivery: SignInDelivery) -> Self {
        Self { owner, delivery }
    }

    /// The service whose sign-in is accepted.
    #[must_use]
    pub fn owner(&self) -> &ServiceId {
        &self.owner
    }

    /// How the sign-in reaches the accepting service.
    #[must_use]
    pub fn delivery(&self) -> &SignInDelivery {
        &self.delivery
    }

    /// The hosts the accepting service's own cookie is set on. Empty unless
    /// it has one.
    #[must_use]
    pub fn cookie_hosts(&self) -> &[DomainName] {
        match &self.delivery {
            SignInDelivery::OwnCookie(hosts) => hosts.hosts(),
            SignInDelivery::SameHost | SignInDelivery::Tokens => &[],
        }
    }

    /// Whether the accepting service is reached with sessions or tokens made
    /// for its own audience, rather than the owner's.
    #[must_use]
    pub fn needs_own_audience(&self) -> bool {
        !matches!(self.delivery, SignInDelivery::SameHost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str) -> DomainName {
        DomainName::new(name).unwrap()
    }

    /// An admin gives a service its own cookie on no hosts. It is refused.
    #[test]
    fn a_cookie_needs_a_host() {
        assert!(CookieHosts::new(Vec::new()).is_err());
    }

    /// An admin lists `api.example.com` twice as a cookie host. It is
    /// refused.
    #[test]
    fn a_cookie_host_is_named_once() {
        let twice = vec![host("api.example.com"), host("api.example.com")];

        assert!(CookieHosts::new(twice).is_err());
    }

    /// Cookie hosts reject wildcard domain names.
    #[test]
    fn a_cookie_belongs_to_one_named_host() {
        assert!(CookieHosts::new(vec![host("*.example.com")]).is_err());
    }

    /// A service on the owner's hosts uses the owner's audience. One with
    /// its own cookie, or reached by tokens, needs an audience of its own.
    #[test]
    fn only_a_service_on_the_owners_hosts_uses_the_owners_audience() {
        let owner = ServiceId::new();
        let cookie = CookieHosts::new(vec![host("api.example.com")]).unwrap();

        assert!(!AcceptedSignIn::new(owner, SignInDelivery::SameHost).needs_own_audience());
        assert!(AcceptedSignIn::new(owner, SignInDelivery::OwnCookie(cookie)).needs_own_audience());
        assert!(AcceptedSignIn::new(owner, SignInDelivery::Tokens).needs_own_audience());
    }

    /// A stored delivery has its own cookie on no hosts. Reading it is
    /// refused, as building it would be.
    #[cfg(feature = "serde")]
    #[test]
    fn stored_cookie_hosts_are_held_to_the_same_rules() {
        let stored = serde_json::json!({ "own_cookie": [] });

        assert!(serde_json::from_value::<SignInDelivery>(stored).is_err());
    }

    /// A delivery by its own cookie on `api.example.com` is written to JSON
    /// and read back. It comes back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn a_delivery_reads_back_what_it_writes() {
        let delivery =
            SignInDelivery::OwnCookie(CookieHosts::new(vec![host("api.example.com")]).unwrap());

        let json = serde_json::to_value(&delivery).unwrap();

        assert_eq!(
            serde_json::from_value::<SignInDelivery>(json).unwrap(),
            delivery
        );
    }
}
