//! Backends named rather than listed.
//!
//! A service normally carries the addresses of its backends. That works for a
//! fixed host, but not for a set of replicas that comes and goes. A pod that
//! moves leaves an address that answers nothing. A new pod gets no traffic
//! until somebody edits the service.
//!
//! So a service may carry a name instead, and the proxy asks what is behind
//! it. How to resolve the name belongs to an adapter. This module says only
//! what may be asked and what shape the answer takes.

use crate::shared::validation::numeric::validate_range;
use crate::shared::validation::{Charset, TextValue, ValidationError, Validator, text_value};
use crate::types::{HttpUrl, Seconds};

/// The shortest a deployment may ask the proxy to re-resolve.
///
/// Below this the proxy spends more time asking than serving. A resolver asked
/// this often by every instance in a fleet would be overloaded.
pub(crate) const MIN_REFRESH_SECS: u32 = 5;

/// The longest a deployment may leave a stale answer in place.
///
/// An hour without noticing that every replica moved is a long outage.
pub(crate) const MAX_REFRESH_SECS: u32 = 3_600;

/// What is asked of the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DiscoveryKind {
    /// `SRV` records, which carry a port and a weight per target.
    ///
    /// A service registry publishes these. It is the only kind that can
    /// describe replicas listening on different ports.
    Srv,
    /// `A` and `AAAA` records, which carry addresses only.
    ///
    /// The port comes from the service's own upstream URL, and every target
    /// is weighted equally. That is a plain round-robin over whatever the
    /// name resolves to, which is how a Kubernetes headless service reads.
    Address,
}

text_value! {
    /// A DNS name whose targets the proxy looks up.
    pub struct DiscoveryName;
}

impl TextValue for DiscoveryName {
    const FIELD: &'static str = "discovery_name";

    fn rules(check: Validator<'_>) -> Validator<'_> {
        check.identifier(
            1..=253,
            Charset::LOWERCASE
                | Charset::UPPERCASE
                | Charset::DIGIT
                | Charset::DOT
                | Charset::HYPHEN
                | Charset::UNDERSCORE,
        )
    }
}

/// How a service's backends are found, when they are not listed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Discovery {
    kind: DiscoveryKind,
    name: DiscoveryName,
    refresh_secs: Seconds,
}

/// Rebuilt through the constructor, not field by field.
///
/// A derived implementation would fill the private fields directly. Then a
/// refresh interval of zero would arrive intact from an API request or an old
/// row. So reading goes through the same checks as creating.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Discovery {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Wire {
            kind: DiscoveryKind,
            name: DiscoveryName,
            refresh_secs: Seconds,
        }

        let wire = Wire::deserialize(deserializer)?;

        Self::new(wire.kind, wire.name, wire.refresh_secs)
            .map_err(<D::Error as serde::de::Error>::custom)
    }
}

impl Discovery {
    /// A checked discovery configuration.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if `refresh_secs` is outside
    ///   `MIN_REFRESH_SECS..=MAX_REFRESH_SECS`.
    pub fn new(
        kind: DiscoveryKind,
        name: DiscoveryName,
        refresh_secs: Seconds,
    ) -> Result<Self, ValidationError> {
        validate_range(
            "refresh_secs",
            refresh_secs.get(),
            MIN_REFRESH_SECS..=MAX_REFRESH_SECS,
        )?;

        Ok(Self {
            kind,
            name,
            refresh_secs,
        })
    }

    /// What is asked of the resolver.
    #[must_use]
    pub fn kind(&self) -> DiscoveryKind {
        self.kind
    }

    /// The name to ask about.
    #[must_use]
    pub fn name(&self) -> &DiscoveryName {
        &self.name
    }

    /// How often the proxy asks the resolver again.
    #[must_use]
    pub fn refresh_secs(&self) -> Seconds {
        self.refresh_secs
    }
}

/// One backend the resolver reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredBackend {
    /// Where the backend answers.
    pub url: HttpUrl,
    /// Its share of the traffic, relative to the others in the same answer.
    pub weight: u32,
}

/// What a resolver reported for one name, at one moment.
///
/// It is a type of its own, not a bare `Vec`, so callers must face the empty
/// case by name. "The resolver answered with nothing" and "the resolver
/// could not be reached" must not look the same to a caller. The second is an
/// error, and this type only ever holds the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredBackends {
    backends: Vec<DiscoveredBackend>,
}

impl DiscoveredBackends {
    /// Wraps what a resolver reported.
    #[must_use]
    pub fn new(backends: Vec<DiscoveredBackend>) -> Self {
        Self { backends }
    }

    /// The backends, in the order the resolver gave them.
    #[must_use]
    pub fn as_slice(&self) -> &[DiscoveredBackend] {
        &self.backends
    }

    /// Whether the name resolved to nothing.
    ///
    /// This is a real state, not an error. A deployment scaled to zero
    /// replicas resolves to nothing. The proxy then refuses the route, and
    /// sends no traffic to addresses that are gone.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    /// How many backends were reported.
    #[must_use]
    pub fn len(&self) -> usize {
        self.backends.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Seconds;

    fn name(value: &str) -> DiscoveryName {
        DiscoveryName::new(value).expect("valid discovery name")
    }

    /// The SRV name `_http._tcp.orders.internal` is accepted and kept as
    /// written.
    #[test]
    fn an_srv_name_with_underscore_labels_is_accepted() {
        assert_eq!(
            name("_http._tcp.orders.internal").as_str(),
            "_http._tcp.orders.internal"
        );
    }

    /// The cluster name `orders.svc.cluster.local` is accepted and kept as
    /// written.
    #[test]
    fn a_plain_service_name_is_accepted() {
        assert_eq!(
            name("orders.svc.cluster.local").as_str(),
            "orders.svc.cluster.local"
        );
    }

    /// An empty name, or one with a space, `/..`, `;` or a newline, is
    /// refused before it reaches a resolver.
    #[test]
    fn a_name_that_is_not_a_dns_name_is_refused() {
        for invalid in [
            "",
            "orders internal",
            "orders/../etc",
            "orders;drop",
            "orders\ninternal",
        ] {
            assert!(
                DiscoveryName::new(invalid).is_err(),
                "accepted {invalid:?} as a discovery name"
            );
        }
    }

    /// A name of 254 characters is refused, one more than DNS allows.
    #[test]
    fn a_name_longer_than_dns_allows_is_refused() {
        assert!(DiscoveryName::new("a".repeat(254)).is_err());
    }

    /// SRV discovery refreshing every 30 seconds is accepted and keeps its
    /// kind and interval.
    #[test]
    fn a_refresh_interval_within_range_is_accepted() {
        let discovery = Discovery::new(
            DiscoveryKind::Srv,
            name("_http._tcp.orders"),
            Seconds::new(30),
        )
        .expect("valid discovery");

        assert_eq!(discovery.refresh_secs(), Seconds::new(30));
        assert_eq!(discovery.kind(), DiscoveryKind::Srv);
    }

    /// Refresh intervals of 0, one under the minimum and one over the
    /// maximum are refused. Too fast overloads the resolver, and too slow
    /// misses a move for too long.
    #[test]
    fn a_refresh_interval_outside_the_range_is_refused() {
        for invalid in [0, MIN_REFRESH_SECS - 1, MAX_REFRESH_SECS + 1] {
            assert!(
                Discovery::new(
                    DiscoveryKind::Srv,
                    name("_http._tcp.orders"),
                    Seconds::new(invalid)
                )
                .is_err(),
                "accepted a refresh interval of {invalid}s"
            );
        }
    }

    /// A name scaled to zero resolves to nothing. That is an empty answer of
    /// length zero, not an error, so the caller can tell it from a failed
    /// lookup.
    #[test]
    fn a_name_that_resolves_to_nothing_is_an_empty_answer_not_an_error() {
        let answer = DiscoveredBackends::new(Vec::new());

        assert!(answer.is_empty());
        assert_eq!(answer.len(), 0);
    }

    /// The resolver reports `10.0.0.1` then `10.0.0.2`. The answer keeps
    /// them in that order.
    #[test]
    fn the_reported_order_is_kept() {
        let first = DiscoveredBackend {
            url: HttpUrl::new("http://10.0.0.1:8080").expect("valid url"),
            weight: 10,
        };
        let second = DiscoveredBackend {
            url: HttpUrl::new("http://10.0.0.2:8080").expect("valid url"),
            weight: 20,
        };

        let answer = DiscoveredBackends::new(vec![first.clone(), second.clone()]);

        assert_eq!(answer.as_slice(), [first, second]);
    }

    /// An API body or a stored row names `orders internal`. Reading it is
    /// refused, so a name that is not a DNS name never reaches a resolver.
    #[cfg(feature = "serde")]
    #[test]
    fn a_name_that_is_not_a_dns_name_is_refused_on_the_way_in() {
        let refused: Result<DiscoveryName, _> = serde_json::from_str("\"orders internal\"");

        assert!(refused.is_err());
    }

    /// A stored discovery refreshes every 0 seconds. Reading it is refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_refresh_interval_outside_the_range_is_refused_on_the_way_in() {
        let refused: Result<Discovery, _> =
            serde_json::from_str(r#"{"kind":"srv","name":"_http._tcp.orders","refresh_secs":0}"#);

        assert!(refused.is_err());
    }

    /// Address discovery of `orders.internal` every 60 seconds is written to
    /// JSON and read back. It comes back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn a_valid_discovery_survives_the_round_trip() {
        let original = Discovery::new(
            DiscoveryKind::Address,
            name("orders.internal"),
            Seconds::new(60),
        )
        .expect("valid discovery");

        let encoded = serde_json::to_string(&original).expect("encode");
        let decoded: Discovery = serde_json::from_str(&encoded).expect("decode");

        assert_eq!(decoded, original);
    }

    /// An answer with one backend is not empty and counts one. An answer with
    /// none is empty and counts zero, which is when the proxy refuses the
    /// route.
    #[test]
    fn an_answer_says_how_many_backends_it_actually_carries() {
        let answered = DiscoveredBackends::new(vec![DiscoveredBackend {
            url: HttpUrl::new("https://orders-1.internal:8080").unwrap(),
            weight: 10,
        }]);
        let nothing = DiscoveredBackends::new(Vec::new());

        assert!(!answered.is_empty());
        assert_eq!(answered.len(), 1);
        assert!(nothing.is_empty());
        assert_eq!(nothing.len(), 0);
    }

    /// The name `orders.internal` prints as itself. Log lines and errors
    /// about a failed lookup show it.
    #[test]
    fn a_name_displays_as_the_name_it_holds() {
        assert_eq!(name("orders.internal").to_string(), "orders.internal");
    }
}
