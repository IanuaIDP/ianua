//! The runner: the only way out of an agent's sandbox.
//!
//! An agent runs where nothing routes anywhere but its runner. The runner
//! holds the agent's key and its task tokens, so the agent holds nothing
//! worth taking. For each request the agent sends it, the runner drops
//! every header that could carry an identity or a credential, attaches the
//! task token the request's destination takes, and for the gateway a fresh
//! proof of possession signed with the agent's key for this request alone.
//! These are the rules it does that by: where a request goes, which of the
//! agent's headers cross, which of the answer's stay behind, what a proof
//! names, and when a key and a token are renewed.

use time::{Duration, OffsetDateTime};

use crate::domains::agents::authority::capability::TokenBinding;
use crate::domains::messaging::topic_name::TopicName;
use crate::shared::errors::DomainError;
use crate::types::DomainName;

/// The path under which the agent publishes to and reads from its topics.
pub(crate) const RELAY_PREFIX: &str = "/_ianua/messages/";

/// How long an assertion the runner signs for a token exchange is good
/// for: long enough to reach the token endpoint, too short to be worth
/// stealing.
pub const ASSERTION_LIFETIME: Duration = Duration::seconds(60);

/// The most a task token is renewed ahead of its end.
const MOST_TOKEN_MARGIN: Duration = Duration::seconds(60);

/// Request headers that describe the request and nothing else.
///
/// Headers cross on an allowlist, not a blocklist: a header nobody thought
/// of is one an agent could carry an identity or a credential past the
/// runner in.
pub(crate) const CROSSING_HEADERS: [&str; 16] = [
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "content-encoding",
    "content-language",
    "content-length",
    "content-type",
    "idempotency-key",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
    "range",
    "traceparent",
    "tracestate",
];

/// Answer headers the agent is never handed: a session it held would be a
/// credential inside the sandbox.
const WITHHELD_HEADERS: [&str; 2] = ["set-cookie", "set-cookie2"];

/// Where a request from the agent goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerDestination {
    /// The gateway, which the request's path addresses on the tenant's host.
    Gateway,
    /// The message relay, for this topic.
    Relay(TopicName),
}

impl RunnerDestination {
    /// Where a request for `path`, without its query, goes.
    ///
    /// The topic lands in an address on the platform's API, so anything
    /// but a plain topic name could walk that address out of the relay to
    /// another endpoint, carrying the agent's token with it.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for a relay path that names no topic.
    pub fn of(path: &str) -> Result<Self, DomainError> {
        let Some(topic) = path.strip_prefix(RELAY_PREFIX) else {
            return Ok(Self::Gateway);
        };
        Ok(Self::Relay(TopicName::new(topic)?))
    }

    /// How the token this destination takes is held to the agent's key.
    ///
    /// The gateway takes a token bound to the key, with a proof made for
    /// each request. The relay has no request a proof could name and
    /// refuses a bound token rather than ignore the binding, so it takes a
    /// bearer token.
    #[must_use]
    pub fn token_binding(&self) -> TokenBinding {
        match self {
            Self::Gateway => TokenBinding::ProofOfPossession,
            Self::Relay(_) => TokenBinding::Bearer,
        }
    }
}

/// Whether the agent's request header `name` crosses to the destination.
#[must_use]
pub fn crosses(name: &str) -> bool {
    CROSSING_HEADERS
        .iter()
        .any(|listed| listed.eq_ignore_ascii_case(name))
}

/// Whether the answer header `name` stays with the runner.
#[must_use]
pub fn is_withheld(name: &str) -> bool {
    WITHHELD_HEADERS
        .iter()
        .any(|listed| listed.eq_ignore_ascii_case(name))
}

/// How the runner reaches the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayTransport {
    /// Over TLS, which the gateway or a proxy in front of it ends.
    Tls,
    /// In the clear, for a gateway beside the runner in development.
    Plain,
}

/// The gateway as the agent's requests address it: the tenant's host, and
/// how the runner reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayAddress {
    host: DomainName,
    transport: GatewayTransport,
}

impl GatewayAddress {
    /// The gateway serving `host`, reached over `transport`.
    #[must_use]
    pub fn new(host: DomainName, transport: GatewayTransport) -> Self {
        Self { host, transport }
    }

    /// The tenant's host the requests name.
    #[must_use]
    pub fn host(&self) -> &DomainName {
        &self.host
    }

    /// The address a proof of possession for `path_and_query` names
    /// (`htu`), as the gateway sees the request: the scheme it arrives
    /// over, the tenant's host and the path, never the query or a fragment
    /// (RFC 9449 section 4.2).
    #[must_use]
    pub fn proof_target(&self, path_and_query: &str) -> String {
        let scheme = match self.transport {
            GatewayTransport::Tls => "https",
            GatewayTransport::Plain => "http",
        };
        let path = path_and_query.split(['?', '#']).next().unwrap_or("/");
        format!("{scheme}://{}{path}", self.host.as_str())
    }
}

/// When to attest again for a key that expires at `expires_at`, held from
/// `now`: halfway to its end, so a slow or refused attempt still leaves
/// time to try again before the key stops working.
#[must_use]
pub fn key_renewal(now: OffsetDateTime, expires_at: OffsetDateTime) -> OffsetDateTime {
    let left = expires_at
        .unix_timestamp()
        .saturating_sub(now.unix_timestamp())
        .max(0);
    now.saturating_add(Duration::seconds(left / 2))
}

/// When to exchange again for a task token issued at `issued_at` and
/// living `lifetime`: a fifth of its life early, at most a minute early, so
/// a token is never sent in its last moments.
#[must_use]
pub fn token_renewal(issued_at: OffsetDateTime, lifetime: Duration) -> OffsetDateTime {
    let fifth = Duration::seconds(lifetime.whole_seconds() / 5);
    let margin = std::cmp::min(fifth, MOST_TOKEN_MARGIN);
    issued_at.saturating_add(lifetime).saturating_sub(margin)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(seconds)
    }

    /// A message to `orders.created` goes to the relay with a bearer
    /// token; every other path goes to the gateway with a bound one.
    #[test]
    fn messages_go_to_the_relay_and_everything_else_to_the_gateway() {
        let relay = RunnerDestination::of("/_ianua/messages/orders.created").unwrap();
        let gateway = RunnerDestination::of("/reports/5").unwrap();

        assert_eq!(
            relay,
            RunnerDestination::Relay(TopicName::new("orders.created").unwrap())
        );
        assert_eq!(relay.token_binding(), TokenBinding::Bearer);
        assert_eq!(gateway, RunnerDestination::Gateway);
        assert_eq!(gateway.token_binding(), TokenBinding::ProofOfPossession);
    }

    /// Relay paths containing traversal, slashes, encoded separators, an
    /// empty topic or an empty segment are refused as invalid input.
    #[test]
    fn a_topic_that_is_no_plain_name_is_refused() {
        for path in [
            "/_ianua/messages/../../../signup",
            "/_ianua/messages/a/b",
            "/_ianua/messages/a%2F..%2Fb",
            "/_ianua/messages/",
            "/_ianua/messages/a..b",
        ] {
            assert!(
                matches!(RunnerDestination::of(path), Err(DomainError::Validation(_))),
                "{path}"
            );
        }
    }

    /// Identity, credential and host headers cannot cross the runner.
    /// Content-Type and Accept remain allowed request headers.
    #[test]
    fn identity_and_credentials_never_cross() {
        for name in [
            "authorization",
            "cookie",
            "dpop",
            "x-api-key",
            "x-forwarded-user",
            "x-ianua-assertion",
            "host",
        ] {
            assert!(!crosses(name), "{name}");
        }
        assert!(crosses("Content-Type"));
        assert!(crosses("accept"));
    }

    /// Set-Cookie is withheld from the agent, while Content-Type is not.
    #[test]
    fn the_agent_is_handed_no_session() {
        assert!(is_withheld("Set-Cookie"));
        assert!(!is_withheld("content-type"));
    }

    /// A proof names the scheme the gateway sees, the tenant's host and the
    /// path, without the query.
    #[test]
    fn a_proof_names_the_scheme_host_and_path_without_the_query() {
        let host = DomainName::new("api.acme.test").unwrap();
        let tls = GatewayAddress::new(host.clone(), GatewayTransport::Tls);
        let plain = GatewayAddress::new(host, GatewayTransport::Plain);

        assert_eq!(
            tls.proof_target("/reports/5?month=1#top"),
            "https://api.acme.test/reports/5"
        );
        assert_eq!(
            plain.proof_target("/reports"),
            "http://api.acme.test/reports"
        );
    }

    /// A key good for ten minutes is renewed after five; one already past
    /// its end is renewed at once.
    #[test]
    fn a_key_is_renewed_halfway_to_its_end() {
        assert_eq!(key_renewal(at(1_000), at(1_600)), at(1_300));
        assert_eq!(key_renewal(at(1_000), at(900)), at(1_000));
    }

    /// A ten-minute token is renewed a minute early, a hundred-second one
    /// twenty seconds early.
    #[test]
    fn a_token_is_renewed_before_its_last_moments() {
        assert_eq!(token_renewal(at(0), Duration::seconds(600)), at(540));
        assert_eq!(token_renewal(at(0), Duration::seconds(100)), at(80));
    }
}
