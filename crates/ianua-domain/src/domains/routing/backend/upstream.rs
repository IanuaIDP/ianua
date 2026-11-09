#[cfg(feature = "serde")]
mod record;
mod rules;

use std::num::NonZeroU32;

use crate::domains::routing::backend::assertion::AssertionAudience;
use crate::domains::routing::backend::balancing::LoadBalancing;
use crate::domains::routing::backend::circuit_breaker::CircuitBreaker;
use crate::domains::routing::backend::discovery::Discovery;
use crate::domains::routing::backend::retry::RetryPolicy;
use crate::domains::routing::backend::tls::UpstreamTls;
use crate::domains::routing::connector::scope::UpstreamReach;
use crate::shared::errors::DomainError;
use crate::shared::model::two_cases::two_cases;
use crate::shared::validation::ValidationError;
use crate::shared::validation::numeric::validate_range;
use crate::types::{Audience, ConnectorId, CookieName, HeaderName, HttpUrl, Seconds, Setting};

/// How sticky sessions pin requests to backends.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", content = "value"))]
pub enum StickySession {
    /// Pin by the signed-in user's id, which the identity stage finds.
    UserId,
    /// Pin by the calling consumer's id, for machine-to-machine traffic.
    ConsumerId,
    /// Pin by a named cookie value.
    Cookie(CookieName),
    /// Pin by a named request header value.
    Header(HeaderName),
    /// Pin by client IP address.
    SourceIp,
}

/// A single backend target with a traffic weight.
///
/// Weight is relative to other backends in the same upstream. A backend with
/// weight 3 gets three times the traffic of one with weight 1.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WeightedBackend {
    /// The base URL of the backend service.
    url: HttpUrl,
    /// Relative traffic weight. A higher weight gets more traffic. Never
    /// zero, which would send the backend nothing.
    weight: NonZeroU32,
}

impl WeightedBackend {
    /// Creates a weighted backend.
    #[must_use]
    pub fn new(url: HttpUrl, weight: NonZeroU32) -> Self {
        Self { url, weight }
    }

    /// The backend service URL.
    #[must_use]
    pub fn url(&self) -> &HttpUrl {
        &self.url
    }

    /// Relative traffic weight.
    #[must_use]
    pub fn weight(&self) -> u32 {
        self.weight.get()
    }
}

/// How long the proxy waits for an upstream to answer.
///
/// It is at least a second, since a zero timeout would time out every
/// request. It is at most [`Self::MAX_SECS`]. A backend that accepts and
/// never answers must not hold a connection and its concurrency slot longer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u32", into = "u32"))]
pub struct UpstreamTimeout(NonZeroU32);

impl UpstreamTimeout {
    /// Thirty seconds, the timeout a service gets unless it asks otherwise.
    ///
    /// It is built at compile time, so the `unwrap` cannot fail at run time.
    /// A zero here would not compile.
    pub const DEFAULT: Self = Self(NonZeroU32::new(30).unwrap());

    /// The longest a proxy waits for an upstream, in seconds.
    pub const MAX_SECS: u32 = 300;

    /// A timeout of `seconds`.
    ///
    /// # Errors
    ///
    /// - [`ValidationError`] if `seconds` is zero or above [`Self::MAX_SECS`].
    pub fn seconds(seconds: u32) -> Result<Self, ValidationError> {
        validate_range("timeout_secs", seconds, 1..=Self::MAX_SECS)?;
        NonZeroU32::new(seconds)
            .map(Self)
            .ok_or(ValidationError::OutOfRange {
                field: "timeout_secs",
                min: 1,
                max: u64::from(Self::MAX_SECS),
                actual: 0,
            })
    }

    /// The timeout in whole seconds.
    #[must_use]
    pub fn as_secs(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for UpstreamTimeout {
    type Error = ValidationError;

    fn try_from(seconds: u32) -> Result<Self, Self::Error> {
        Self::seconds(seconds)
    }
}

impl From<UpstreamTimeout> for u32 {
    fn from(timeout: UpstreamTimeout) -> Self {
        timeout.as_secs()
    }
}

two_cases! {
    /// Which `Host` header a forwarded request carries. Storage keeps it as
    /// the `preserve_host` flag.
    pub enum HostHeader {
        /// The host the client asked for, for an app that answers on it.
        Preserve => true,
        /// The upstream's own host.
        Rewrite => false,
    }
}

two_cases! {
    /// Whether a backend speaks HTTP/2 on a plaintext connection. Most do
    /// not, so a stored upstream that never mentions it does not.
    #[derive(Default)]
    pub enum PlaintextHttp2 {
        /// It does, so the proxy talks h2c to it.
        Spoken => true,
        /// It does not.
        #[default]
        NotSpoken => false,
    }
}

/// Which tokens a route accepts as the caller's identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum TokenAudience {
    /// No audience is pinned, so no token identifies a caller here.
    #[default]
    NoTokenAccepted,
    /// Only tokens issued for this audience.
    Pinned(Audience),
}

/// What identity a route takes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RouteIdentity {
    /// A token, as the route's audience allows.
    #[default]
    Token,
    /// A client certificate from the mutual-TLS handshake. A token alone is
    /// not enough.
    ClientCertificate,
}

/// The backend service a route forwards requests to.
///
/// It covers the common single backend, and canary deploys over weighted
/// backends.
///
/// With no extra backends, every request goes to `url`. With extras, the
/// proxy builds a weighted pool from them and `url`, as
/// [`Upstream::effective_backends`] says.
///
/// Its settings are built one at a time, and the rules between them are
/// checked once they are all in place, by [`Upstream::ensure_consistent`].
/// The service checks it whenever it takes an upstream, and reading one
/// from storage checks it too.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "record::UpstreamRecord"))]
pub struct Upstream {
    /// The primary backend URL. Always present.
    url: HttpUrl,

    /// How long to wait for a response from the upstream.
    timeout_secs: UpstreamTimeout,

    /// Whether to pass the original `Host` header to the upstream
    /// instead of the upstream's own hostname.
    preserve_host: HostHeader,

    /// Extra weighted backends, for canary deploys and traffic splits.
    ///
    /// When non-empty, the proxy distributes traffic proportionally by
    /// weight, across these and the primary `url`. See
    /// [`Upstream::effective_backends`].
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    backends: Vec<WeightedBackend>,

    /// Where the backends come from, when they are not the ones listed here.
    ///
    /// A service pointing at replicas that come and go cannot list them. A
    /// written-down address ends up answering nothing, and a new replica gets
    /// no traffic until somebody edits the service. With this set,
    /// [`Self::url`] and [`Self::backends`] do not say where traffic goes.
    /// They serve as the fallback until the name first resolves, and give the
    /// port that an address record lacks.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Setting::is_unset"))]
    discovery: Setting<Discovery>,

    /// Sticky session configuration. When set, the proxy pins requests
    /// from the same identity to the same backend.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Setting::is_unset"))]
    sticky_session: Setting<StickySession>,

    /// Which tokens this route accepts as identity.
    ///
    /// With an audience pinned, the `aud` claim of incoming JWTs must name
    /// it. A token that does not is refused with 401. With none accepted, the
    /// proxy takes no JWT as identity. A signed-in route then refuses every
    /// token, and a public route serves the request anonymously.
    expected_audience: TokenAudience,

    /// What identity this route takes.
    ///
    /// On a client-certificate route, a bearer token does not pass the
    /// identity stage, even a valid one. Only the certificate does. The
    /// identity stage tries the certificate only when no bearer token is
    /// sent. So without this, Sam sends any token and skips the certificate
    /// check.
    identity: RouteIdentity,

    /// Whether this backend speaks HTTP/2 on a plaintext connection.
    ///
    /// Over TLS the protocol is agreed by ALPN, and nothing has to be
    /// declared. Without TLS there is no ALPN. A plaintext HTTP/2 backend,
    /// such as a gRPC service inside a mesh, is reached only by knowing in
    /// advance that it speaks HTTP/2. RFC 9113 calls that prior knowledge.
    ///
    /// It is declared, never guessed. An HTTP/2 preface sent to an HTTP/1
    /// backend breaks the connection, so a wrong guess is an outage. The one
    /// hint, `content-type: application/grpc` on the request, is the client's
    /// claim about itself, not the backend's.
    plaintext_http2: PlaintextHttp2,

    /// How the gateway opens TLS to the backends, when they are on a
    /// private PKI, answer to another name or ask for a client
    /// certificate. Unset, the gateway checks them against the public roots.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Setting::is_unset"))]
    tls: Setting<UpstreamTls>,

    /// When a failed request is tried again. Unset, it never is.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Setting::is_unset"))]
    retry: Setting<RetryPolicy>,

    /// How one backend of several is picked for each request.
    balancing: LoadBalancing,

    /// Whether failures of real traffic set a backend aside.
    circuit_breaker: CircuitBreaker,

    /// The audience the gateway's signed assertion names on requests to
    /// this service.
    assertion_audience: AssertionAudience,

    /// Whether the gateway dials the backends itself, or through the
    /// tenant's connector inside its private network.
    reach: UpstreamReach,
}

impl Upstream {
    /// Creates an upstream configuration with a single backend.
    #[must_use]
    pub fn new(url: HttpUrl, timeout_secs: UpstreamTimeout, host: HostHeader) -> Self {
        Self::with_backends(url, timeout_secs, host, Vec::new())
    }

    /// Creates an upstream with extra weighted backends, for canary deploys.
    ///
    /// An empty `backends` is accepted and behaves like [`Self::new`].
    #[must_use]
    pub fn with_backends(
        url: HttpUrl,
        timeout_secs: UpstreamTimeout,
        host: HostHeader,
        backends: Vec<WeightedBackend>,
    ) -> Self {
        Self {
            url,
            timeout_secs,
            preserve_host: host,
            backends,
            discovery: Setting::Unset,
            sticky_session: Setting::Unset,
            expected_audience: TokenAudience::NoTokenAccepted,
            identity: RouteIdentity::Token,
            plaintext_http2: PlaintextHttp2::NotSpoken,
            tls: Setting::Unset,
            retry: Setting::Unset,
            balancing: LoadBalancing::RoundRobin,
            circuit_breaker: CircuitBreaker::default(),
            assertion_audience: AssertionAudience::ServiceId,
            reach: UpstreamReach::Direct,
        }
    }

    /// Checks that upstream settings can operate together.
    ///
    /// # Errors
    /// [`DomainError::Validation`] for TLS on non-HTTPS backends, missing or forbidden
    /// sticky keys, combined retry time above [`UpstreamTimeout::MAX_SECS`], or DNS
    /// discovery through a connector whose private network the resolver cannot see.
    pub fn ensure_consistent(&self) -> Result<(), DomainError> {
        rules::check(self)
    }

    /// How the gateway opens TLS to the backends, when set.
    #[must_use]
    pub fn tls(&self) -> Option<&UpstreamTls> {
        self.tls.value()
    }

    /// Returns a new upstream opening TLS to its backends as `tls` says.
    #[must_use]
    pub fn with_tls(mut self, tls: UpstreamTls) -> Self {
        self.tls = Setting::Set(tls);
        self
    }

    /// This upstream with every setting it has but its TLS, so the gateway
    /// checks the backends against the public roots again and presents no
    /// client certificate.
    #[must_use]
    pub fn without_tls(&self) -> Self {
        Self {
            tls: Setting::Unset,
            ..self.clone()
        }
    }

    /// This upstream as a document carries it out of the platform: with no
    /// client key, and dialled directly.
    ///
    /// A client certificate's key stays sealed in the store and never
    /// leaves it, so a document can be checked into a repository. A
    /// connector's id means nothing in another environment, so it is named
    /// beside the upstream rather than inside it.
    #[must_use]
    pub fn portable(&self) -> Self {
        let tls = match self.tls.value() {
            Some(tls) => Setting::Set(tls.without_client_certificate()),
            None => Setting::Unset,
        };
        Self {
            tls,
            reach: UpstreamReach::Direct,
            ..self.clone()
        }
    }

    /// When a failed request is tried again, if ever.
    #[must_use]
    pub fn retry(&self) -> Option<&RetryPolicy> {
        self.retry.value()
    }

    /// Returns a new upstream trying failed requests again as `retry` says.
    #[must_use]
    pub fn with_retries(mut self, retry: RetryPolicy) -> Self {
        self.retry = Setting::Set(retry);
        self
    }

    /// How one backend of several is picked for each request.
    #[must_use]
    pub fn balancing(&self) -> LoadBalancing {
        self.balancing
    }

    /// Returns a new upstream picking its backends as `balancing` says.
    #[must_use]
    pub fn with_balancing(mut self, balancing: LoadBalancing) -> Self {
        self.balancing = balancing;
        self
    }

    /// Whether failures of real traffic set a backend aside.
    #[must_use]
    pub fn circuit_breaker(&self) -> CircuitBreaker {
        self.circuit_breaker
    }

    /// Returns a new upstream whose backends are set aside as `breaker`
    /// says.
    #[must_use]
    pub fn with_circuit_breaker(mut self, breaker: CircuitBreaker) -> Self {
        self.circuit_breaker = breaker;
        self
    }

    /// The audience the gateway's signed assertion names here.
    #[must_use]
    pub fn assertion_audience(&self) -> &AssertionAudience {
        &self.assertion_audience
    }

    /// Returns a new upstream whose assertions name `audience`.
    #[must_use]
    pub fn with_assertion_audience(mut self, audience: AssertionAudience) -> Self {
        self.assertion_audience = audience;
        self
    }

    /// Whether the gateway dials the backends itself or through a
    /// connector.
    #[must_use]
    pub fn reach(&self) -> UpstreamReach {
        self.reach
    }

    /// Returns a new upstream reached through the connector `connector`.
    #[must_use]
    pub fn through_connector(mut self, connector: ConnectorId) -> Self {
        self.reach = UpstreamReach::Connector(connector);
        self
    }

    /// The primary backend service URL.
    #[must_use]
    pub fn url(&self) -> &HttpUrl {
        &self.url
    }

    /// How long to wait for a response, in seconds.
    #[must_use]
    pub fn timeout_secs(&self) -> Seconds {
        Seconds::new(self.timeout_secs.as_secs())
    }

    /// Whether to forward the original `Host` header.
    #[must_use]
    pub fn preserve_host(&self) -> bool {
        self.preserve_host == HostHeader::Preserve
    }

    /// Finds this upstream's backends by name instead of by address.
    #[must_use]
    pub fn with_discovery(mut self, discovery: Discovery) -> Self {
        self.discovery = Setting::Set(discovery);
        self
    }

    /// How the backends are found, when they are not the ones listed.
    #[must_use]
    pub fn discovery(&self) -> Option<&Discovery> {
        self.discovery.value()
    }

    /// The port an address record cannot carry.
    ///
    /// `A` and `AAAA` records name a host and nothing else. So the port comes
    /// from the URL configured on the upstream, the one an operator wrote
    /// when setting the service up.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.url.port()
    }

    /// The extra weighted backends. Empty for a single backend.
    #[must_use]
    pub fn backends(&self) -> &[WeightedBackend] {
        &self.backends
    }

    /// Whether this upstream splits traffic across weighted backends.
    #[must_use]
    pub fn is_canary(&self) -> bool {
        !self.backends.is_empty()
    }

    /// Sticky session configuration, if any.
    #[must_use]
    pub fn sticky_session(&self) -> Option<&StickySession> {
        self.sticky_session.value()
    }

    /// Returns a new upstream with sticky sessions enabled.
    #[must_use]
    pub fn with_sticky(mut self, sticky: StickySession) -> Self {
        self.sticky_session = Setting::Set(sticky);
        self
    }

    /// Which tokens this route accepts as identity.
    #[must_use]
    pub fn token_audience(&self) -> &TokenAudience {
        &self.expected_audience
    }

    /// The audience a token must name here, when one is pinned.
    #[must_use]
    pub fn expected_audience(&self) -> Option<&Audience> {
        let TokenAudience::Pinned(audience) = &self.expected_audience else {
            return None;
        };
        Some(audience)
    }

    /// Returns a new upstream with an expected JWT audience.
    #[must_use]
    pub fn with_audience(mut self, audience: Audience) -> Self {
        self.expected_audience = TokenAudience::Pinned(audience);
        self
    }

    /// What identity this route takes.
    #[must_use]
    pub fn identity(&self) -> RouteIdentity {
        self.identity
    }

    /// Whether this route requires client-certificate authentication.
    #[must_use]
    pub fn requires_client_certificate(&self) -> bool {
        self.identity == RouteIdentity::ClientCertificate
    }

    /// Returns a new upstream that requires client-certificate
    /// authentication.
    #[must_use]
    pub fn with_required_client_certificate(mut self) -> Self {
        self.identity = RouteIdentity::ClientCertificate;
        self
    }

    /// Whether this backend speaks HTTP/2 without negotiating it.
    #[must_use]
    pub fn speaks_plaintext_http2(&self) -> bool {
        self.plaintext_http2 == PlaintextHttp2::Spoken
    }

    /// Returns a new upstream opened with HTTP/2 by prior knowledge.
    #[must_use]
    pub fn with_plaintext_http2(mut self) -> Self {
        self.plaintext_http2 = PlaintextHttp2::Spoken;
        self
    }

    /// Every backend traffic is spread across, with its weight.
    ///
    /// The primary URL always takes part. With no extra backends it is the
    /// only one, at weight 1. With extras, it joins them at
    /// [`Self::PRIMARY_WEIGHT`]. If it is listed among them, the weight given
    /// there is its weight. So a service at `a` with `b` weighted 10 sends
    /// about one request in eleven to `b`.
    #[must_use]
    pub fn effective_backends(&self) -> Vec<WeightedBackend> {
        let primary_listed = self.backends.iter().any(|b| b.url == self.url);
        if primary_listed {
            return self.backends.clone();
        }
        let primary_weight = if self.backends.is_empty() {
            NonZeroU32::MIN
        } else {
            Self::PRIMARY_WEIGHT
        };
        std::iter::once(WeightedBackend::new(self.url.clone(), primary_weight))
            .chain(self.backends.iter().cloned())
            .collect()
    }

    /// The weight the primary URL carries next to extra backends, when it is
    /// not listed among them with one of its own.
    ///
    /// It is built at compile time, so the `unwrap` cannot fail at run time.
    /// A zero here would not compile.
    pub const PRIMARY_WEIGHT: NonZeroU32 = NonZeroU32::new(100).unwrap();

    /// Every URL this upstream could send tenant traffic to. That is the
    /// primary URL and then each weighted backend, repeats kept.
    #[must_use]
    pub fn all_target_urls(&self) -> Vec<&HttpUrl> {
        std::iter::once(&self.url)
            .chain(self.backends.iter().map(WeightedBackend::url))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::routing::backend::tls::{
        UpstreamClientCertificate, UpstreamTlsParams, UpstreamTrust,
    };
    use crate::types::{CertificatePem, DomainName, SealedSecret, Seconds};

    fn url(s: &str) -> HttpUrl {
        HttpUrl::new(s).unwrap()
    }

    /// A single-backend upstream with the default timeout keeps its URL,
    /// waits 30 seconds, rewrites the host and splits no traffic.
    #[test]
    fn a_new_upstream_rewrites_the_host_and_is_no_canary() {
        let u = Upstream::new(
            url("https://api.internal:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        );
        assert_eq!(u.url().as_str(), "https://api.internal:8080");
        assert_eq!(u.timeout_secs(), Seconds::new(30));
        assert!(!u.preserve_host());
        assert!(!u.is_canary());
    }

    /// An upstream at plain `http://localhost:3000` is accepted, and keeps
    /// the client's `Host` header when asked to.
    #[test]
    fn http_upstreams_can_preserve_the_host() {
        let u = Upstream::new(
            url("http://localhost:3000"),
            UpstreamTimeout::seconds(10).unwrap(),
            HostHeader::Preserve,
        );
        assert!(u.preserve_host());
    }

    /// An upstream with no extra backends sends all traffic to its URL, as
    /// one backend at weight 1.
    #[test]
    fn single_backend_effective() {
        let u = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        );
        let backends = u.effective_backends();
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].url().as_str(), "http://a:8080");
        assert_eq!(backends[0].weight(), 1);
    }

    /// The primary `a` is listed at 90 beside `b` at 10. The pool holds those
    /// two at those weights, and `a` is not added a second time.
    #[test]
    fn canary_with_weighted_backends() {
        let u = Upstream::with_backends(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
            vec![
                WeightedBackend::new(url("http://a:8080"), NonZeroU32::new(90).unwrap()),
                WeightedBackend::new(url("http://b:8080"), NonZeroU32::new(10).unwrap()),
            ],
        );
        assert!(u.is_canary());
        let backends = u.effective_backends();
        assert_eq!(backends.len(), 2);
        assert_eq!(backends[0].weight(), 90);
        assert_eq!(backends[1].weight(), 10);
    }

    /// `shop` has one extra backend, `shop-v2` at 10, and is not listed
    /// itself. The pool holds `shop` at the primary weight, then `shop-v2`.
    #[test]
    fn the_primary_url_shares_traffic_with_extra_backends() {
        let u = Upstream::with_backends(
            url("http://shop:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
            vec![WeightedBackend::new(
                url("http://shop-v2:8080"),
                NonZeroU32::new(10).unwrap(),
            )],
        );

        let backends = u.effective_backends();

        assert_eq!(backends.len(), 2);
        assert_eq!(backends[0].url().as_str(), "http://shop:8080");
        assert_eq!(backends[0].weight(), Upstream::PRIMARY_WEIGHT.get());
        assert_eq!(backends[1].weight(), 10);
    }

    /// A timeout of zero seconds is refused, since it would time out every
    /// request. One second is accepted.
    #[test]
    fn a_zero_timeout_is_refused() {
        assert!(UpstreamTimeout::seconds(0).is_err());
        assert_eq!(UpstreamTimeout::seconds(1).unwrap().as_secs(), 1);
    }

    /// The maximum timeout is accepted; one second above it and the largest
    /// `u32` value are refused.
    #[test]
    fn a_timeout_beyond_the_cap_is_refused() {
        assert!(UpstreamTimeout::seconds(UpstreamTimeout::MAX_SECS).is_ok());
        assert!(UpstreamTimeout::seconds(UpstreamTimeout::MAX_SECS + 1).is_err());
        assert!(UpstreamTimeout::seconds(u32::MAX).is_err());
    }

    /// One stored upstream has a zero timeout, and another a backend of
    /// weight zero. Reading either is refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_upstream_with_a_zero_timeout_or_weight_is_refused() {
        let zero_timeout = r#"{"url":"http://a:8080","timeout_secs":0,"preserve_host":false}"#;
        let zero_weight = r#"{"url":"http://a:8080","timeout_secs":30,"preserve_host":false,"backends":[{"url":"http://b:8080","weight":0}]}"#;

        assert!(serde_json::from_str::<Upstream>(zero_timeout).is_err());
        assert!(serde_json::from_str::<Upstream>(zero_weight).is_err());
    }

    /// A backend made at `canary:8080` with weight 25 reports both.
    #[test]
    fn canary_backend_accessors() {
        let b = WeightedBackend::new(url("http://canary:8080"), NonZeroU32::new(25).unwrap());
        assert_eq!(b.url().as_str(), "http://canary:8080");
        assert_eq!(b.weight(), 25);
    }

    /// An upstream built with an empty list of extra backends splits no
    /// traffic.
    #[test]
    fn empty_backends_is_not_canary() {
        let u = Upstream::with_backends(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
            vec![],
        );
        assert!(!u.is_canary());
    }

    /// A single-backend upstream is written to JSON with no `backends` field
    /// and read back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_single() {
        let u = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        );
        let json = serde_json::to_string(&u).unwrap();
        assert!(!json.contains("backends"));
        let u2: Upstream = serde_json::from_str(&json).unwrap();
        assert_eq!(u, u2);
    }

    /// A canary upstream is written to JSON with its `backends` and read back
    /// equal.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_canary() {
        let u = Upstream::with_backends(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
            vec![
                WeightedBackend::new(url("http://a:8080"), NonZeroU32::new(90).unwrap()),
                WeightedBackend::new(url("http://b:8080"), NonZeroU32::new(10).unwrap()),
            ],
        );
        let json = serde_json::to_string(&u).unwrap();
        assert!(json.contains("backends"));
        let u2: Upstream = serde_json::from_str(&json).unwrap();
        assert_eq!(u, u2);
    }

    /// An upstream pinned by user id reports that sticky setting.
    #[test]
    fn sticky_session_user_id() {
        let u = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
        .with_sticky(StickySession::UserId);
        assert_eq!(u.sticky_session(), Some(&StickySession::UserId));
    }

    /// An upstream pinned by the `session_id` cookie reports that cookie
    /// name.
    #[test]
    fn sticky_session_cookie() {
        let u = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
        .with_sticky(StickySession::Cookie(
            CookieName::new("session_id").unwrap(),
        ));
        assert!(
            matches!(u.sticky_session(), Some(StickySession::Cookie(c)) if c.as_str() == "session_id")
        );
    }

    /// A single-backend upstream can send traffic only to its own URL.
    #[test]
    fn all_target_urls_single_backend() {
        let u = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        );
        let urls: Vec<&str> = u.all_target_urls().iter().map(|u| u.as_str()).collect();
        assert_eq!(urls, vec!["http://a:8080"]);
    }

    /// A canary upstream at `a`, listing `a` and `b`, names `a`, `a` and `b`
    /// as targets. So every URL that may get traffic can be checked.
    #[test]
    fn all_target_urls_includes_every_canary_backend() {
        let u = Upstream::with_backends(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
            vec![
                WeightedBackend::new(url("http://a:8080"), NonZeroU32::new(90).unwrap()),
                WeightedBackend::new(url("http://b:8080"), NonZeroU32::new(10).unwrap()),
            ],
        );
        let urls: Vec<&str> = u.all_target_urls().iter().map(|u| u.as_str()).collect();
        assert_eq!(
            urls,
            vec!["http://a:8080", "http://a:8080", "http://b:8080"]
        );
    }

    /// A new upstream has no sticky sessions.
    #[test]
    fn no_sticky_by_default() {
        let u = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        );
        assert!(u.sticky_session().is_none());
    }

    /// An upstream pinned by the `x-session` header is written to JSON with
    /// its `sticky_session` and read back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_sticky() {
        let u = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
        .with_sticky(StickySession::Header(HeaderName::new("x-session").unwrap()));
        let json = serde_json::to_string(&u).unwrap();
        assert!(json.contains("sticky_session"));
        let u2: Upstream = serde_json::from_str(&json).unwrap();
        assert_eq!(u, u2);
    }

    /// A stored upstream has no `sticky_session` field. It reads back with
    /// no sticky sessions.
    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_without_sticky_field() {
        let json = r#"{"url":"http://a:8080","timeout_secs":30,"preserve_host":false,"expected_audience":"no_token_accepted","identity":"token"}"#;
        let u: Upstream = serde_json::from_str(json).unwrap();
        assert!(u.sticky_session().is_none());
    }

    /// A stored upstream has no `backends` field. It reads back as a single
    /// backend at its URL.
    #[cfg(feature = "serde")]
    #[test]
    fn deserialize_without_backends_field() {
        let json = r#"{"url":"http://a:8080","timeout_secs":30,"preserve_host":false,"expected_audience":"no_token_accepted","identity":"token"}"#;
        let u: Upstream = serde_json::from_str(json).unwrap();
        assert!(!u.is_canary());
        assert_eq!(u.url().as_str(), "http://a:8080");
    }

    /// Stored upstream settings without audience and identity fields fail
    /// deserialization.
    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_route_missing_its_identity_rules_does_not_load() {
        let json = r#"{"url":"http://a:8080","timeout_secs":30,"preserve_host":false}"#;

        assert!(serde_json::from_str::<Upstream>(json).is_err());
    }

    /// A plain upstream needs no client certificate and does not open with
    /// HTTP/2. One built asking for both reports both.
    #[test]
    fn client_certificates_and_plaintext_http2_are_only_on_when_asked_for() {
        let plain = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        );

        assert!(!plain.requires_client_certificate());
        assert!(!plain.speaks_plaintext_http2());

        let hardened = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
        .with_required_client_certificate()
        .with_plaintext_http2();

        assert!(hardened.requires_client_certificate());
        assert!(hardened.speaks_plaintext_http2());
    }

    /// Upstreams at `a:8080` and `api.internal:8443` report ports 8080 and
    /// 8443. Backends found through address records are dialled on that
    /// port.
    #[test]
    fn a_resolved_backend_is_dialled_on_the_configured_port() {
        assert_eq!(
            Upstream::new(
                url("http://a:8080"),
                UpstreamTimeout::DEFAULT,
                HostHeader::Rewrite
            )
            .port(),
            8080
        );
        assert_eq!(
            Upstream::new(
                url("https://api.internal:8443"),
                UpstreamTimeout::DEFAULT,
                HostHeader::Rewrite
            )
            .port(),
            8443
        );
    }

    /// A plain upstream has no discovery. One given discovery of
    /// `orders.internal` reports exactly that setting.
    #[test]
    fn an_upstream_reports_the_discovery_it_was_given() {
        let plain = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        );
        assert!(plain.discovery().is_none());

        let discovery = Discovery::new(
            crate::domains::routing::backend::discovery::DiscoveryKind::Address,
            crate::domains::routing::backend::discovery::DiscoveryName::new("orders.internal")
                .unwrap(),
            Seconds::new(60),
        )
        .unwrap();
        let resolved = Upstream::new(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
        .with_discovery(discovery.clone());

        assert_eq!(resolved.discovery(), Some(&discovery));
    }

    /// A canary upstream lists `stable` at 90 and `canary` at 10. It reports
    /// both, so the split is not lost.
    #[test]
    fn a_canary_upstream_reports_every_weighted_backend() {
        let u = Upstream::with_backends(
            url("http://a:8080"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
            vec![
                WeightedBackend::new(url("http://stable:8080"), NonZeroU32::new(90).unwrap()),
                WeightedBackend::new(url("http://canary:8080"), NonZeroU32::new(10).unwrap()),
            ],
        );

        assert_eq!(u.backends().len(), 2);
        assert_eq!(u.backends()[1].url().as_str(), "http://canary:8080");
        assert_eq!(u.backends()[1].weight(), 10);
    }

    /// The payroll upstream, opening TLS with a client certificate to
    /// `payroll.internal`, its key sealed.
    fn payroll_with_client_tls() -> Upstream {
        let tls = UpstreamTls::new(UpstreamTlsParams {
            trust: UpstreamTrust::PublicRoots,
            client_certificate: Setting::Set(UpstreamClientCertificate::new(
                CertificatePem::new(
                    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                )
                .unwrap(),
                SealedSecret::new("v1.sealed-client-key").unwrap(),
            )),
            server_name: Setting::Set(DomainName::new("payroll.internal").unwrap()),
        })
        .unwrap();
        Upstream::new(
            url("https://payroll:8443"),
            UpstreamTimeout::DEFAULT,
            HostHeader::Rewrite,
        )
        .with_balancing(LoadBalancing::LeastConnections)
        .with_tls(tls)
    }

    /// Ann drops the payroll service's TLS settings. Every other setting
    /// stays, and the gateway opens TLS against the public roots again.
    #[test]
    fn dropping_tls_keeps_every_other_setting() {
        let upstream = payroll_with_client_tls();

        let plain = upstream.without_tls();

        assert!(plain.tls().is_none());
        assert_eq!(plain.balancing(), LoadBalancing::LeastConnections);
        assert_eq!(plain.url(), upstream.url());
    }

    /// A portable upstream retains its TLS server name and removes the
    /// client certificate containing the sealed key.
    #[test]
    fn a_portable_upstream_carries_no_client_key() {
        let upstream = payroll_with_client_tls();

        let carried = upstream.portable();

        let tls = carried.tls().unwrap();
        assert!(tls.client_certificate().is_none());
        assert_eq!(tls.server_name(), upstream.tls().unwrap().server_name());
    }

    /// The payroll service is reached through a connector. Its portable
    /// form dials directly, since a connector's id means nothing elsewhere,
    /// and every other setting comes through as it was.
    #[test]
    fn a_portable_upstream_is_dialled_directly() {
        let upstream = payroll_with_client_tls().without_tls();
        let through = upstream.clone().through_connector(ConnectorId::new());

        assert_eq!(through.portable(), upstream);
    }
}
