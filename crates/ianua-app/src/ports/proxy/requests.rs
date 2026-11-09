//! What the proxy records and analyses about each request.

use std::net::IpAddr;

use async_trait::async_trait;
use ianua_domain::domains::data_classification::level::DataClassLevel;
use ianua_domain::domains::proxy::observation::{
    ObservedPrincipal, RequestObservation, RequestOutcome, RouteMatch, RulingPolicy, TunnelClose,
};
use ianua_domain::domains::proxy::request::graphql::GraphQlOperation;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{CorrelationId, Fact, TenantId, UntrustedText};
use time::OffsetDateTime;

/// A single proxied request, reduced to what the access log records.
///
/// The proxy adapter builds this with [`ProxyRequestRecord::of`] from a
/// finished request's observation and hands it to a [`ProxyAccessLogSink`].
/// Only a request that resolved a tenant gets one. It carries only the facts
/// the proxy observes; the zero-trust context columns are filled with
/// defaults by the sink, since the proxy does not compute them. A
/// [`ProxyRequestLog`](crate::ports::proxy::ProxyRequestLog) reads the
/// records back.
#[derive(Debug, Clone)]
pub struct ProxyRequestRecord {
    /// The tenant the request was routed to.
    pub tenant_id: TenantId,
    /// Correlation id linking this row to logs and traces.
    pub correlation_id: CorrelationId,
    /// Who the proxy decided was asking.
    ///
    /// The person column takes only a tenant user directly behind the
    /// request. One hop down a delegation chain the delegator is another
    /// agent, and writing that there would put a machine's id in a column
    /// named for a person.
    pub principal: ObservedPrincipal,
    /// The route that served the request and the service behind it, or that
    /// none did.
    ///
    /// No route for a request rejected before route matching, such as an
    /// unresolved tenant or a path no route claims. That is exactly the
    /// traffic a per-route rollup must not attribute to a route.
    pub route: RouteMatch,
    /// The client's IP address.
    pub ip_address: IpAddr,
    /// The HTTP method as it arrived.
    pub method: UntrustedText,
    /// The request path as it arrived.
    pub path: UntrustedText,
    /// What the proxy decided: forwarded with the upstream's status, or
    /// refused with the status, the reason, the check that refused it and
    /// the rule it was refused under.
    pub outcome: RequestOutcome,
    /// How long the request took to process, in milliseconds.
    pub duration_ms: u32,
    /// When the request completed.
    pub occurred_at: OffsetDateTime,
    /// The data classification levels the `DataClassify` stage found on
    /// this request, highest first. Empty when no such stage ran or it found
    /// nothing to classify.
    pub classification: Vec<DataClassLevel>,
    /// The version of the tenant's policy that ruled on the request, if
    /// one did. With the route, it names the policy that decided.
    pub policy: RulingPolicy,
    /// How the gateway closed the connection the request upgraded, when it
    /// did because the caller's access ended, a check of it failed or the
    /// credential ran out. Filled by a later write of the same record.
    pub closed: Option<TunnelClose>,
}

impl ProxyRequestRecord {
    /// The record of `observation`, or `None` when the request never
    /// resolved a tenant, so no tenant's log may hold it.
    #[must_use]
    pub fn of(observation: &RequestObservation) -> Option<Self> {
        let Fact::Known(tenant_id) = observation.tenant_id else {
            return None;
        };
        Some(Self {
            tenant_id,
            correlation_id: observation.correlation_id,
            principal: observation.principal,
            route: observation.route,
            ip_address: observation.client,
            method: observation.method.clone(),
            path: observation.path.as_text().clone(),
            outcome: observation.outcome.clone(),
            duration_ms: u32::try_from(observation.latency.whole_milliseconds())
                .unwrap_or(u32::MAX),
            occurred_at: observation.occurred_at,
            classification: observation.classification.clone(),
            policy: observation.policy,
            closed: None,
        })
    }

    /// Whether the policy pipeline let the request through.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self.outcome, RequestOutcome::Allowed { .. })
    }

    /// The status returned to the client, as [`RequestOutcome::status`]
    /// reads it.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.outcome.status()
    }
}

/// Reads a GraphQL request body into something a gateway can act on.
///
/// Synchronous: parsing is work, not waiting, and a port that returned a
/// future here would invite an implementation that goes and asks something,
/// which on this path would be a network call per request.
pub trait GraphQlAnalyzer: Send + Sync {
    /// Reads the operation `body` describes.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Validation`] if the body is not a GraphQL
    /// request the proxy can read. A body it cannot read is refused rather
    /// than forwarded uncosted: costing is the whole control, and a caller
    /// able to skip it by sending something malformed has skipped it.
    fn analyze(&self, body: &[u8]) -> Result<GraphQlOperation, DomainError>;
}

/// Persists proxied-request records for the organization usage metrics.
///
/// Failure is non-fatal: the proxy records out of band and must never fail
/// a request because the sink is unavailable. The gateway gathers records
/// in a bounded batcher and hands each batch to
/// [`write_batch`](Self::write_batch), logging rather than propagating
/// errors.
#[async_trait]
pub trait ProxyAccessLogSink: Send + Sync {
    /// Records `records`, many at once. An empty batch writes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the underlying store rejects the write.
    /// Records of other tenants in the same batch may have been written.
    async fn write_batch(&self, records: &[ProxyRequestRecord]) -> Result<(), DomainError>;

    /// Records one proxied request.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the underlying store rejects the write.
    async fn record(&self, record: ProxyRequestRecord) -> Result<(), DomainError> {
        self.write_batch(std::slice::from_ref(&record)).await
    }
}
