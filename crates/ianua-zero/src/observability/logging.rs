//! One structured log line per finished request: who asked, for what,
//! what was decided, by which check and under which rule, and the
//! correlation id tying it to the request record and the trace.
//!
//! The destination every deployment has without configuring anything.
//! Decisions are in it; tokens never are, since the observation holds none
//! and the path was cut at its query string when the request arrived.

use ianua_app::ports::runtime::RequestObserver;
use ianua_domain::domains::proxy::observation::{
    DecidingRule, ObservedPrincipal, RequestObservation, RequestOutcome, RouteMatch, Traced,
};

/// Writes each finished request as a `tracing` event.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct StructuredLog;

impl RequestObserver for StructuredLog {
    fn observe(&self, observation: &RequestObservation) {
        let line = Line::of(observation);
        match &observation.outcome {
            RequestOutcome::Allowed { upstream_status } => {
                line.allow(observation, *upstream_status)
            }
            RequestOutcome::Denied { .. } => line.deny(observation),
            RequestOutcome::Undecided => line.refuse_undecided(observation),
        }
    }
}

impl Line {
    /// Records the backend status of an admitted request.
    fn allow(&self, observation: &RequestObservation, upstream_status: u16) {
        tracing::info!(
                correlation_id = %observation.correlation_id,
                tenant_id = self.tenant.as_deref(),
                route_id = self.route.as_deref(),
                subject = self.subject,
                subject_id = self.subject_id.as_deref(),
                method = observation.method.as_str(),
                path = observation.path.as_str(),
                client = %observation.client,
                decision = "allowed",
                status = upstream_status,
                latency_ms = self.latency_ms,
                trace_id = self.trace_id.as_deref(),
                "request forwarded"
        );
    }

    /// Records the check and rule that refused a request.
    fn deny(&self, observation: &RequestObservation) {
        let RequestOutcome::Denied {
            status,
            reason,
            decided_by,
            rule,
        } = &observation.outcome
        else {
            return;
        };
        tracing::warn!(
                correlation_id = %observation.correlation_id,
                tenant_id = self.tenant.as_deref(),
                route_id = self.route.as_deref(),
                subject = self.subject,
                subject_id = self.subject_id.as_deref(),
                method = observation.method.as_str(),
                path = observation.path.as_str(),
                client = %observation.client,
                decision = "denied",
                status,
                reason = reason.as_str(),
                decided_by = decided_by.name(),
                rule = rule_name(rule),
                latency_ms = self.latency_ms,
                trace_id = self.trace_id.as_deref(),
                "request refused"
        );
    }

    /// Records the refusal when a request ended before any check decided it.
    fn refuse_undecided(&self, observation: &RequestObservation) {
        tracing::error!(
                correlation_id = %observation.correlation_id,
                tenant_id = self.tenant.as_deref(),
                route_id = self.route.as_deref(),
                method = observation.method.as_str(),
                path = observation.path.as_str(),
                client = %observation.client,
                decision = "undecided",
                latency_ms = self.latency_ms,
                "request ended without a decision and was refused"
        );
    }
}

/// The fields of a line that need writing out first.
struct Line {
    tenant: Option<String>,
    route: Option<String>,
    subject: &'static str,
    subject_id: Option<String>,
    latency_ms: i64,
    trace_id: Option<String>,
}

impl Line {
    /// The fields of `observation`.
    fn of(observation: &RequestObservation) -> Self {
        let (subject, subject_id) = subject_of(&observation.principal);
        Self {
            tenant: observation.tenant_id.known().map(ToString::to_string),
            route: route_of(observation.route),
            subject,
            subject_id,
            latency_ms: i64::try_from(observation.latency.whole_milliseconds()).unwrap_or(i64::MAX),
            trace_id: trace_of(observation.trace),
        }
    }
}

/// The kind of subject and its id.
fn subject_of(principal: &ObservedPrincipal) -> (&'static str, Option<String>) {
    match principal {
        ObservedPrincipal::Anonymous => ("anonymous", None),
        ObservedPrincipal::User(user_id) => ("user", Some(user_id.to_string())),
        ObservedPrincipal::Agent { agent_id, .. } => ("agent", Some(agent_id.to_string())),
        ObservedPrincipal::Consumer { consumer_id, .. } => {
            ("consumer", Some(consumer_id.to_string()))
        }
    }
}

/// The route's id, when one matched.
fn route_of(route: RouteMatch) -> Option<String> {
    match route {
        RouteMatch::NoRoute => None,
        RouteMatch::Matched { route_id, .. } => Some(route_id.to_string()),
    }
}

/// The trace id, when the request was traced.
fn trace_of(trace: Traced) -> Option<String> {
    match trace {
        Traced::NotTraced => None,
        Traced::In(context) => Some(context.trace_id().to_string()),
    }
}

/// The tenant rule's name, when the refusal was made under one.
fn rule_name(rule: &DecidingRule) -> Option<&str> {
    match rule {
        DecidingRule::Unnamed => None,
        DecidingRule::Named(label) => Some(label.as_str()),
    }
}
