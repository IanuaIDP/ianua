//! A request record as a log destination receives it: one flat JSON object
//! per finished request, the same fields in every format.
//!
//! The fields are what the gateway may report about a request: who asked,
//! what was decided, by which check, and how long it took. Never a token, a
//! header or a body, since the observation carries none.

use std::collections::BTreeMap;

use data_encoding::HEXLOWER;
use ianua_domain::domains::proxy::observation::{
    DecidingRule, DecidingStage, ObservedPrincipal, RequestObservation, RequestOutcome, RouteMatch,
    Traced,
};
use ianua_domain::shared::errors::DomainError;
use serde::Serialize;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;

/// One request record as it is written out.
#[derive(Serialize)]
pub(super) struct RecordLine<'a> {
    time: String,
    correlation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_id: Option<String>,
    method: &'a str,
    path: &'a str,
    client: String,
    principal: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_behalf_of: Option<String>,
    decision: &'static str,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decided_by: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_id: Option<String>,
    latency_ms: i64,
    classification: Vec<&'static str>,
}

impl<'a> RecordLine<'a> {
    /// The record of `observed`.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when its time cannot be
    /// written out.
    pub(super) fn of(observed: &'a RequestObservation) -> Result<Self, DomainError> {
        let (principal, principal_id, delegation_id, on_behalf_of) =
            principal_of(&observed.principal);
        let (route_id, service_id) = route_of(observed.route);
        let (trace_id, span_id) = trace_of(observed.trace);
        Ok(Self {
            time: record_time(observed)?,
            correlation_id: observed.correlation_id.to_string(),
            tenant_id: observed.tenant_id.known().map(ToString::to_string),
            route_id,
            service_id,
            method: observed.method.as_str(),
            path: observed.path.as_str(),
            client: observed.client.to_string(),
            principal,
            principal_id,
            delegation_id,
            on_behalf_of,
            decision: decision_of(&observed.outcome),
            status: observed.status(),
            reason: observed.denial_reason(),
            decided_by: observed.decided_by().map(DecidingStage::name),
            rule: rule_of(observed.deciding_rule()),
            trace_id,
            span_id,
            latency_ms: i64::try_from(observed.latency.whole_milliseconds()).unwrap_or(i64::MAX),
            classification: classification_names(observed),
        })
    }

    /// The decision, the status and the path, as one line a person reads.
    pub(super) fn summary(&self) -> String {
        format!(
            "{} {} {} {}",
            self.decision, self.status, self.method, self.path
        )
    }

    /// Every field that is set, by name, each as text.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the record cannot be
    /// written out.
    pub(super) fn attributes(&self) -> Result<BTreeMap<String, String>, DomainError> {
        let Value::Object(fields) = serde_json::to_value(self).map_err(DomainError::infra)? else {
            return Err(DomainError::infra_msg("a request record is not an object"));
        };
        Ok(fields
            .into_iter()
            .map(|(name, value)| (name, text_of(value)))
            .collect())
    }
}

/// Writes the observation's timestamp in the log destination's RFC 3339 format.
fn record_time(observed: &RequestObservation) -> Result<String, DomainError> {
    observed
        .occurred_at
        .format(&Rfc3339)
        .map_err(DomainError::infra)
}

/// Names every classification level reported for this request.
fn classification_names(observed: &RequestObservation) -> Vec<&'static str> {
    observed
        .classification
        .iter()
        .map(|level| level.as_str())
        .collect()
}

/// `value` as plain text: a string as it is, anything else as JSON.
fn text_of(value: Value) -> String {
    match value {
        Value::String(text) => text,
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
            value.to_string()
        }
    }
}

/// The batch as JSON lines: one object per record, each ending in a new
/// line.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a record cannot be written
/// out.
pub(super) fn json_lines(records: &[RequestObservation]) -> Result<Vec<u8>, DomainError> {
    let mut body = Vec::new();
    for record in records {
        serde_json::to_writer(&mut body, &RecordLine::of(record)?).map_err(DomainError::infra)?;
        body.push(b'\n');
    }
    Ok(body)
}

/// The kind of principal, its id, its delegation and whom it acted for.
fn principal_of(
    principal: &ObservedPrincipal,
) -> (&'static str, Option<String>, Option<String>, Option<String>) {
    match principal {
        ObservedPrincipal::Anonymous => ("anonymous", None, None, None),
        ObservedPrincipal::User(user) => ("user", Some(user.to_string()), None, None),
        ObservedPrincipal::Agent {
            agent_id,
            delegation_id,
            on_behalf_of,
        } => (
            "agent",
            Some(agent_id.to_string()),
            Some(delegation_id.to_string()),
            Some(on_behalf_of.label()),
        ),
        ObservedPrincipal::Consumer { consumer_id, .. } => {
            ("consumer", Some(consumer_id.to_string()), None, None)
        }
    }
}

/// The route and service a request matched.
fn route_of(route: RouteMatch) -> (Option<String>, Option<String>) {
    match route {
        RouteMatch::NoRoute => (None, None),
        RouteMatch::Matched {
            route_id,
            service_id,
        } => (Some(route_id.to_string()), Some(service_id.to_string())),
    }
}

/// The trace and span ids, in hex, when the request was traced.
pub(super) fn trace_of(trace: Traced) -> (Option<String>, Option<String>) {
    match trace {
        Traced::NotTraced => (None, None),
        Traced::In(context) => (
            Some(HEXLOWER.encode(context.trace_id().as_bytes())),
            Some(HEXLOWER.encode(context.span_id().as_bytes())),
        ),
    }
}

/// What was decided, as one word.
fn decision_of(outcome: &RequestOutcome) -> &'static str {
    match outcome {
        RequestOutcome::Allowed { .. } => "allowed",
        RequestOutcome::Denied { .. } => "denied",
        RequestOutcome::Undecided => "undecided",
    }
}

/// The named rule a request was refused under.
fn rule_of(rule: &DecidingRule) -> Option<&str> {
    match rule {
        DecidingRule::Unnamed => None,
        DecidingRule::Named(name) => Some(name.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ianua_domain::domains::proxy::observation::{GatewayCheck, ObservedPath};
    use ianua_domain::types::{CorrelationId, Fact, TenantId, UntrustedText};
    use serde_json::json;
    use time::{Duration, OffsetDateTime};

    use super::*;

    fn denied() -> RequestObservation {
        RequestObservation {
            correlation_id: CorrelationId::new(),
            tenant_id: Fact::Known(TenantId::new()),
            route: RouteMatch::NoRoute,
            method: UntrustedText::record("GET"),
            path: ObservedPath::record("/reports"),
            client: IpAddr::from([203, 0, 113, 1]),
            principal: ObservedPrincipal::Anonymous,
            outcome: RequestOutcome::Denied {
                status: 403,
                reason: "policy denied".to_owned(),
                decided_by: DecidingStage::Gateway(GatewayCheck::Route),
                rule: DecidingRule::Unnamed,
            },
            trace: Traced::NotTraced,
            latency: Duration::milliseconds(12),
            classification: Vec::new(),
            policy: Default::default(),
            occurred_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        }
    }

    /// A refused request is written as one line naming the decision, the
    /// status, the reason and the check that refused it.
    #[test]
    fn a_refused_request_is_one_line_with_its_decision() {
        let observed = denied();

        let body = json_lines(std::slice::from_ref(&observed)).unwrap();

        let text = String::from_utf8(body).unwrap();
        assert!(text.ends_with('\n'));
        let line: Value = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(line["decision"], json!("denied"));
        assert_eq!(line["status"], json!(403));
        assert_eq!(line["reason"], json!("policy denied"));
        assert_eq!(line["decided_by"], json!("route"));
        assert_eq!(line["time"], json!("2023-11-14T22:13:20Z"));
        assert_eq!(line["latency_ms"], json!(12));
    }

    /// Every set field is an attribute as text, and an unset one is none.
    #[test]
    fn attributes_hold_every_set_field_as_text() {
        let observed = denied();

        let attributes = RecordLine::of(&observed).unwrap().attributes().unwrap();

        assert_eq!(attributes.get("status").map(String::as_str), Some("403"));
        assert_eq!(attributes.get("method").map(String::as_str), Some("GET"));
        assert!(!attributes.contains_key("route_id"));
    }
}
