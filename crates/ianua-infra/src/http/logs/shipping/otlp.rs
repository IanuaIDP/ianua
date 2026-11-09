//! A batch of request records as OpenTelemetry log records, in the JSON
//! encoding of an OTLP logs export (`/v1/logs`).
//!
//! Each record becomes one log record: its time, a severity by its
//! decision, a one-line body, the trace it sat in, and every field of the
//! JSON-lines shape as an attribute under `ianua.`.

use ianua_domain::domains::proxy::observation::{RequestObservation, RequestOutcome};
use ianua_domain::shared::errors::DomainError;
use serde::Serialize;

use crate::http::logs::shipping::lines::{RecordLine, trace_of};

/// The service the records are reported as.
const SERVICE_NAME: &str = "ianua-gateway";

/// The severity of an allowed request: `INFO`.
const INFO: u8 = 9;

/// The severity of a refused or undecided request: `WARN`.
const WARN: u8 = 13;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Export {
    resource_logs: [ResourceLogs; 1],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceLogs {
    resource: Resource,
    scope_logs: [ScopeLogs; 1],
}

#[derive(Serialize)]
struct Resource {
    attributes: Vec<Attribute>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeLogs {
    scope: Scope,
    log_records: Vec<LogRecord>,
}

#[derive(Serialize)]
struct Scope {
    name: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogRecord {
    time_unix_nano: String,
    severity_number: u8,
    severity_text: &'static str,
    body: AnyValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_id: Option<String>,
    attributes: Vec<Attribute>,
}

#[derive(Serialize)]
struct Attribute {
    key: String,
    value: AnyValue,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AnyValue {
    string_value: String,
}

/// The batch as one OTLP logs export, in JSON.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a record cannot be written
/// out.
pub(super) fn export(records: &[RequestObservation]) -> Result<Vec<u8>, DomainError> {
    let log_records = records
        .iter()
        .map(log_record)
        .collect::<Result<Vec<_>, _>>()?;
    let export = Export {
        resource_logs: [ResourceLogs {
            resource: Resource {
                attributes: vec![attribute(
                    "service.name".to_owned(),
                    SERVICE_NAME.to_owned(),
                )],
            },
            scope_logs: [ScopeLogs {
                scope: Scope { name: "ianua" },
                log_records,
            }],
        }],
    };
    serde_json::to_vec(&export).map_err(DomainError::infra)
}

/// One request as a log record.
fn log_record(observed: &RequestObservation) -> Result<LogRecord, DomainError> {
    let line = RecordLine::of(observed)?;
    let (severity_number, severity_text) = severity(&observed.outcome);
    let (trace_id, span_id) = trace_of(observed.trace);
    let attributes = line
        .attributes()?
        .into_iter()
        .map(|(name, value)| attribute(format!("ianua.{name}"), value))
        .collect();
    Ok(LogRecord {
        time_unix_nano: observed.occurred_at.unix_timestamp_nanos().to_string(),
        severity_number,
        severity_text,
        body: AnyValue {
            string_value: line.summary(),
        },
        trace_id,
        span_id,
        attributes,
    })
}

/// The severity a request is logged at: a refusal or an undecided request
/// is a warning.
fn severity(outcome: &RequestOutcome) -> (u8, &'static str) {
    match outcome {
        RequestOutcome::Allowed { .. } => (INFO, "INFO"),
        RequestOutcome::Denied { .. } | RequestOutcome::Undecided => (WARN, "WARN"),
    }
}

fn attribute(key: String, value: String) -> Attribute {
    Attribute {
        key,
        value: AnyValue {
            string_value: value,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use ianua_domain::domains::proxy::observation::{
        ObservedPath, ObservedPrincipal, RouteMatch, Traced,
    };
    use ianua_domain::types::{CorrelationId, Fact, TenantId, UntrustedText};
    use serde_json::{Value, json};
    use time::{Duration, OffsetDateTime};

    use super::*;

    fn allowed() -> RequestObservation {
        RequestObservation {
            correlation_id: CorrelationId::new(),
            tenant_id: Fact::Known(TenantId::new()),
            route: RouteMatch::NoRoute,
            method: UntrustedText::record("POST"),
            path: ObservedPath::record("/orders"),
            client: IpAddr::from([203, 0, 113, 7]),
            principal: ObservedPrincipal::Anonymous,
            outcome: RequestOutcome::Allowed {
                upstream_status: 201,
            },
            trace: Traced::NotTraced,
            latency: Duration::milliseconds(3),
            classification: Vec::new(),
            policy: Default::default(),
            occurred_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        }
    }

    /// An allowed request is one INFO log record with its time in
    /// nanoseconds, a readable body and its fields as `ianua.` attributes.
    #[test]
    fn a_request_is_one_log_record_of_the_export() {
        let body = export(&[allowed()]).unwrap();

        let sent: Value = serde_json::from_slice(&body).unwrap();
        let record = &sent["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(record["timeUnixNano"], json!("1700000000000000000"));
        assert_eq!(record["severityText"], json!("INFO"));
        assert_eq!(
            record["body"]["stringValue"],
            json!("allowed 201 POST /orders")
        );
        let attributes = record["attributes"].as_array().unwrap();
        assert!(
            attributes.contains(&json!({"key": "ianua.status", "value": {"stringValue": "201"}}))
        );
    }
}
