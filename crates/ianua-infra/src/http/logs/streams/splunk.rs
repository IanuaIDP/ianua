//! An audit record as a Splunk HTTP Event Collector takes it: the record
//! as the event, its time in seconds, the source type the platform's
//! records are searched by, and the index when the stream names one.

use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::domains::audit::streaming::SplunkIndex;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::shared::security::secret::Secret;
use serde::Serialize;

use crate::http::logs::streams::event::RecordJson;

/// The source type every record is sent under.
const SOURCE_TYPE: &str = "ianua:audit";

/// The source every record is sent from.
const SOURCE: &str = "ianua";

#[derive(Serialize)]
struct CollectorEvent<'a> {
    time: i64,
    source: &'static str,
    sourcetype: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<&'a str>,
    event: RecordJson<'a>,
}

/// The body `record` is posted to the collector as, into `index`.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be written out.
pub(super) fn event(record: &AuditRecord, index: &SplunkIndex) -> Result<Vec<u8>, DomainError> {
    let event = CollectorEvent {
        time: record.occurred_at.unix_timestamp(),
        source: SOURCE,
        sourcetype: SOURCE_TYPE,
        index: match index {
            SplunkIndex::TokenDefault => None,
            SplunkIndex::Named(name) => Some(name.as_str()),
        },
        event: RecordJson::of(record)?,
    };
    serde_json::to_vec(&event).map_err(DomainError::infra)
}

/// The `Authorization` value the collector's `token` is sent as.
pub(super) fn authorization(token: &Secret) -> Secret {
    Secret::new(format!("Splunk {}", token.expose()))
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::audit::streaming::SplunkIndexName;
    use serde_json::{Value, json};

    use super::*;
    use crate::http::logs::streams::event::tests::record;

    /// A record sent into a named index carries the index, its time in
    /// seconds and the platform's source type, the record as the event.
    #[test]
    fn a_record_goes_into_the_named_index() {
        let record = record();
        let index = SplunkIndex::Named(SplunkIndexName::new("ianua_audit").unwrap());

        let sent: Value = serde_json::from_slice(&event(&record, &index).unwrap()).unwrap();

        assert_eq!(sent["index"], json!("ianua_audit"));
        assert_eq!(sent["time"], json!(1_700_000_000));
        assert_eq!(sent["sourcetype"], json!("ianua:audit"));
        assert_eq!(
            sent["event"]["event_type"],
            json!(record.event_type.as_str())
        );
    }

    /// The token's own index is used when the stream names none, so no
    /// index field is sent.
    #[test]
    fn the_tokens_index_sends_no_index() {
        let sent: Value =
            serde_json::from_slice(&event(&record(), &SplunkIndex::TokenDefault).unwrap()).unwrap();

        assert!(sent.get("index").is_none());
    }
}
