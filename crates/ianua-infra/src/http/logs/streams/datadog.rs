//! An audit record as Datadog's log intake takes it: a one-entry array,
//! filed under the platform's source and service, the record's fields
//! beside them.

use ianua_domain::domains::audit::record::AuditRecord;
use ianua_domain::domains::audit::streaming::DatadogSite;
use ianua_domain::shared::errors::DomainError;
use serde::Serialize;

use crate::http::logs::streams::event::RecordJson;

/// The source Datadog files the records under.
const SOURCE: &str = "ianua";

/// The service Datadog files the records under.
const SERVICE: &str = "ianua-audit";

#[derive(Serialize)]
struct Entry<'a> {
    ddsource: &'static str,
    service: &'static str,
    message: &'static str,
    #[serde(flatten)]
    record: RecordJson<'a>,
}

/// The address of `site`'s log intake: the site's own host, never one a
/// tenant typed.
pub(super) fn intake(site: DatadogSite) -> String {
    format!("https://{}/api/v2/logs", site.log_intake_host())
}

/// The body `record` is posted to the intake as.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when it cannot be written out.
pub(super) fn entries(record: &AuditRecord) -> Result<Vec<u8>, DomainError> {
    let record = RecordJson::of(record)?;
    let entry = Entry {
        ddsource: SOURCE,
        service: SERVICE,
        message: record.event_type(),
        record,
    };
    serde_json::to_vec(&[entry]).map_err(DomainError::infra)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::http::logs::streams::event::tests::record;

    /// A record is one entry under the platform's source, its event type
    /// as the message.
    #[test]
    fn a_record_is_one_entry_named_by_its_event() {
        let record = record();

        let sent: Value = serde_json::from_slice(&entries(&record).unwrap()).unwrap();

        assert_eq!(sent[0]["ddsource"], json!("ianua"));
        assert_eq!(sent[0]["message"], json!(record.event_type.as_str()));
        assert_eq!(sent[0]["details"], json!({"status": "active"}));
    }

    /// Records for an EU account go to the EU intake.
    #[test]
    fn an_eu_account_is_sent_to_the_eu_intake() {
        assert_eq!(
            intake(DatadogSite::Eu1),
            "https://http-intake.logs.datadoghq.eu/api/v2/logs"
        );
    }
}
