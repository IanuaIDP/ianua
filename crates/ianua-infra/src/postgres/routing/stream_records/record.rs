//! Stream records as their rows hold them: one tenant's records written out
//! column by column, for one statement to insert them all. Nothing is read
//! back; the gateway's role may not.

use ianua_app::ports::routing::{StreamConnectionCaller, StreamDecision, StreamRecord};
use time::OffsetDateTime;
use uuid::Uuid;

/// The columns a batch of one tenant's stream records is written to.
#[derive(Default)]
pub(super) struct StreamBatch {
    pub(super) ids: Vec<Uuid>,
    pub(super) stream_route_ids: Vec<Uuid>,
    pub(super) listen_ports: Vec<i32>,
    pub(super) client_addresses: Vec<String>,
    pub(super) server_names: Vec<Option<String>>,
    pub(super) callers: Vec<Option<String>>,
    pub(super) caller_ids: Vec<Option<Uuid>>,
    pub(super) decisions: Vec<String>,
    pub(super) reasons: Vec<String>,
    pub(super) backends: Vec<Option<String>>,
    pub(super) bytes_to_backend: Vec<i64>,
    pub(super) bytes_to_client: Vec<i64>,
    pub(super) durations: Vec<i32>,
    pub(super) occurred_at: Vec<OffsetDateTime>,
}

impl StreamBatch {
    /// The columns `records` are written to, each under a fresh id.
    pub(super) fn of<'a>(records: impl IntoIterator<Item = &'a StreamRecord>) -> Self {
        let mut batch = Self::default();
        for record in records {
            batch.push(record);
        }
        batch
    }

    fn push(&mut self, record: &StreamRecord) {
        let (caller, caller_id) = record.caller.as_ref().map_or((None, None), caller_columns);
        self.ids.push(Uuid::now_v7());
        self.stream_route_ids
            .push(*record.stream_route_id.as_uuid());
        self.listen_ports.push(i32::from(record.listen_port.get()));
        self.client_addresses.push(record.client.to_string());
        self.server_names.push(
            record
                .server_name
                .as_ref()
                .map(|name| name.as_str().to_owned()),
        );
        self.callers.push(caller.map(str::to_owned));
        self.caller_ids.push(caller_id);
        self.decisions
            .push(decision_word(record.decision).to_owned());
        self.reasons.push(record.reason.to_owned());
        self.backends.push(record.backend.clone());
        self.bytes_to_backend
            .push(stored_bytes(record.bytes_to_backend));
        self.bytes_to_client
            .push(stored_bytes(record.bytes_to_client));
        self.durations
            .push(i32::try_from(record.duration_ms).unwrap_or(i32::MAX));
        self.occurred_at.push(record.occurred_at);
    }
}

/// The word and id a caller is stored as.
fn caller_columns(caller: &StreamConnectionCaller) -> (Option<&'static str>, Option<Uuid>) {
    match caller {
        StreamConnectionCaller::Nobody => (Some("nobody"), None),
        StreamConnectionCaller::UnnamedCertificate => (Some("unnamed_certificate"), None),
        StreamConnectionCaller::Consumer(consumer) => (Some("consumer"), Some(*consumer.as_uuid())),
        StreamConnectionCaller::Person(user) => (Some("person"), Some(*user.as_uuid())),
    }
}

/// The word a decision is stored as.
fn decision_word(decision: StreamDecision) -> &'static str {
    match decision {
        StreamDecision::Allowed => "allowed",
        StreamDecision::Denied => "denied",
    }
}

/// A byte count as its column holds it, held at the largest it can.
fn stored_bytes(bytes: u64) -> i64 {
    i64::try_from(bytes).unwrap_or(i64::MAX)
}
