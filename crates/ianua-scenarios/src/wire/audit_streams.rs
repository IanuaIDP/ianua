//! Streams of a tenant's audit records to an outside collector, as its
//! administrators set them up: where they go with the credential as typed,
//! and the stream as read back without it.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A stream to add, or the whole of one to change, with the caller's own
/// password typed again.
#[derive(Clone, Serialize)]
pub struct AuditStreamSetup {
    /// What it is called.
    pub name: String,
    /// Where records go, by `kind`, with its credential.
    pub destination: Value,
    /// The event types sent; every record when `null`.
    pub events: Option<Vec<String>>,
    /// The caller's password, typed again.
    pub proof: StreamProof,
}

impl std::fmt::Debug for AuditStreamSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditStreamSetup")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// The password a person types again to change where the records go.
#[derive(Clone, Serialize)]
pub struct StreamProof {
    /// The caller's password.
    pub password: String,
}

/// A stream just added.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditStreamCreated {
    /// The id later changes name it by.
    pub id: String,
}

/// A tenant's audit stream as read back: no credential is ever shown.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditStream {
    /// The id a listing shows it by.
    pub id: String,
    /// What it is called.
    pub name: String,
    /// Where records go, without its credential.
    pub destination: StreamDestination,
    /// The event types sent, or `None` for every record.
    #[serde(default)]
    pub events: Option<Vec<String>>,
    /// `active`, `failing` or `paused`.
    pub state: String,
    /// How many sends in a row failed, while it is failing.
    #[serde(default)]
    pub failures: Option<u32>,
    /// Why it stopped, while it is paused.
    #[serde(default)]
    pub paused_reason: Option<String>,
}

/// Where a stream sends records, without its credential.
#[derive(Debug, Clone, Deserialize)]
pub struct StreamDestination {
    /// `splunk`, `datadog`, `syslog` or `http`.
    pub kind: String,
    /// The collector or endpoint address, for Splunk and HTTP.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// The Splunk index, or `None` for the token's own.
    #[serde(default)]
    pub index: Option<String>,
    /// The Datadog site.
    #[serde(default)]
    pub site: Option<String>,
    /// The header an HTTPS endpoint gets, by name only.
    #[serde(default)]
    pub header_name: Option<String>,
}
