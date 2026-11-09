//! What the gateway kept of each request, as the API answers it.

use serde::Deserialize;

use crate::wire::Status;

/// Who a request record says sent the request.
#[derive(Debug, Clone, Deserialize)]
pub struct RecordSubject {
    /// `anonymous`, `user`, `agent` or `consumer`.
    pub kind: String,
    /// Their id, for anyone but nobody.
    #[serde(default)]
    pub id: Option<String>,
    /// Whom an agent acted for.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
}

/// What decided a refusal.
#[derive(Debug, Clone, Deserialize)]
pub struct DecidedBy {
    /// `gateway` or `stage`.
    pub kind: String,
    /// The check's or the stage's name.
    pub name: String,
}

/// One request the gateway kept a record of.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestRecord {
    /// The request's correlation id.
    pub correlation_id: String,
    /// Who sent it.
    pub subject: RecordSubject,
    /// The route it matched, if any.
    #[serde(default)]
    pub route_id: Option<String>,
    /// HTTP verb evaluated by the gateway's policy.
    pub method: String,
    /// Request target evaluated by the gateway's policy.
    pub path: String,
    /// `allowed`, `refused` or `undecided`.
    pub decision: String,
    /// The status it was answered with.
    #[serde(deserialize_with = "read_status")]
    pub status: Status,
    /// Why it was refused, when it was.
    #[serde(default)]
    pub reason: Option<String>,
    /// What refused it, when something did.
    #[serde(default)]
    pub decided_by: Option<DecidedBy>,
    /// The rule that decided, when one did.
    #[serde(default)]
    pub rule: Option<String>,
    /// The version of the tenant's policy that ruled, when one did.
    #[serde(default)]
    pub policy_version: Option<u32>,
    /// How the gateway closed the connection the request upgraded, when
    /// it closed one for access.
    #[serde(default)]
    pub closed: Option<RecordClosed>,
}

/// How the gateway closed a connection a request upgraded.
#[derive(Debug, Clone, Deserialize)]
pub struct RecordClosed {
    /// `access_ended`, `check_failed` or `credential_expired`.
    pub reason: String,
}

/// Reads the gateway's numeric wire status into the shared named HTTP status.
fn read_status<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Status, D::Error> {
    let code = u16::deserialize(deserializer)?;
    Status::from_u16(code).map_err(serde::de::Error::custom)
}
