//! The audit trail, as an organization's audit log answers it, its
//! exports and the check of a tenant's chain.

use serde::{Deserialize, Serialize};

/// One record of the audit trail.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditEntry {
    /// The record's id.
    pub id: String,
    /// What happened, such as `organization.org_login_succeeded`.
    pub event_type: String,
    /// Who did it, as the log shows them.
    pub actor: String,
    /// The tenant it happened in, for a tenant's event.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// What it happened to.
    #[serde(default)]
    pub target_id: Option<String>,
    /// The client's address.
    #[serde(default)]
    pub ip_address: Option<String>,
    /// What it says happened, as named values.
    #[serde(default)]
    pub details: serde_json::Value,
    /// When, in RFC 3339.
    pub occurred_at: String,
    /// Whom or what the actor acted through, or `None` when they acted in
    /// their own name.
    #[serde(default)]
    pub acted_through: Option<ActedThrough>,
}

/// Whom or what an actor acted through.
#[derive(Debug, Clone, Deserialize)]
pub struct ActedThrough {
    /// `impersonation`, `support_impersonation` or `workflow_run`.
    pub kind: String,
    /// The workflow run, for `workflow_run`.
    #[serde(default)]
    pub execution_id: Option<String>,
    /// The operator who acted as someone, for `impersonation`.
    #[serde(default)]
    pub operator_id: Option<String>,
    /// The person acted as, for either impersonation.
    #[serde(default)]
    pub as_user_id: Option<String>,
}

/// What the check of a tenant's tamper-evident chain found.
#[derive(Debug, Clone, Deserialize)]
pub struct ChainCheck {
    /// `intact`, `intact_so_far`, `broken` or `not_verified_yet`.
    pub status: String,
    /// The last record verified, by its place in the chain.
    #[serde(default)]
    pub checked_through_seq: Option<i64>,
    /// The first record that did not verify, for a broken chain.
    #[serde(default)]
    pub broken_at_seq: Option<i64>,
}

/// `POST …/audit-log/exports`: which records an export holds and how its
/// file is written.
#[derive(Debug, Clone, Serialize)]
pub struct ExportAsked {
    /// `csv` or `json`.
    pub format: String,
    /// Only records whose type starts with this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
}

/// The export just asked for.
#[derive(Debug, Clone, Deserialize)]
pub struct ExportAccepted {
    /// Handle used to poll for the export's downloadable file.
    pub id: String,
}

/// Where an export stands. Holds a signed download link, so it has no
/// `Debug`.
#[derive(Clone, Deserialize)]
pub struct AuditExport {
    /// `pending`, `ready`, `failed` or `expired`.
    pub status: String,
    /// How many records the file holds, once ready.
    #[serde(default)]
    pub rows: Option<u64>,
    /// The file's SHA-256 in lower-case hex, once ready.
    #[serde(default)]
    pub sha256: Option<String>,
    /// The compact JWS over a ready tenant export's file, signed with the
    /// tenant's key.
    #[serde(default)]
    pub seal: Option<String>,
    /// The signed link the file downloads from once, while ready.
    #[serde(default)]
    pub download_url: Option<String>,
}
