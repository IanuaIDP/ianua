//! A tenant's consumers: partner programs and other machines that call
//! the tenant's apps with a credential of their own, their key shown once.

use serde::{Deserialize, Serialize};

/// `POST …/consumers`: a consumer signing in with an API key the platform
/// makes.
#[derive(Debug, Clone, Serialize)]
pub struct NewConsumer {
    /// The name people see.
    pub name: String,
    /// What it is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Always `api_key` here.
    pub credential_kind: String,
}

/// The consumer just made. Holds its key, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct ConsumerMade {
    /// Handle used to manage it.
    pub id: String,
    /// Its API key, shown this once.
    #[serde(default)]
    pub api_key: Option<String>,
}

/// `POST …/consumers/{id}/rotate`: a new API key, the old one working
/// beside it for `overlap_seconds` when set.
#[derive(Debug, Clone, Serialize)]
pub struct Rotation {
    /// Always `api_key` here.
    pub credential_kind: String,
    /// How long the old key keeps working, at most seven days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlap_seconds: Option<i64>,
}

/// The new credential of a rotation. Holds its key, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct Rotated {
    /// The new API key, shown this once.
    #[serde(default)]
    pub api_key: Option<String>,
}

/// A consumer as `GET …/consumers/{id}` answers it.
#[derive(Debug, Clone, Deserialize)]
pub struct Consumer {
    /// Handle used to manage it.
    pub id: String,
    /// The name people see.
    pub name: String,
    /// What it is for.
    #[serde(default)]
    pub description: Option<String>,
    /// A short hint of its credential, never the credential itself.
    pub credential_hint: String,
    /// The credential the last rotation replaced, while it still works.
    #[serde(default)]
    pub previous_credential: Option<PreviousCredential>,
    /// Its own request allowance, if it has one.
    #[serde(default)]
    pub quota: Option<Quota>,
    /// `Active` or `Disabled`.
    pub status: String,
    /// The most sensitive data it may receive, such as `Internal`.
    pub clearance: String,
    /// When its current credential stops working, in RFC 3339, if ever.
    #[serde(default)]
    pub credential_expires_at: Option<String>,
}

/// `PUT …/consumers/{id}/description`.
#[derive(Debug, Clone, Serialize)]
pub struct DescriptionChange {
    /// What it is for, or `None` to clear it.
    pub description: Option<String>,
}

/// `PUT …/consumers/{id}/expiry`.
#[derive(Debug, Clone, Serialize)]
pub struct ExpiryChange {
    /// When the current credential stops working, in RFC 3339, or `None`
    /// for never.
    pub expires_at: Option<String>,
}

/// The credential a rotation replaced, working until `until`.
#[derive(Debug, Clone, Deserialize)]
pub struct PreviousCredential {
    /// The last characters of the key, for telling keys apart.
    pub credential_hint: String,
    /// When it stops working, in RFC 3339.
    pub until: String,
}

/// A request allowance: `requests` per `per`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    /// How many requests.
    pub requests: u64,
    /// `minute`, `hour`, `day` or `month`.
    pub per: String,
}

/// `PATCH …/consumers/{id}`: a new name.
#[derive(Debug, Clone, Serialize)]
pub struct ConsumerName {
    /// The new name.
    pub name: String,
}

/// `PUT …/consumers/{id}/quota`: a new allowance, or none.
#[derive(Debug, Clone, Serialize)]
pub struct QuotaChange {
    /// The allowance, or `None` to remove it.
    pub quota: Option<Quota>,
}

/// `PUT …/consumers/{id}/clearance`.
#[derive(Debug, Clone, Serialize)]
pub struct ClearanceChange {
    /// `Public`, `Internal`, `Confidential` or `Restricted`.
    pub clearance: String,
}
