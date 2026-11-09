//! A tenant's API keys: making one with its scopes, reading, changing and
//! revoking it.

use serde::{Deserialize, Serialize};

/// `POST …/oauth/api-keys`: a key and what it may do.
#[derive(Debug, Clone, Serialize)]
pub struct NewApiKey {
    /// The name it is listed under.
    pub name: String,
    /// What it may do, such as `idp:users:view`; never more than its maker
    /// holds.
    pub scopes: Vec<String>,
}

/// `POST …/oauth/api-keys` with an end: a key that stops working when
/// `expires_at` comes.
#[derive(Debug, Clone, Serialize)]
pub struct NewEndingApiKey {
    /// The name it is listed under.
    pub name: String,
    /// What it may do, such as `idp:users:view`.
    pub scopes: Vec<String>,
    /// When it stops working, in RFC 3339.
    pub expires_at: String,
}

/// The key made, shown this once. Holds it, so it has no `Debug`.
#[derive(Clone, Deserialize)]
pub struct ApiKeyMade {
    /// Handle used to update or revoke the issued credential.
    pub id: String,
    /// The key, sent as `Authorization: Bearer`.
    pub raw_key: String,
}

/// One key, as the tenant lists it.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiKey {
    /// Handle used to update or revoke the listed credential.
    pub id: String,
    /// Label people use to distinguish credentials in the list.
    pub name: String,
    /// When it was last used, if ever.
    #[serde(default)]
    pub last_used_at: Option<String>,
    /// What it may reach.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// When it was paused, or `None` while it works.
    #[serde(default)]
    pub paused_at: Option<String>,
    /// When it stops working, or `None` for a key that never does.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// `PATCH …/oauth/api-keys/{id}`: what changes.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ApiKeyChange {
    /// Its new name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Its whole new set of scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}
