//! The error body of the OAuth protocol endpoints (RFC 6749 5.2, RFC 6750
//! 3, RFC 7591 3.2.2), which every OAuth library branches on.

use serde::Serialize;

/// An OAuth error: the registered code and what was wrong.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OAuthErrorBody {
    /// The registered code, such as `invalid_grant` or `invalid_client`.
    pub error: &'static str,
    /// What was wrong, for a person reading the client's logs. Never names
    /// a token or a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}
