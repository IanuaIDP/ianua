//! A member's password reset: asking for a link, reading what it is worth,
//! replacing a dead one, and setting the new password.

use ianua_app::email::TokenResent;
use ianua_app::use_cases::organization::password_reset::ConfirmOrgResetRequest;
use ianua_domain::shared::security::secret::Secret;
use ianua_domain::types::{Email, PasswordLinkStatus, PasswordPolicy, TokenStatus};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Request body naming the address a reset link is asked for.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgResetRequestBody {
    /// The member's email address.
    pub email: String,
}

impl TryFrom<OrgResetRequestBody> for Email {
    type Error = ApiError;

    fn try_from(body: OrgResetRequestBody) -> Result<Self, Self::Error> {
        Self::new(body.email).map_err(ApiError::validation)
    }
}

/// Request body completing a password reset.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgResetConfirmBody {
    /// The single-use token from the reset email.
    pub token: String,
    /// The new password.
    pub password: String,
    /// A code from the member's authenticator, required when they have an
    /// active second factor.
    #[serde(default)]
    pub mfa_code: Option<String>,
}

impl From<OrgResetConfirmBody> for ConfirmOrgResetRequest {
    fn from(body: OrgResetConfirmBody) -> Self {
        Self {
            raw_token: body.token,
            new_password: Secret::new(body.password),
            mfa_code: body.mfa_code,
        }
    }
}

/// The token from a reset link, to ask what it is worth or replace it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct OrgResetTokenBody {
    /// The single-use token from the link.
    pub token: String,
}

/// What a reset link is worth, and the rules the new password must meet.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgResetLinkStatusResponse {
    /// `Valid`, `Expired`, `AlreadyUsed`, or `Invalid`.
    pub status: OrgResetLinkState,
    /// The policy the new password must meet. Present only when `status` is
    /// `Valid`, the one answer that offers the form.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub password_policy: Option<PasswordPolicy>,
}

impl From<PasswordLinkStatus> for OrgResetLinkStatusResponse {
    fn from(answer: PasswordLinkStatus) -> Self {
        Self {
            status: answer.token_status().into(),
            password_policy: answer.password_policy().cloned(),
        }
    }
}

/// The wire spelling of a reset link's state.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) enum OrgResetLinkState {
    /// Unspent and in date: offer the form.
    Valid,
    /// Out of date or superseded; offer to send another link.
    Expired,
    /// Already spent, so the password was changed on it.
    AlreadyUsed,
    /// No such token: mistyped, truncated by a mail client, or never ours.
    Invalid,
}

impl From<TokenStatus> for OrgResetLinkState {
    fn from(status: TokenStatus) -> Self {
        match status {
            TokenStatus::Valid => Self::Valid,
            TokenStatus::Expired => Self::Expired,
            TokenStatus::AlreadyUsed => Self::AlreadyUsed,
            TokenStatus::Invalid => Self::Invalid,
        }
    }
}

/// Confirmation that another reset email is on its way.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OrgResetResentResponse {
    /// Seconds before another may be requested. Count this down rather than
    /// assuming a value: it is the wait the server enforces.
    pub retry_after_seconds: u64,
}

impl From<TokenResent> for OrgResetResentResponse {
    fn from(resent: TokenResent) -> Self {
        Self {
            retry_after_seconds: resent.retry_after_seconds,
        }
    }
}
