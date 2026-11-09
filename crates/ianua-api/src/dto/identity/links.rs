//! What an emailed link is worth, and the answer to asking for another:
//! the bodies every invitation, verification and email change link shares.

use ianua_app::email::{TokenResent, VerificationResent, VerificationTokenStatus};
use ianua_domain::types::{PasswordLinkStatus, PasswordPolicy, TokenStatus};
use serde::{Deserialize, Serialize};

/// The token from an emailed link, submitted to ask what it is worth, to
/// replace it, or to follow it.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct TokenStatusBody {
    /// The single-use token from the link.
    pub token: String,
}

/// The token from an address verification link.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct VerifyEmailBody {
    /// The single-use token from the link.
    pub token: String,
}

/// The token from an email change link.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ConfirmEmailChangeBody {
    /// The single-use token from the email sent to the new address.
    pub token: String,
}

/// What an emailed link is worth, without spending it.
///
/// Shared by the invitation and email change checks, which answer the same
/// question about the same kind of token. Address verification keeps
/// [`VerificationTokenStatusResponse`], whose `Verified` says something
/// particular to that flow.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TokenStatusResponse {
    /// `Valid`, `Expired`, `AlreadyUsed`, or `Invalid`.
    pub status: TokenStatusDto,
}

impl From<TokenStatus> for TokenStatusResponse {
    fn from(status: TokenStatus) -> Self {
        Self {
            status: status.into(),
        }
    }
}

/// What a link that sets a password is worth, and the rules the new
/// password must meet.
///
/// The reader is signed out, so this is the only way the form behind the
/// link learns the tenant's rules before they type.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PasswordLinkStatusResponse {
    /// `Valid`, `Expired`, `AlreadyUsed`, or `Invalid`.
    pub status: TokenStatusDto,
    /// The policy the new password must meet. Present only when `status` is
    /// `Valid`, the one answer that offers the form, and absent even then
    /// for a tenant without password sign-in, where there is no password to
    /// choose.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub password_policy: Option<PasswordPolicy>,
}

impl From<PasswordLinkStatus> for PasswordLinkStatusResponse {
    fn from(answer: PasswordLinkStatus) -> Self {
        Self {
            status: answer.token_status().into(),
            password_policy: answer.password_policy().cloned(),
        }
    }
}

/// The wire spelling of an emailed token's state.
///
/// Spelled the same way as [`VerificationTokenStatusDto`], so a client
/// reading one status field reads them all the same.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) enum TokenStatusDto {
    /// Unspent and in date: offer the action.
    Valid,
    /// Out of date or superseded: offer to send another link.
    Expired,
    /// Already spent, so the action has happened. Say so rather than
    /// offering it again.
    AlreadyUsed,
    /// No such token: mistyped, cut short by a mail client, or never ours.
    Invalid,
}

impl From<TokenStatus> for TokenStatusDto {
    fn from(status: TokenStatus) -> Self {
        match status {
            TokenStatus::Valid => Self::Valid,
            TokenStatus::Expired => Self::Expired,
            TokenStatus::AlreadyUsed => Self::AlreadyUsed,
            TokenStatus::Invalid => Self::Invalid,
        }
    }
}

/// What a verification link is worth, without spending it.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct VerificationTokenStatusResponse {
    /// `Valid`, `Expired`, or `Verified`.
    pub status: VerificationTokenStatusDto,
}

impl From<VerificationTokenStatus> for VerificationTokenStatusResponse {
    fn from(status: VerificationTokenStatus) -> Self {
        let status = match status {
            VerificationTokenStatus::Valid => VerificationTokenStatusDto::Valid,
            VerificationTokenStatus::Expired => VerificationTokenStatusDto::Expired,
            VerificationTokenStatus::Verified => VerificationTokenStatusDto::Verified,
        };
        Self { status }
    }
}

/// The wire spelling of a verification token's state.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) enum VerificationTokenStatusDto {
    /// Following the link will confirm the address.
    Valid,
    /// Out of date or superseded: ask for another link.
    Expired,
    /// The address is already confirmed: nothing to do.
    Verified,
}

/// Confirmation that another email is on its way.
///
/// Shared by the invitation and email change re-sends. Address
/// verification keeps [`VerificationResentResponse`], which said the same
/// thing first.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TokenResentResponse {
    /// Seconds before another may be requested. Count this down rather than
    /// assuming a value: it is the wait the server reports.
    pub retry_after_seconds: u64,
}

impl From<TokenResent> for TokenResentResponse {
    fn from(resent: TokenResent) -> Self {
        Self {
            retry_after_seconds: resent.retry_after_seconds,
        }
    }
}

/// Confirmation that another verification email is on its way.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct VerificationResentResponse {
    /// Seconds before another may be requested. Count this down rather than
    /// assuming a value: it is the wait the server enforces, and a request
    /// made sooner comes back `429`.
    pub retry_after_seconds: u64,
}

impl From<VerificationResent> for VerificationResentResponse {
    fn from(resent: VerificationResent) -> Self {
        Self {
            retry_after_seconds: resent.retry_after_seconds,
        }
    }
}
