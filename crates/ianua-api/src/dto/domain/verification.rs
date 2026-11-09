//! Domain verification bodies: where a domain's proof stands.

use ianua_domain::domains::tenant::custom_domains::verification_status::VerificationStatus;
use serde::Serialize;

/// Where a domain's proof stands after a check.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct VerificationStatusResponse {
    /// `Pending`, `Verified` or `Failed`.
    pub status: &'static str,
}

impl From<VerificationStatus> for VerificationStatusResponse {
    fn from(status: VerificationStatus) -> Self {
        Self {
            status: verification_name(status),
        }
    }
}

/// The name a verification status is sent under.
pub(crate) fn verification_name(status: VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::Pending => "Pending",
        VerificationStatus::Verified => "Verified",
        VerificationStatus::Failed => "Failed",
    }
}
