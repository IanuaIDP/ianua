//! Mailing a link of its own to each organization's member holding one
//! address.

use std::future::Future;

use ianua_domain::domains::organization::lifecycle::Organization;
use ianua_domain::domains::organization::members::org_user::OrgUser;
use ianua_domain::types::Email;

use crate::auditor::RequestAuditor;
use crate::error::AppError;

/// The member a link goes to, and their organization.
pub(in crate::use_cases::organization) struct Recipient {
    /// The member the link signs in or resets.
    pub(in crate::use_cases::organization) member: OrgUser,
    /// The organization the link names.
    pub(in crate::use_cases::organization) organization: Organization,
}

/// A request that mails each organization's member holding an address a
/// link of their own.
pub(in crate::use_cases::organization) trait LinkPerOrganization:
    Sync
{
    /// Whether a link may go to `email` now.
    fn admitted(&self, email: &Email) -> impl Future<Output = Result<bool, AppError>> + Send;

    /// Mails `to` a fresh link and records it.
    fn sent(
        &self,
        auditor: &RequestAuditor,
        to: &Recipient,
    ) -> impl Future<Output = Result<(), AppError>> + Send;
}

/// Mails each of `recipients` a link, unless there is none or `email` had
/// a link a moment ago. The answer is the same either way, so it tells
/// nobody whether the address is a member anywhere.
///
/// # Errors
///
/// - `AppError::Internal` when a link cannot be kept or recorded.
pub(in crate::use_cases::organization) async fn mail_each(
    mailing: &impl LinkPerOrganization,
    auditor: &RequestAuditor,
    email: &Email,
    recipients: &[Recipient],
) -> Result<(), AppError> {
    if recipients.is_empty() || !mailing.admitted(email).await? {
        return Ok(());
    }
    for to in recipients {
        mailing.sent(auditor, to).await?;
    }
    Ok(())
}
