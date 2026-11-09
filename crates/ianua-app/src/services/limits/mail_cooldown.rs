//! The wait between two mails of one kind that an admin or owner sends to
//! one address.

use ianua_domain::message;
use ianua_domain::types::Email;

use crate::error::{AppError, OrInternal};
use crate::ports::limits::{MailPurpose, MailThrottle};

/// Refuses sending `recipient` a `purpose` mail when one went to the
/// address a moment ago.
///
/// Asking admits the mail and starts the wait, so callers ask after every
/// other check and before anything changes: a request refused for another
/// reason leaves the address's minute unspent, and one refused here leaves
/// the link already sent working. Mallory owns an organization and sends
/// an invitation to Bob, a stranger, again and again. Without the wait,
/// the platform fills Bob's inbox in her name.
///
/// # Errors
///
/// - `AppError::TooManyRequests` when a `purpose` mail went to `recipient`
///   within the last minute.
/// - `AppError::Internal` when the throttle cannot be read.
pub(crate) async fn ensure_mail_admitted(
    throttle: &dyn MailThrottle,
    purpose: MailPurpose,
    recipient: &Email,
) -> Result<(), AppError> {
    let admitted = throttle.admit(purpose, recipient).await.or_internal()?;
    if admitted {
        return Ok(());
    }
    Err(AppError::TooManyRequests(message!(
        "limits-an-email-went-to-this-address",
        "an email went to this address a moment ago; try again in a minute"
    )))
}
