//! What an integration says when asked whether an account's credential
//! works, before the account is kept.

use crate::types::UntrustedText;

/// Whether a credential works, as the service behind an integration said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountCheck {
    /// The service took the credential.
    Accepted,
    /// The service refused it, for the reason given, such as a revoked
    /// token. The account is not kept.
    Refused(UntrustedText),
    /// The service could not be asked now, such as when it is down or busy.
    /// Nothing is known about the credential, so the account is not kept
    /// either; asking again later may settle it.
    Unreachable,
    /// The integration has no service of its own to ask, such as a request
    /// to an address each step names. The credential is kept unchecked.
    NotCheckable,
}
