//! What each kind of emailed link is for: how long it may live, and whether
//! following it signs someone in.

use time::Duration;

use crate::domains::identity::sealed::Sealed;
use crate::domains::identity::tokens::email_verification::EmailVerification;
use crate::domains::identity::tokens::installation_setup::InstallationSetup;
use crate::domains::identity::tokens::magic_link::MagicLink;
use crate::domains::identity::tokens::password_reset::PasswordReset;
use crate::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;

/// What following a link does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEffect {
    /// It signs the person in, or finishes a sign-in they began. So it does
    /// nothing for an account that may not sign in now.
    SignsIn,
    /// It proves the reader holds the mailbox, and nothing more.
    ProvesAddress,
}

/// The rules for one kind of emailed link.
///
/// A link that lives for years is a key lying in a mailbox for years. So
/// each kind has a ceiling, well above what a server sets by default.
pub trait TokenPurpose: Sealed {
    /// The kind's name, stable across releases. Storage files each link
    /// under it, so a lookup for one kind never finds a link of another.
    const NAME: &'static str;
    /// The longest a link of this kind may live.
    const LONGEST: Duration;
    /// What following it does.
    const EFFECT: LinkEffect;
}

impl Sealed for EmailVerification {}

impl TokenPurpose for EmailVerification {
    const NAME: &'static str = "email_verification";
    const LONGEST: Duration = Duration::days(7);
    const EFFECT: LinkEffect = LinkEffect::ProvesAddress;
}

impl Sealed for PasswordReset {}

impl TokenPurpose for PasswordReset {
    const NAME: &'static str = "password_reset";
    const LONGEST: Duration = Duration::hours(1);
    const EFFECT: LinkEffect = LinkEffect::ProvesAddress;
}

impl Sealed for MagicLink {}

impl TokenPurpose for MagicLink {
    const NAME: &'static str = "magic_link";
    const LONGEST: Duration = Duration::hours(1);
    const EFFECT: LinkEffect = LinkEffect::SignsIn;
}

impl Sealed for SignInConfirmation {}

impl TokenPurpose for SignInConfirmation {
    const NAME: &'static str = "sign_in_confirmation";
    const LONGEST: Duration = Duration::hours(1);
    const EFFECT: LinkEffect = LinkEffect::SignsIn;
}

impl Sealed for InstallationSetup {}

impl TokenPurpose for InstallationSetup {
    const NAME: &'static str = "installation_setup";
    const LONGEST: Duration = Duration::days(1);
    const EFFECT: LinkEffect = LinkEffect::ProvesAddress;
}

/// A kind of token that is mailed to its holder, and so may be issued to
/// any account its use case names.
///
/// An installation's setup token is not one: it proves an address without
/// the mailbox, so only founding an installation issues it.
pub trait MailedPurpose: TokenPurpose {}

impl MailedPurpose for EmailVerification {}

impl MailedPurpose for PasswordReset {}

impl MailedPurpose for MagicLink {}

impl MailedPurpose for SignInConfirmation {}

/// A kind of link a tenant account is mailed as a
/// [`SecureToken`](crate::domains::identity::tokens::secure::SecureToken).
///
/// A tenant password reset goes through
/// [`PasswordResetRequest`](crate::domains::authentication::recovery::reset::PasswordResetRequest)
/// alone, with its lockout and its own checks. A second way to reset a
/// password would be a second place to get them wrong.
pub trait TenantLinkPurpose: TokenPurpose {}

impl TenantLinkPurpose for EmailVerification {}

impl TenantLinkPurpose for MagicLink {}

impl TenantLinkPurpose for SignInConfirmation {}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// Each of the five link purposes has a distinct storage name, keeping
    /// lookups for different kinds apart.
    #[test]
    fn every_kind_of_link_has_a_name_of_its_own() {
        let names = [
            EmailVerification::NAME,
            PasswordReset::NAME,
            MagicLink::NAME,
            SignInConfirmation::NAME,
            InstallationSetup::NAME,
        ];

        let distinct: HashSet<&str> = names.into_iter().collect();

        assert_eq!(distinct.len(), names.len());
    }
}
