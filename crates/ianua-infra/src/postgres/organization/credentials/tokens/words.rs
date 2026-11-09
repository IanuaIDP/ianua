//! The word each kind of mailed link is stored under.
//!
//! The kinds are marker types, not values, so each has its word as a
//! constant of its own rather than a row of a `stored_words!` table.

use ianua_domain::domains::identity::tokens::email_verification::EmailVerification;
use ianua_domain::domains::identity::tokens::installation_setup::InstallationSetup;
use ianua_domain::domains::identity::tokens::magic_link::MagicLink;
use ianua_domain::domains::identity::tokens::password_reset::PasswordReset;
use ianua_domain::domains::identity::tokens::purpose::TokenPurpose;
use ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;

/// A kind of mailed link, with the word its rows are stored under. Every
/// read and write names it, so a link of one kind is never found as
/// another.
pub(crate) trait StoredPurpose: TokenPurpose + Send + Sync + 'static {
    /// The word in the `purpose` column.
    const WORD: &'static str;
}

impl StoredPurpose for EmailVerification {
    const WORD: &'static str = "email_verification";
}

impl StoredPurpose for PasswordReset {
    const WORD: &'static str = "password_reset";
}

impl StoredPurpose for MagicLink {
    const WORD: &'static str = "magic_link";
}

impl StoredPurpose for SignInConfirmation {
    const WORD: &'static str = "sign_in_confirmation";
}

impl StoredPurpose for InstallationSetup {
    const WORD: &'static str = "installation_setup";
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// The five mailed-link purposes each have a distinct stored word.
    #[test]
    fn every_kind_of_link_has_a_word_of_its_own() {
        let words = [
            EmailVerification::WORD,
            PasswordReset::WORD,
            MagicLink::WORD,
            SignInConfirmation::WORD,
            InstallationSetup::WORD,
        ];

        assert_eq!(words.iter().collect::<BTreeSet<_>>().len(), words.len());
    }
}
