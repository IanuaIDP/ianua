//! Whether an admin creating an account vouches for its email address.
//!
//! Shared by the tenant and control-plane creation paths so both answer the
//! question the same way: an address nobody has confirmed leaves the account
//! unable to sign in until the user follows a verification link.

/// Whether the admin creating an account vouches for its email address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailVerification {
    /// The address is taken as confirmed: the account is usable at once.
    Automatic,
    /// The user must follow a verification link before the account activates.
    Required,
}

impl EmailVerification {
    /// Reads the intent from an optional `auto_verify` flag.
    ///
    /// Absent means [`Self::Required`]: an account is only trusted when a
    /// caller says so explicitly.
    #[must_use]
    pub fn from_auto_verify(auto_verify: Option<bool>) -> Self {
        match auto_verify.unwrap_or(false) {
            true => Self::Automatic,
            false => Self::Required,
        }
    }

    /// Whether the address counts as confirmed at creation time.
    #[must_use]
    pub fn is_automatic(self) -> bool {
        self == Self::Automatic
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// When nothing says to trust the address, Ann must confirm her email.
    #[test]
    fn absent_auto_verify_requires_verification() {
        assert_eq!(
            EmailVerification::from_auto_verify(None),
            EmailVerification::Required
        );
    }

    /// When the request says to trust the address, it counts as confirmed
    /// without an email.
    #[test]
    fn explicit_auto_verify_is_automatic() {
        assert_eq!(
            EmailVerification::from_auto_verify(Some(true)),
            EmailVerification::Automatic
        );
    }

    /// When the request says not to trust the address, Ann must confirm her
    /// email.
    #[test]
    fn explicit_false_requires_verification() {
        assert_eq!(
            EmailVerification::from_auto_verify(Some(false)),
            EmailVerification::Required
        );
    }

    /// Only a trusted address counts as confirmed. One still waiting on Ann
    /// does not.
    #[test]
    fn only_automatic_counts_the_address_as_confirmed() {
        assert!(EmailVerification::Automatic.is_automatic());
        assert!(!EmailVerification::Required.is_automatic());
    }
}
