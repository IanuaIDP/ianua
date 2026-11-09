//! An address someone was shown to hold.

use crate::types::Email;

/// An address the person in front of us was shown to hold.
///
/// An identity provider proved it, or the person followed a link sent to
/// it. Only the domain makes one, where that proof is checked. So anything
/// that needs a proven address, such as an account created already
/// verified, cannot be given an address someone only typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEmail(Email);

impl VerifiedEmail {
    pub(crate) fn proven(email: Email) -> Self {
        Self(email)
    }

    /// The address.
    #[must_use]
    pub fn as_email(&self) -> &Email {
        &self.0
    }

    /// The address, with the proof given up.
    #[must_use]
    pub fn into_email(self) -> Email {
        self.0
    }
}

/// Proof of `email`, for tests that need an account whose address is
/// already verified.
#[cfg(test)]
pub(crate) fn proof_of(email: &Email) -> VerifiedEmail {
    VerifiedEmail::proven(email.clone())
}

/// Why an account's address could not be marked verified.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerificationRefused<E> {
    /// The proof is for an address the account does not have.
    #[error("the proof is for another address than the account's")]
    OtherAddress,
    /// The account's status could not make the move that verifying needs.
    #[error(transparent)]
    Transition(#[from] E),
}
