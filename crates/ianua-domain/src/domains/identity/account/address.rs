//! An account's address, and whether its owner was shown to hold it.

use crate::domains::identity::account::verified_email::{VerificationRefused, VerifiedEmail};
use crate::types::Email;

/// Whether a mail sent now could reach the person an address belongs to.
///
/// A deployment with no mail server never delivers a confirmation link, so
/// a sign-in that waited for one would wait for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailReach {
    /// A mail server is set up, so a mailed link arrives.
    Available,
    /// None is: a mailed link would never arrive.
    NotSetUp,
}

/// Whether an account's address was shown to belong to the person who
/// holds the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AddressStanding {
    /// Typed in by the person, an admin or a directory.
    ///
    /// Nobody has shown it reaches the account's owner.
    Unverified,
    /// Shown to reach the account's owner.
    ///
    /// A link mailed to it was followed, an invitation to it was accepted,
    /// or a provider trusted for it said so.
    Verified,
}

impl AddressStanding {
    /// Whether an account whose address stands so may finish a sign-in,
    /// where `mail` says whether a link confirming the address could reach
    /// anyone.
    ///
    /// | standing   | mail set up | no mail server |
    /// |------------|-------------|----------------|
    /// | Verified   | admitted    | admitted       |
    /// | Unverified | refused     | admitted       |
    ///
    /// With mail, an unverified address is confirmed through the link
    /// first. Without it no link could ever arrive, so the sign-in goes on
    /// and the address stays unverified: it is never marked verified here,
    /// and whatever needs a verified address stays refused.
    #[must_use]
    pub fn admits_sign_in(self, mail: MailReach) -> bool {
        match (self, mail) {
            (Self::Verified, MailReach::Available | MailReach::NotSetUp)
            | (Self::Unverified, MailReach::NotSetUp) => true,
            (Self::Unverified, MailReach::Available) => false,
        }
    }
}

/// The address an account is reached at, with its standing.
///
/// A new address starts unverified. It becomes verified only through a
/// [`VerifiedEmail`] for that same address. So nothing outside the domain
/// can mark an address verified that nobody proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountAddress {
    email: Email,
    standing: AddressStanding,
}

impl AccountAddress {
    /// An address nobody has proved yet.
    #[must_use]
    pub fn unverified(email: Email) -> Self {
        Self {
            email,
            standing: AddressStanding::Unverified,
        }
    }

    /// An address its owner was shown to hold.
    #[must_use]
    pub fn verified(proof: VerifiedEmail) -> Self {
        Self {
            email: proof.into_email(),
            standing: AddressStanding::Verified,
        }
    }

    /// The address as it was stored, with the standing it was stored with.
    ///
    /// Only for an account rebuilt from storage, which holds the standing
    /// the domain gave it.
    #[must_use]
    pub(crate) fn stored(email: Email, standing: AddressStanding) -> Self {
        Self { email, standing }
    }

    /// Marks the address proved by `proof`.
    ///
    /// # Errors
    ///
    /// - [`VerificationRefused::OtherAddress`] when `proof` is for another
    ///   address. The standing is left as it was.
    pub fn confirm<E>(&mut self, proof: &VerifiedEmail) -> Result<(), VerificationRefused<E>> {
        if proof.as_email() != &self.email {
            return Err(VerificationRefused::OtherAddress);
        }
        self.standing = AddressStanding::Verified;
        Ok(())
    }

    /// The address.
    #[must_use]
    pub fn email(&self) -> &Email {
        &self.email
    }

    /// Whether its owner was shown to hold it, as an [`AddressStanding`].
    #[must_use]
    pub fn standing(&self) -> AddressStanding {
        self.standing
    }

    /// Whether its owner was shown to hold it.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.standing == AddressStanding::Verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::identity::account::verified_email::proof_of;

    fn email(text: &str) -> Email {
        Email::new(text).unwrap()
    }

    /// An admin types in a@example.com for a new account. Nobody has proved
    /// it, so it starts unverified.
    #[test]
    fn a_typed_address_is_unverified() {
        let address = AccountAddress::unverified(email("a@example.com"));

        assert!(!address.is_verified());
    }

    /// An address built from a proof for a@example.com is verified and keeps
    /// that exact address.
    #[test]
    fn a_proved_address_is_verified() {
        let address = AccountAddress::verified(proof_of(&email("a@example.com")));

        assert!(address.is_verified());
        assert_eq!(address.email(), &email("a@example.com"));
    }

    /// An unverified a@example.com receives a proof for a@example.com. It
    /// becomes verified.
    #[test]
    fn a_proof_confirms_its_own_address() {
        let mut address = AccountAddress::unverified(email("a@example.com"));

        address
            .confirm::<()>(&proof_of(&email("a@example.com")))
            .unwrap();

        assert!(address.is_verified());
    }

    /// Proof for a different mailbox returns an address-mismatch refusal
    /// and leaves the account's address unverified.
    #[test]
    fn a_proof_for_another_address_confirms_nothing() {
        let mut address = AccountAddress::unverified(email("a@example.com"));

        let result = address.confirm::<()>(&proof_of(&email("b@example.com")));

        assert!(matches!(result, Err(VerificationRefused::OtherAddress)));
        assert!(!address.is_verified());
    }

    /// Every standing against every mail setup gives the answer the table
    /// on `admits_sign_in` states.
    #[test]
    fn every_standing_and_mail_setup_has_its_stated_answer() {
        let table = [
            (AddressStanding::Verified, MailReach::Available, true),
            (AddressStanding::Verified, MailReach::NotSetUp, true),
            (AddressStanding::Unverified, MailReach::Available, false),
            (AddressStanding::Unverified, MailReach::NotSetUp, true),
        ];

        for (standing, mail, admitted) in table {
            assert_eq!(
                standing.admits_sign_in(mail),
                admitted,
                "{standing:?} {mail:?}"
            );
        }
    }

    /// Ann's address was typed in by an admin on a deployment with no mail
    /// server. She may sign in, and admitting her leaves the address
    /// unverified.
    #[test]
    fn admitting_an_unverified_address_without_mail_leaves_it_unverified() {
        let address = AccountAddress::unverified(email("ann@example.com"));

        let admitted = address.standing().admits_sign_in(MailReach::NotSetUp);

        assert!(admitted);
        assert!(!address.is_verified());
    }
}
