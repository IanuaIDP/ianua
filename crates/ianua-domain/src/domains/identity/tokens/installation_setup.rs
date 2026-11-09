use crate::domains::identity::account::verified_email::VerifiedEmail;

/// Marks an organization token as the setup token an installation hands its
/// first owner.
///
/// The install step shows it to the person who ran it. Using it proves the
/// owner's address, so a self-hosted platform needs no mail server for its
/// first sign-in. Only founding an installation issues one; see
/// [`OrgToken::for_installer`](crate::domains::organization::access::token::OrgToken::for_installer).
#[derive(Debug)]
pub struct InstallationSetup;

/// What spending an installation's setup token shows: that whoever
/// presented it ran the install, and so is the first owner, holding the
/// address the token was issued for.
///
/// Only spending the token makes one, through
/// [`OrgToken::confirm_installer`](crate::domains::organization::access::token::OrgToken::confirm_installer).
#[derive(Debug)]
pub struct InstallerProof {
    address: VerifiedEmail,
}

impl InstallerProof {
    /// The proof a setup token gave once it was spent for the owner at
    /// `address`.
    pub(crate) fn spent_for(address: VerifiedEmail) -> Self {
        Self { address }
    }

    /// The owner's address, proven.
    pub(crate) fn address(&self) -> &VerifiedEmail {
        &self.address
    }
}
