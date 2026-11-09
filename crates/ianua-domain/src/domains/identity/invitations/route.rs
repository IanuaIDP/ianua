//! How an invitation's link reached the person who accepts it, and what
//! accepting it shows about the invited address.
//!
//! A link mailed to the invited address proves that whoever followed it
//! holds that mailbox. On a deployment with no mail server the link is
//! handed to the inviter instead, who passes it on by other means: then
//! accepting proves nothing about the mailbox, and the address keeps
//! whatever standing it had. The same rule holds for tenant and
//! organization invitations.

use crate::domains::identity::account::address::MailReach;
use crate::domains::identity::account::verified_email::VerifiedEmail;
use crate::types::{Email, PersonProof};

/// How an invitation's link reached the person accepting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationRoute {
    /// Mailed to the invited address.
    Mailed,
    /// Handed to the inviter to pass on, because no mail server is set up.
    HandedOver,
}

impl InvitationRoute {
    /// The route a link takes on a deployment whose mail is as `mail` says:
    /// mailed where a mail reaches, handed to the inviter otherwise.
    ///
    /// It is read when the invitation is accepted. A deployment whose mail
    /// server came or went since the link went out is judged by how it
    /// stands now, which errs towards proving nothing only when no mail
    /// goes out at all.
    #[must_use]
    pub fn under(mail: MailReach) -> Self {
        match mail {
            MailReach::Available => Self::Mailed,
            MailReach::NotSetUp => Self::HandedOver,
        }
    }

    /// What following the link shows about the person: that they hold the
    /// invited mailbox when it was mailed there, nothing when it was handed
    /// over.
    #[must_use]
    pub fn proof(self) -> PersonProof {
        match self {
            Self::Mailed => PersonProof::Mailbox,
            Self::HandedOver => PersonProof::Nothing,
        }
    }

    /// What accepting an invitation sent to `email` by this route shows
    /// about that address.
    ///
    /// | route      | the invited address |
    /// |------------|---------------------|
    /// | Mailed     | proven              |
    /// | HandedOver | unproven            |
    ///
    /// Only accepting an invitation calls this, once it checked the link.
    pub(crate) fn accepted_address(self, email: Email) -> AcceptedAddress {
        match self {
            Self::Mailed => AcceptedAddress::proven(VerifiedEmail::proven(email)),
            Self::HandedOver => AcceptedAddress::unproven(email),
        }
    }
}

/// What accepting an invitation shows about the invited address.
///
/// Only accepting an invitation makes one, so holding it shows the invited
/// person followed the invitation's link. Nothing outside the domain can
/// make one for an address of its choosing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedAddress(Standing);

/// Whether accepting proved the mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Standing {
    /// The link was mailed there, so whoever followed it holds the mailbox.
    Proven(VerifiedEmail),
    /// The link was handed over: the address is as unproven as before.
    Unproven(Email),
}

impl AcceptedAddress {
    /// An invited address the mailed link proved.
    pub(crate) fn proven(proof: VerifiedEmail) -> Self {
        Self(Standing::Proven(proof))
    }

    /// An invited address a handed over link left unproven.
    pub(crate) fn unproven(email: Email) -> Self {
        Self(Standing::Unproven(email))
    }

    /// The invited address, proven or not.
    #[must_use]
    pub fn email(&self) -> &Email {
        match &self.0 {
            Standing::Proven(proof) => proof.as_email(),
            Standing::Unproven(email) => email,
        }
    }

    /// Whether accepting proved the person holds the invited mailbox.
    #[must_use]
    pub fn is_proven(&self) -> bool {
        matches!(self.0, Standing::Proven(_))
    }

    /// The proof of the invited mailbox, when accepting gave one.
    pub(crate) fn proof(&self) -> Option<&VerifiedEmail> {
        match &self.0 {
            Standing::Proven(proof) => Some(proof),
            Standing::Unproven(_) => None,
        }
    }

    /// The proof of the invited mailbox, when accepting gave one, taken
    /// out to be kept on the account.
    pub(crate) fn into_proof(self) -> Option<VerifiedEmail> {
        match self.0 {
            Standing::Proven(proof) => Some(proof),
            Standing::Unproven(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ann() -> Email {
        Email::new("ann@acme.test").unwrap()
    }

    /// Every mail setup gives the route the table on `under` states, and
    /// every route the address standing the table on `accepted_address`
    /// states.
    #[test]
    fn every_mail_setup_gives_its_route_and_every_route_its_standing() {
        let table = [
            (MailReach::Available, InvitationRoute::Mailed, true),
            (MailReach::NotSetUp, InvitationRoute::HandedOver, false),
        ];

        for (mail, route, proven) in table {
            let accepted = InvitationRoute::under(mail).accepted_address(ann());

            assert_eq!(InvitationRoute::under(mail), route, "{mail:?}");
            assert_eq!(accepted.is_proven(), proven, "{mail:?}");
            assert_eq!(accepted.email(), &ann());
        }
    }

    /// Accepting a handed-over invitation leaves the invited mailbox
    /// unproven because the link did not establish access to it.
    #[test]
    fn a_handed_over_link_proves_no_mailbox() {
        let accepted = InvitationRoute::HandedOver.accepted_address(ann());

        assert_eq!(accepted, AcceptedAddress::unproven(ann()));
    }

    /// A mailed link shows the mailbox; a handed over one shows nothing.
    #[test]
    fn only_a_mailed_link_shows_the_mailbox() {
        assert_eq!(InvitationRoute::Mailed.proof(), PersonProof::Mailbox);
        assert_eq!(InvitationRoute::HandedOver.proof(), PersonProof::Nothing);
    }
}
