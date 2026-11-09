//! How an invitation's link reaches the person invited: by mail, or, on a
//! deployment with no mail server, through the inviter, who is handed the
//! link to pass on.

use std::sync::Arc;

use ianua_domain::shared::security::secret::Secret;

use crate::email::InvitationPolicy;
use crate::ports::shared::{MailSetup, Mailer};
use crate::services::authentication::channels::mail_reaches;

/// What an invitation's link goes out through, for tenant and organization
/// invitations alike: the mailer, whether the deployment can mail at all,
/// and how long the link lasts and where it is built.
#[derive(ianua_macros::Fakes)]
pub struct InvitationMailing {
    /// Mails the invitation.
    pub mailer: Arc<dyn Mailer>,
    /// Whether anything can be mailed here at all.
    pub mail: Arc<dyn MailSetup>,
    /// How long the link lasts, the address it is built on and how soon
    /// another may be asked for.
    pub policy: InvitationPolicy,
}

/// How an invitation's one-time accept link went out.
///
/// Its `Debug` never shows the link: [`Secret`] prints redacted.
#[derive(Debug)]
pub enum InvitationDelivery {
    /// It was mailed to the invited address.
    Mailed,
    /// No mail server is set up, so nothing was mailed. The link is handed
    /// to the inviter, who passes it on to the person invited.
    HandOver {
        /// The accept link. Whoever holds it joins as the invited account,
        /// so it is never logged nor kept.
        link: Secret,
    },
}

impl InvitationMailing {
    /// The hand-over of `link` on a deployment with no mail server, or
    /// none when mail reaches people and the link is to be mailed.
    pub(crate) fn handed_over_unless_mailed(&self, link: &str) -> Option<InvitationDelivery> {
        if mail_reaches(self.mail.as_ref()) {
            return None;
        }
        Some(InvitationDelivery::HandOver {
            link: Secret::new(link),
        })
    }
}

impl InvitationDelivery {
    /// The link to hand to the inviter, when there is one to hand over.
    #[must_use]
    pub fn handed_over(&self) -> Option<&Secret> {
        match self {
            Self::Mailed => None,
            Self::HandOver { link } => Some(link),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Debug formatting a handed-over invitation omits its live token.
    #[test]
    fn a_handed_over_link_never_prints() {
        let delivery = InvitationDelivery::HandOver {
            link: Secret::new("https://app.test/accept-invite?token=live-token"),
        };

        assert!(!format!("{delivery:?}").contains("live-token"));
    }

    /// A mailed invitation has no link to hand over; a handed over one
    /// gives its link.
    #[test]
    fn only_a_handed_over_invitation_gives_its_link() {
        let handed = InvitationDelivery::HandOver {
            link: Secret::new("https://app.test/accept-invite?token=t"),
        };

        assert!(InvitationDelivery::Mailed.handed_over().is_none());
        assert_eq!(
            handed.handed_over().map(Secret::expose),
            Some("https://app.test/accept-invite?token=t")
        );
    }
}
