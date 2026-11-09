//! What a sign-in whose password must change asks besides the password it
//! just proved, before the new one is set.
//!
//! A password past the tenant's age was chosen by the person, so proving
//! it is enough. A password an administrator set is known to that
//! administrator too: proving it shows nothing about who is signing in. So
//! the person also proves something only they hold, their own second factor
//! or their mailbox, and without either the change cannot be made at all.

use crate::domains::authentication::credentials::password_rules::ChangeReason;
use crate::domains::authentication::mfa::owed::Enrolment;
use crate::domains::identity::account::address::MailReach;
use crate::types::PersonProof;

/// The proof a password change inside a sign-in needs besides the current
/// password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeProof {
    /// Nothing more: the person chose the password that expired.
    PasswordAlone,
    /// A code from the person's own second factor, given with the new
    /// password.
    OwnFactor,
    /// The change token is mailed to the account's address instead of
    /// handed back, so only the mailbox's holder can set the new password.
    MailedLink,
    /// Nothing the person alone holds can be asked for here. The change is
    /// refused: an administrator must send an invitation instead of setting
    /// a password.
    NotPossible,
}

impl ChangeProof {
    /// What a change owed for `reason` asks, where `mail` says whether a
    /// mail reaches the person and `factor` whether they hold a second
    /// factor that can answer here.
    ///
    /// | reason     | factor   | mail set up | no mail server |
    /// |------------|----------|-------------|----------------|
    /// | Expired    | any      | PasswordAlone | PasswordAlone |
    /// | SetByAdmin | Enrolled | OwnFactor   | OwnFactor      |
    /// | SetByAdmin | none     | MailedLink  | NotPossible    |
    ///
    /// A factor is asked before the mailbox when the person has one: an
    /// administrator could reach neither, and the factor needs no mail.
    #[must_use]
    pub fn for_change(reason: ChangeReason, mail: MailReach, factor: Enrolment) -> Self {
        match (reason, factor, mail) {
            (
                ChangeReason::Expired,
                Enrolment::Enrolled | Enrolment::NotEnrolled,
                MailReach::Available | MailReach::NotSetUp,
            ) => Self::PasswordAlone,
            (
                ChangeReason::SetByAdmin,
                Enrolment::Enrolled,
                MailReach::Available | MailReach::NotSetUp,
            ) => Self::OwnFactor,
            (ChangeReason::SetByAdmin, Enrolment::NotEnrolled, MailReach::Available) => {
                Self::MailedLink
            }
            (ChangeReason::SetByAdmin, Enrolment::NotEnrolled, MailReach::NotSetUp) => {
                Self::NotPossible
            }
        }
    }

    /// Whether the change token goes back to the browser that proved the
    /// password, rather than to the mailbox or nowhere.
    #[must_use]
    pub fn hands_token_back(self) -> bool {
        matches!(self, Self::PasswordAlone | Self::OwnFactor)
    }

    /// What the change shows about the person beyond the password they
    /// proved: nothing, their mailbox, their own factor, or, refused, that
    /// nothing they hold is enough.
    #[must_use]
    pub fn proof(self) -> PersonProof {
        match self {
            Self::PasswordAlone => PersonProof::Nothing,
            Self::MailedLink => PersonProof::Mailbox,
            Self::OwnFactor => PersonProof::OwnFactor,
            Self::NotPossible => PersonProof::Refused,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authentication::credentials::password_rules::ChangeReason::{
        Expired, SetByAdmin,
    };
    use crate::domains::authentication::mfa::owed::Enrolment::{Enrolled, NotEnrolled};
    use crate::domains::authentication::recovery::change_proof::ChangeProof::{
        MailedLink, NotPossible, OwnFactor, PasswordAlone,
    };
    use crate::domains::identity::account::address::MailReach::{Available, NotSetUp};

    /// Every reason, factor and mail setup gives the answer the table on
    /// `for_change` states, all eight cells checked one by one.
    #[test]
    fn every_reason_factor_and_mail_setup_has_its_stated_answer() {
        let table = [
            (Expired, Enrolled, Available, PasswordAlone),
            (Expired, Enrolled, NotSetUp, PasswordAlone),
            (Expired, NotEnrolled, Available, PasswordAlone),
            (Expired, NotEnrolled, NotSetUp, PasswordAlone),
            (SetByAdmin, Enrolled, Available, OwnFactor),
            (SetByAdmin, Enrolled, NotSetUp, OwnFactor),
            (SetByAdmin, NotEnrolled, Available, MailedLink),
            (SetByAdmin, NotEnrolled, NotSetUp, NotPossible),
        ];

        for (reason, factor, mail, expected) in table {
            assert_eq!(
                ChangeProof::for_change(reason, mail, factor),
                expected,
                "{reason:?} {factor:?} {mail:?}"
            );
        }
    }

    /// Changing an administrator-set password requires more than that password,
    /// for every tested combination of mail availability and enrolled factor.
    #[test]
    fn a_password_an_admin_set_never_changes_on_the_password_alone() {
        for factor in [Enrolment::Enrolled, Enrolment::NotEnrolled] {
            for mail in [MailReach::Available, MailReach::NotSetUp] {
                let proof = ChangeProof::for_change(ChangeReason::SetByAdmin, mail, factor);

                assert_ne!(proof, ChangeProof::PasswordAlone, "{factor:?} {mail:?}");
            }
        }
    }

    /// Only a change answered by the password alone or by the person's own
    /// factor hands its token back to the browser.
    #[test]
    fn only_a_change_needing_no_mailbox_hands_its_token_back() {
        assert!(ChangeProof::PasswordAlone.hands_token_back());
        assert!(ChangeProof::OwnFactor.hands_token_back());
        assert!(!ChangeProof::MailedLink.hands_token_back());
        assert!(!ChangeProof::NotPossible.hands_token_back());
    }

    /// Each answer shows what it asks of the person: nothing, their
    /// mailbox, their factor, or a refusal.
    #[test]
    fn each_answer_shows_what_it_asks() {
        assert_eq!(PasswordAlone.proof(), PersonProof::Nothing);
        assert_eq!(MailedLink.proof(), PersonProof::Mailbox);
        assert_eq!(OwnFactor.proof(), PersonProof::OwnFactor);
        assert_eq!(NotPossible.proof(), PersonProof::Refused);
    }

    /// Removing mail availability never lowers the required proof for any
    /// tested password-change reason and factor state.
    #[test]
    fn a_change_without_mail_never_asks_less_than_with_it() {
        for reason in [Expired, SetByAdmin] {
            for factor in [Enrolled, NotEnrolled] {
                let with_mail = ChangeProof::for_change(reason, Available, factor).proof();
                let without = ChangeProof::for_change(reason, NotSetUp, factor).proof();

                assert!(without >= with_mail, "{reason:?} {factor:?}");
            }
        }
    }
}
