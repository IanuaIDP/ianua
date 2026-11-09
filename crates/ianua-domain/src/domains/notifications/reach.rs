//! Whom a notification shows to.
//!
//! A notification is kept in one person's inbox, and shows there while they
//! hold the right its category needs. One exception: the person an event is
//! about is always told what changes how safe their own account is. Carol
//! may see no users at all. Without this, an admin locks her out, resets
//! her factors or gives her account a role, and she is the one person who
//! never hears of it. The exception covers her own account only: she still
//! sees nothing about anyone else's in that category.

use crate::domains::authorization::permission::SystemPermission;
use crate::domains::notifications::channel::NotificationChannel;
use crate::shared::model::two_cases::two_cases;
use crate::types::EventType;
use crate::types::event_type::{
    AuthenticationEvent, AuthorizationEvent, IdentityEvent, NotificationsEvent,
};

/// Why a person is told about an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToldAs {
    /// They run what it happened to: an administrator, a member of the
    /// organization, an operator.
    Overseer,
    /// It happened to their own account.
    Subject,
    /// A workflow step sent it to them by name.
    Addressee,
}

/// How a notification reaches the person whose inbox keeps it, which
/// decides whether it shows to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationReach {
    /// It shows while they hold the right its category needs.
    ByRights,
    /// It is about their own account, after something that changes how safe
    /// the account is. It shows to them whatever they hold, and cannot be
    /// switched off.
    OwnAccount,
    /// A workflow step sent it to them by name, as the person the run acts
    /// for. It shows to them whatever they hold: it was meant for them, and
    /// says only what its sender chose to say.
    Addressed,
}

two_cases! {
    /// Whether the address a person is mailed at was proved to be theirs.
    pub enum MailAddress {
        /// Proved, by a link, an invitation or a trusted provider.
        Confirmed => true,
        /// Set on someone else's word and never proved.
        Unconfirmed => false,
    }
}

impl NotificationReach {
    /// How someone told about an event of `event_type` as `told_as` is
    /// reached: on their own account's safety whatever they hold, and by
    /// their rights otherwise.
    #[must_use]
    pub fn of(event_type: &EventType, told_as: ToldAs) -> Self {
        match told_as {
            ToldAs::Subject if concerns_account_safety(event_type) => Self::OwnAccount,
            ToldAs::Addressee if is_addressed_notice(event_type) => Self::Addressed,
            ToldAs::Subject | ToldAs::Addressee | ToldAs::Overseer => Self::ByRights,
        }
    }

    /// Whether a notification needing `required` shows to someone holding
    /// `held`, each wider permission listed with all it covers.
    #[must_use]
    pub fn shows(self, required: SystemPermission, held: &[SystemPermission]) -> bool {
        match self {
            Self::OwnAccount | Self::Addressed => true,
            Self::ByRights => held.contains(&required),
        }
    }

    /// How the person is reached, given the channel they `chose` for the
    /// category and whether their `address` was proved theirs.
    ///
    /// By rights, as they chose. On their own account, in the app and by
    /// mail whatever they chose: a locked or switched-off account cannot
    /// sign in to read it, and whoever took over an account could otherwise
    /// switch the category off first. Mail goes only to a proved address,
    /// so an address set on someone else's word is not sent what happened
    /// to the account.
    #[must_use]
    pub fn channel(self, chose: NotificationChannel, address: MailAddress) -> NotificationChannel {
        match (self, address) {
            (Self::ByRights | Self::Addressed, _) => chose,
            (Self::OwnAccount, MailAddress::Confirmed) => NotificationChannel::InAppAndEmail,
            (Self::OwnAccount, MailAddress::Unconfirmed) => NotificationChannel::InApp,
        }
    }

    /// The name storage keeps it under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ByRights => "by_rights",
            Self::OwnAccount => "own_account",
            Self::Addressed => "addressed",
        }
    }

    /// The reach a stored name stands for, if it names one.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [Self::ByRights, Self::OwnAccount, Self::Addressed]
            .into_iter()
            .find(|reach| reach.as_str() == value)
    }
}

/// Whether an event of `event_type` is a notice a workflow step sent to one
/// person by name, telling them or offering them access.
#[must_use]
pub(crate) fn is_addressed_notice(event_type: &EventType) -> bool {
    matches!(
        event_type,
        EventType::Notifications(
            NotificationsEvent::NoticeSent | NotificationsEvent::AccessOffered
        )
    )
}

/// Whether an event of `event_type` changes how safe the account it is
/// about is, so the account's holder is always told: how they sign in, what
/// they may do, whether they may sign in at all, and who acts as them.
#[must_use]
pub(crate) fn concerns_account_safety(event_type: &EventType) -> bool {
    match event_type {
        EventType::Authentication(event) => authentication_safety(*event),
        EventType::Identity(event) => identity_safety(*event),
        EventType::Authorization(event) => authorization_safety(*event),
        EventType::Agents(_)
        | EventType::Branding(_)
        | EventType::Crypto(_)
        | EventType::Federation(_)
        | EventType::OAuth(_)
        | EventType::Operator(_)
        | EventType::Organization(_)
        | EventType::Proxy(_)
        | EventType::Routing(_)
        | EventType::Signals(_)
        | EventType::Tenant(_)
        | EventType::Notifications(_)
        | EventType::Messaging(_)
        | EventType::Consumers(_)
        | EventType::Webhooks(_)
        | EventType::Workflows(_) => false,
    }
}

/// Whether an identity event changes how safe its account is: whether it
/// may sign in, where its mail goes, its password, and who acts as it.
fn identity_safety(event: IdentityEvent) -> bool {
    matches!(
        event,
        IdentityEvent::UserStatusChanged
            | IdentityEvent::EmailChanged
            | IdentityEvent::PasswordReset
            | IdentityEvent::SupportImpersonationStarted
            | IdentityEvent::SupportImpersonationEnded
    )
}

/// Whether an authorization event changes what its account may do.
fn authorization_safety(event: AuthorizationEvent) -> bool {
    matches!(
        event,
        AuthorizationEvent::RoleAssigned
            | AuthorizationEvent::RoleRevoked
            | AuthorizationEvent::RoleAssignmentExpired
            | AuthorizationEvent::GroupMemberAdded
            | AuthorizationEvent::GroupMemberRemoved
            | AuthorizationEvent::GroupMembershipExpired
    )
}

/// Whether an authentication event changes how safe its account is.
fn authentication_safety(event: AuthenticationEvent) -> bool {
    matches!(
        event,
        AuthenticationEvent::SessionRevoked
            | AuthenticationEvent::SessionSuspended
            | AuthenticationEvent::PasswordChanged
            | AuthenticationEvent::PasswordResetCompleted
            | AuthenticationEvent::PasswordBreachDetected
            | AuthenticationEvent::PasskeyRegistered
            | AuthenticationEvent::PasskeyRemoved
            | AuthenticationEvent::MfaEnrolled
            | AuthenticationEvent::MfaUnenrolled
            | AuthenticationEvent::FactorsReset
            | AuthenticationEvent::DeviceTrusted
            | AuthenticationEvent::DeviceRevoked
            | AuthenticationEvent::AccountLockedOut
            | AuthenticationEvent::RecoveryCodesGenerated
            | AuthenticationEvent::RecoveryCodeUsed
            | AuthenticationEvent::BreakGlassGranted
            | AuthenticationEvent::BreakGlassRevoked
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::UserAction;
    use crate::types::event_type::MessagingEvent;

    const LOCKED: EventType = EventType::Identity(IdentityEvent::UserStatusChanged);

    /// An admin locks Carol's account. Carol, the account's holder, is
    /// reached on her own account; the admins who run the tenant are
    /// reached by their rights.
    #[test]
    fn the_holder_of_a_locked_account_is_reached_on_their_own_account() {
        assert_eq!(
            NotificationReach::of(&LOCKED, ToldAs::Subject),
            NotificationReach::OwnAccount
        );
        assert_eq!(
            NotificationReach::of(&LOCKED, ToldAs::Overseer),
            NotificationReach::ByRights
        );
    }

    /// Carol is renamed. That changes nothing about how safe her account
    /// is, so she hears of it only if she may see users.
    #[test]
    fn a_rename_reaches_its_subject_only_by_rights() {
        let renamed = EventType::Identity(IdentityEvent::UserRenamed);

        assert_eq!(
            NotificationReach::of(&renamed, ToldAs::Subject),
            NotificationReach::ByRights
        );
    }

    /// Carol holds no right at all. A notice about her own account shows to
    /// her; one reaching her by rights about users does not.
    #[test]
    fn an_own_account_notice_shows_whatever_the_reader_holds() {
        let required = SystemPermission::Users(UserAction::View);

        assert!(NotificationReach::OwnAccount.shows(required, &[]));
        assert!(!NotificationReach::ByRights.shows(required, &[]));
        assert!(NotificationReach::ByRights.shows(required, &[required]));
    }

    /// Disabling notifications leaves account-safety notices in-app and
    /// mails only proved addresses; ordinary notices remain disabled.
    #[test]
    fn an_own_account_notice_cannot_be_switched_off() {
        let off = NotificationChannel::Disabled;

        assert_eq!(
            NotificationReach::OwnAccount.channel(off, MailAddress::Confirmed),
            NotificationChannel::InAppAndEmail
        );
        assert_eq!(
            NotificationReach::OwnAccount.channel(off, MailAddress::Unconfirmed),
            NotificationChannel::InApp
        );
        assert_eq!(
            NotificationReach::ByRights.channel(off, MailAddress::Confirmed),
            off
        );
    }

    /// A paused topic is about no account, so nobody is told of it whatever
    /// they hold.
    #[test]
    fn an_event_about_no_account_is_not_an_account_safety_event() {
        let paused = EventType::Messaging(MessagingEvent::TopicPaused);

        assert!(!concerns_account_safety(&paused));
    }

    /// Both reaches are stored by name and read back.
    #[test]
    fn a_reach_reads_back_from_its_stored_name() {
        for reach in [NotificationReach::ByRights, NotificationReach::OwnAccount] {
            assert_eq!(NotificationReach::parse(reach.as_str()), Some(reach));
        }
        assert_eq!(NotificationReach::parse("anyone"), None);
    }
}
