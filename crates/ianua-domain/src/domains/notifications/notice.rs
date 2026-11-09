//! A notice one person sends another by name, through a workflow step.
//!
//! Pat's workflow signs Lee out after a risky sign-in and tells Lee why:
//! "You were signed out. Sign in again and check your devices." The notice
//! lands in Lee's inbox whatever Lee may see, since it was meant for Lee,
//! and the audit trail records that it was sent, to whom and under what
//! title. Its message is kept in Lee's inbox only.
//!
//! A notice may offer to ask for access: "You may ask to join Support."
//! It names the group, so Lee's dashboard can offer the request in one
//! press. Asking still goes through an access request someone approves.

use time::OffsetDateTime;

use crate::domains::notifications::events::NoticeSent;
use crate::domains::notifications::notification::{
    AboutResource, CreateNotificationParams, Notification,
};
use crate::domains::notifications::reach::ToldAs;
use crate::domains::notifications::severity::NotificationSeverity;
use crate::isolation::scope::TenantScope;
use crate::shared::events::event::DomainEvent;
use crate::shared::events::raised::{Raised, Raises, SavedFor};
use crate::types::event_type::NotificationsEvent;
use crate::types::{EventLabel, GroupId, Label, NotificationId, Text, UserId};

/// What a notice is sent with.
pub struct SendNoticeParams {
    /// Its id: the same each time the same step's call sends it, so a call
    /// made again keeps one notice.
    pub id: NotificationId,
    /// The person it is for.
    pub recipient: UserId,
    /// Their name as the audit trail shows it.
    pub recipient_label: EventLabel,
    /// What it says in short.
    pub title: Label,
    /// What else it says.
    pub message: NoticeMessage,
    /// What it offers, if anything.
    pub offer: NoticeOffer,
}

/// What a notice offers its recipient to ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoticeOffer {
    /// Nothing: it only tells.
    Nothing,
    /// To ask to join this group, named as the audit trail shows it.
    JoinGroup(GroupId, EventLabel),
}

impl NoticeOffer {
    /// The kind of notice it makes: an offer of access, or a plain notice.
    #[must_use]
    pub fn event_type(&self) -> NotificationsEvent {
        match self {
            Self::Nothing => NotificationsEvent::NoticeSent,
            Self::JoinGroup(..) => NotificationsEvent::AccessOffered,
        }
    }

    /// The record it is about: the group offered, or none.
    #[must_use]
    pub fn about(&self) -> AboutResource {
        match self {
            Self::Nothing => AboutResource::Nothing,
            Self::JoinGroup(group, _) => AboutResource::Resource(*group.as_uuid()),
        }
    }
}

/// Whether a notice says more than its title.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoticeMessage {
    /// Its title says all.
    TitleOnly,
    /// It says this as well.
    Says(Text),
}

/// A notice on its way to one person's inbox.
#[derive(Debug)]
pub struct Notice<T: TenantScope> {
    recipient: UserId,
    notification: Notification,
    raised: Raised<T>,
}

impl<T: TenantScope> Notice<T> {
    /// A notice to `params.recipient`, unread, shown to them whatever they
    /// hold.
    ///
    /// Raises `notifications.notice_sent`.
    #[must_use]
    pub fn send(params: SendNoticeParams) -> Self {
        let notification = Notification::create(CreateNotificationParams {
            id: params.id,
            event_type: params.offer.event_type().into(),
            severity: NotificationSeverity::Info,
            title: params.title,
            body: match params.message {
                NoticeMessage::TitleOnly => None,
                NoticeMessage::Says(text) => Some(text),
            },
            resource_id: params.offer.about(),
            told_as: ToldAs::Addressee,
        });
        let mut raised = Raised::default();
        raised.raise(NoticeSent {
            notification_id: notification.id(),
            notification_label: EventLabel::of(notification.title().as_str()),
            recipient: params.recipient,
            recipient_label: params.recipient_label,
            offer: params.offer,
            occurred_at: notification.created_at(),
        });
        Self {
            recipient: params.recipient,
            notification,
            raised,
        }
    }

    /// The person it is for.
    #[must_use]
    pub fn recipient(&self) -> &UserId {
        &self.recipient
    }

    /// The notification kept in their inbox.
    #[must_use]
    pub fn notification(&self) -> &Notification {
        &self.notification
    }

    /// When it was sent.
    #[must_use]
    pub fn sent_at(&self) -> OffsetDateTime {
        self.notification.created_at()
    }
}

impl<T: TenantScope> Raises for Notice<T> {
    fn take_events(&mut self, saved_for: &impl SavedFor) -> Vec<DomainEvent> {
        self.raised.take(saved_for)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::authorization::permission::SystemPermission;
    use crate::domains::notifications::reach::NotificationReach;
    use crate::isolation::scope::ResolvedTenant;
    use crate::test_support::events::raised_names;

    /// Pat's workflow tells Lee to check their devices. Lee holds no right
    /// at all, and still sees it, unread; the trail records it was sent.
    #[test]
    fn a_notice_reaches_its_recipient_whatever_they_hold() {
        let mut notice = Notice::<ResolvedTenant>::send(SendNoticeParams {
            id: NotificationId::new(),
            recipient: UserId::new(),
            recipient_label: EventLabel::of("Lee"),
            title: Label::new("title", "You were signed out").unwrap(),
            message: NoticeMessage::Says(
                Text::new("message", "Sign in again and check your devices.").unwrap(),
            ),
            offer: NoticeOffer::Nothing,
        });

        let held: &[SystemPermission] = &[];
        assert!(notice.notification().shows_to(held));
        assert!(!notice.notification().is_read());
        assert_eq!(notice.notification().reach(), NotificationReach::Addressed);
        assert_eq!(raised_names(&mut notice), ["notifications.notice_sent"]);
    }

    /// Pat's workflow offers Lee to ask to join Support. The notice names
    /// the group, so Lee's dashboard can offer the request, and it is
    /// recorded as an offer of access.
    #[test]
    fn a_notice_offering_access_names_the_group() {
        let support = GroupId::new();
        let mut notice = Notice::<ResolvedTenant>::send(SendNoticeParams {
            id: NotificationId::new(),
            recipient: UserId::new(),
            recipient_label: EventLabel::of("Lee"),
            title: Label::new("title", "You may ask to join Support").unwrap(),
            message: NoticeMessage::TitleOnly,
            offer: NoticeOffer::JoinGroup(support, EventLabel::of("Support")),
        });

        assert_eq!(
            notice.notification().resource_id(),
            AboutResource::Resource(*support.as_uuid())
        );
        assert_eq!(notice.notification().reach(), NotificationReach::Addressed);
        assert_eq!(raised_names(&mut notice), ["notifications.access_offered"]);
    }
}
