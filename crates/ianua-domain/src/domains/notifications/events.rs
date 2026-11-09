//! Events raised when a notification is read, a preference changes, or an
//! email could not be delivered.
//!
//! Notifications mostly react to events from other contexts. These events
//! go the other way. The audit trail shows who dismissed a security alert,
//! and the WebSocket stream keeps read state the same across devices.
//!
//! Who read or changed something is the record's actor, which the
//! application names, so no event here carries the reader.

use time::OffsetDateTime;

use crate::domains::branding::email_template::EmailTemplateType;
use crate::domains::notifications::category::NotificationCategory;
use crate::domains::notifications::channel::NotificationChannel;
use crate::domains::notifications::destination::DestinationKind;
use crate::domains::notifications::notice::NoticeOffer;
use crate::shared::events::data::{EventData, RefKind, Reference};
use crate::shared::events::event::{
    DomainEvent, DomainEventCore, organization_event, platform_event, tenant_event,
};
use crate::types::event_type::NotificationsEvent;
use crate::types::{
    Email, EventLabel, EventType, NotificationDestinationId, NotificationId, OrganizationId,
    TenantId, UntrustedText, UserId,
};

/// A notification was marked as read by its recipient.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct NotificationMarkedRead {
    /// The inbox entry acknowledged by its recipient.
    pub(crate) notification_id: NotificationId,
    /// The notification's title. It is copied when the event is raised, so
    /// the audit entry stays readable after the notification is deleted.
    pub(crate) notification_label: EventLabel,
    /// When it was read.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    NotificationMarkedRead => NotificationsEvent::NotificationRead,
    fn payload(&self) -> EventData {
        EventData::new().reference(
            "notification",
            Reference::new(
                RefKind::new("notification"),
                self.notification_id.to_string(),
                self.notification_label.as_str(),
            ),
        )
    }
}

/// A tenant user's read is recorded in the tenant's trail, through
/// [`InboxRead`](crate::domains::notifications::reading::InboxRead).
impl crate::shared::events::raised::TenantEventBody for NotificationMarkedRead {}

/// All notifications were marked as read in bulk.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct AllNotificationsMarkedRead {
    /// How many were marked.
    pub(crate) count: u64,
    /// When the bulk read occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    AllNotificationsMarkedRead => NotificationsEvent::AllNotificationsRead,
    fn payload(&self) -> EventData {
        EventData::new().field("count", self.count.to_string())
    }
}

/// A tenant user's read is recorded in the tenant's trail, through
/// [`InboxRead`](crate::domains::notifications::reading::InboxRead).
impl crate::shared::events::raised::TenantEventBody for AllNotificationsMarkedRead {}

/// A user updated their notification preferences.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct NotificationPreferencesUpdated {
    /// The category that was changed.
    pub(crate) category: NotificationCategory,
    /// The new channel setting.
    pub(crate) new_channel: NotificationChannel,
    /// When the update occurred.
    pub(crate) occurred_at: OffsetDateTime,
}

tenant_event! {
    NotificationPreferencesUpdated => NotificationsEvent::PreferencesUpdated,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("category", self.category.as_str().to_owned())
            .field("channel", self.new_channel.as_str().to_owned())
    }
}

/// A workflow step sent a person a notice by name.
///
/// It names the notice by its title and never carries its message, which
/// stays in the recipient's inbox.
#[derive(Debug, Clone)]
pub struct NoticeSent {
    /// The notification kept in their inbox.
    pub(crate) notification_id: NotificationId,
    /// Its title.
    pub(crate) notification_label: EventLabel,
    /// The person it is for.
    pub(crate) recipient: UserId,
    /// Their name when it was sent.
    pub(crate) recipient_label: EventLabel,
    /// What it offers them, if anything.
    pub(crate) offer: NoticeOffer,
    /// When it was sent.
    pub(crate) occurred_at: OffsetDateTime,
}

impl DomainEventCore for NoticeSent {
    fn event_type(&self) -> EventType {
        self.offer.event_type().into()
    }

    fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    fn payload(&self) -> EventData {
        let offered = match &self.offer {
            NoticeOffer::Nothing => None,
            NoticeOffer::JoinGroup(group, label) => Some(Reference::new(
                RefKind::GROUP,
                group.to_string(),
                label.as_str(),
            )),
        };
        EventData::new()
            .reference(
                "notification",
                Reference::new(
                    RefKind::new("notification"),
                    self.notification_id.to_string(),
                    self.notification_label.as_str(),
                ),
            )
            .reference(
                "recipient",
                Reference::new(
                    RefKind::USER,
                    self.recipient.to_string(),
                    self.recipient_label.as_str(),
                ),
            )
            .optional_reference("group", offered)
    }
}

impl crate::shared::events::raised::TenantEventBody for NoticeSent {}

/// An email could not be delivered after every retry.
///
/// Sign-in and reset links are mailed in the background, so the person who
/// asked never sees a failure. This record is where it shows up.
#[derive(Debug, Clone)]
pub struct MailUndelivered {
    /// Which email it was.
    pub(crate) template: EmailTemplateType,
    /// The address it was for.
    pub(crate) recipient: Email,
    /// How many times delivery was tried.
    pub(crate) attempts: u32,
    /// The last error the mail service gave.
    pub(crate) reason: UntrustedText,
    /// When delivery was given up on.
    pub(crate) occurred_at: OffsetDateTime,
}

/// Whose mail a lost mail was, so it is recorded in the right trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailSentFor {
    /// A tenant's mail, such as a reset link to one of its people.
    Tenant(TenantId),
    /// The platform's own mail, such as one to an organization member.
    Platform,
}

impl From<Option<TenantId>> for MailSentFor {
    /// A mail's tenant, or the platform's when it has none.
    fn from(tenant: Option<TenantId>) -> Self {
        tenant.map_or(Self::Platform, Self::Tenant)
    }
}

/// A mail the delivery worker gave up on, as it saw it.
#[derive(Debug, Clone)]
pub struct UndeliveredMail {
    /// Which email it was.
    pub template: EmailTemplateType,
    /// The address it was for.
    pub recipient: Email,
    /// How many times delivery was tried.
    pub attempts: u32,
    /// The last error the mail service gave.
    pub reason: UntrustedText,
}

impl MailUndelivered {
    /// The record that `mail` was given up on, in the trail of the tenant
    /// it was sent for, or the platform's for the platform's own mail. A
    /// tenant's lost mail is its own to see: its reset link went to one of
    /// its people, and whoever runs its mail is the one who can act.
    ///
    /// No aggregate changes when a mail is given up on; the delivery worker
    /// observes it, and this is how it records what it saw. The time is now.
    #[must_use]
    pub fn observed(mail: UndeliveredMail, sent_for: MailSentFor) -> DomainEvent {
        let body = Self {
            template: mail.template,
            recipient: mail.recipient,
            attempts: mail.attempts,
            reason: mail.reason,
            occurred_at: crate::shared::clock::now(),
        };
        match sent_for {
            MailSentFor::Tenant(tenant_id) => {
                crate::shared::events::raised::scoped(tenant_id, body)
            }
            MailSentFor::Platform => DomainEvent::platform(Box::new(body)),
        }
    }
}

/// A tenant's lost mail is recorded in the tenant's trail, through
/// [`MailUndelivered::observed`].
impl crate::shared::events::raised::TenantEventBody for MailUndelivered {}

platform_event! {
    MailUndelivered => NotificationsEvent::MailUndelivered,
    fn payload(&self) -> EventData {
        EventData::new()
            .field("template", self.template.name())
            .field("recipient", self.recipient.as_str())
            .field("attempts", self.attempts.to_string())
            .field("reason", self.reason.as_str())
    }
}

/// An organization added a place outside the app its notifications go to.
///
/// The payload names the destination and its kind, never where it points:
/// a Slack or Teams address is itself the key that posts to the channel.
#[derive(Debug)]
pub struct DestinationAdded {
    /// The organization that owns the destination.
    pub(crate) organization_id: OrganizationId,
    /// The newly configured endpoint that may receive organization notices.
    pub(crate) destination_id: NotificationDestinationId,
    /// Its name when the record was made.
    pub(crate) destination_label: EventLabel,
    /// Where it delivers: Slack, Teams or a webhook.
    pub(crate) kind: DestinationKind,
    /// When it was added.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    DestinationAdded => NotificationsEvent::DestinationAdded,
    fn payload(&self) -> EventData {
        destination_payload(self.destination_id, &self.destination_label, self.kind)
    }
}

/// An organization changed one of its destinations: its name, where it
/// points or what it receives.
#[derive(Debug)]
pub struct DestinationChanged {
    /// The organization that owns the destination.
    pub(crate) organization_id: OrganizationId,
    /// The endpoint whose configuration or subscribed categories changed.
    pub(crate) destination_id: NotificationDestinationId,
    /// Its name after the change.
    pub(crate) destination_label: EventLabel,
    /// Where it delivers after the change.
    pub(crate) kind: DestinationKind,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    DestinationChanged => NotificationsEvent::DestinationChanged,
    fn payload(&self) -> EventData {
        destination_payload(self.destination_id, &self.destination_label, self.kind)
    }
}

/// An organization stopped sending to one of its destinations for now.
#[derive(Debug)]
pub struct DestinationPaused {
    /// The organization that owns the destination.
    pub(crate) organization_id: OrganizationId,
    /// The endpoint temporarily excluded from notice delivery.
    pub(crate) destination_id: NotificationDestinationId,
    /// Its name when it was paused.
    pub(crate) destination_label: EventLabel,
    /// Where it delivers.
    pub(crate) kind: DestinationKind,
    /// When it was paused.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    DestinationPaused => NotificationsEvent::DestinationPaused,
    fn payload(&self) -> EventData {
        destination_payload(self.destination_id, &self.destination_label, self.kind)
    }
}

/// An organization sent to a paused destination again.
#[derive(Debug)]
pub struct DestinationResumed {
    /// The organization that owns the destination.
    pub(crate) organization_id: OrganizationId,
    /// The endpoint allowed to receive notices again.
    pub(crate) destination_id: NotificationDestinationId,
    /// Its name when it was resumed.
    pub(crate) destination_label: EventLabel,
    /// Where it delivers.
    pub(crate) kind: DestinationKind,
    /// When it was resumed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    DestinationResumed => NotificationsEvent::DestinationResumed,
    fn payload(&self) -> EventData {
        destination_payload(self.destination_id, &self.destination_label, self.kind)
    }
}

/// An organization removed one of its destinations.
#[derive(Debug)]
pub struct DestinationRemoved {
    /// The organization that owned the destination.
    pub(crate) organization_id: OrganizationId,
    /// The endpoint permanently removed from notice delivery.
    pub(crate) destination_id: NotificationDestinationId,
    /// Its name when it was removed, so the record reads after it is gone.
    pub(crate) destination_label: EventLabel,
    /// Where it delivered.
    pub(crate) kind: DestinationKind,
    /// When it was removed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    DestinationRemoved => NotificationsEvent::DestinationRemoved,
    fn payload(&self) -> EventData {
        destination_payload(self.destination_id, &self.destination_label, self.kind)
    }
}

/// An organization member changed how one category reaches them.
///
/// The member is the record's actor, so the payload holds only the choice.
#[derive(Debug)]
pub struct MemberPreferencesUpdated {
    /// The organization the member belongs to.
    pub(crate) organization_id: OrganizationId,
    /// The category that changed.
    pub(crate) category: NotificationCategory,
    /// The channel it now goes to.
    pub(crate) channel: NotificationChannel,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

organization_event! {
    MemberPreferencesUpdated => NotificationsEvent::MemberPreferencesUpdated,
    fn payload(&self) -> EventData {
        preference_payload(self.category, self.channel)
    }
}

/// An operator changed how one category reaches them.
///
/// The operator is the record's actor, so the payload holds only the
/// choice.
#[derive(Debug)]
pub struct OperatorPreferencesUpdated {
    /// The category that changed.
    pub(crate) category: NotificationCategory,
    /// The channel it now goes to.
    pub(crate) channel: NotificationChannel,
    /// When it changed.
    pub(crate) occurred_at: OffsetDateTime,
}

platform_event! {
    OperatorPreferencesUpdated => NotificationsEvent::OperatorPreferencesUpdated,
    fn payload(&self) -> EventData {
        preference_payload(self.category, self.channel)
    }
}

/// What every destination record says: the destination by id and name, and
/// its kind. Never the address it posts to.
fn destination_payload(
    id: NotificationDestinationId,
    label: &EventLabel,
    kind: DestinationKind,
) -> EventData {
    EventData::new()
        .reference(
            "destination",
            Reference::new(
                RefKind::new("notification_destination"),
                id.to_string(),
                label.as_str(),
            ),
        )
        .field("kind", kind.as_str())
}

/// What a preference record says: the category and its new channel.
fn preference_payload(category: NotificationCategory, channel: NotificationChannel) -> EventData {
    EventData::new()
        .field("category", category.as_str())
        .field("channel", channel.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::events::data::FieldValue;
    use crate::shared::events::event::DomainEventCore;
    use crate::types::EventType;

    /// A user reads the notification "Signing key rotated". The event is
    /// recorded as a notification read.
    #[test]
    fn marked_read_event_carries_context() {
        let e = NotificationMarkedRead {
            notification_id: NotificationId::new(),
            notification_label: EventLabel::of("Signing key rotated"),
            occurred_at: crate::shared::clock::now(),
        };
        assert_eq!(
            e.event_type(),
            EventType::Notifications(NotificationsEvent::NotificationRead)
        );
    }

    /// A user marks 42 notifications read at once. The event keeps the
    /// count and is recorded as a bulk read.
    #[test]
    fn bulk_read_event_carries_count() {
        let e = AllNotificationsMarkedRead {
            count: 42,
            occurred_at: crate::shared::clock::now(),
        };
        assert_eq!(e.count, 42);
        assert_eq!(
            e.event_type(),
            EventType::Notifications(NotificationsEvent::AllNotificationsRead)
        );
    }

    /// A user turns off crypto notifications. The event keeps the category
    /// and the disabled channel, and is recorded as a preference update.
    #[test]
    fn preferences_updated_event() {
        let e = NotificationPreferencesUpdated {
            category: NotificationCategory::Crypto,
            new_channel: NotificationChannel::Disabled,
            occurred_at: crate::shared::clock::now(),
        };
        assert_eq!(e.category, NotificationCategory::Crypto);
        assert!(e.new_channel.is_disabled());
        assert_eq!(
            e.event_type(),
            EventType::Notifications(NotificationsEvent::PreferencesUpdated)
        );
    }

    /// A user reads "Signing key rotated". The payload links that
    /// notification by id and title, and leaves the reader out because the
    /// audit record names the actor already.
    #[test]
    fn marked_read_payload_references_the_notification_and_omits_the_reader() {
        let e = NotificationMarkedRead {
            notification_id: NotificationId::new(),
            notification_label: EventLabel::of("Signing key rotated"),
            occurred_at: crate::shared::clock::now(),
        };

        let p = e.payload();

        let Some(FieldValue::Reference(r)) = p.value("notification") else {
            panic!("expected a notification reference");
        };
        assert_eq!(r.id(), e.notification_id.to_string());
        assert_eq!(r.label(), "Signing key rotated");
        assert_eq!(
            p.get("read_by"),
            None,
            "the reader is the audit record's actor"
        );
    }

    /// A user marks 42 notifications read. The payload holds the count 42
    /// and leaves the reader to the audit record's actor.
    #[test]
    fn bulk_read_payload_keeps_the_count_and_omits_the_reader() {
        let e = AllNotificationsMarkedRead {
            count: 42,
            occurred_at: crate::shared::clock::now(),
        };

        let p = e.payload();

        assert_eq!(p.get("count"), Some("42"));
        assert_eq!(p.get("read_by"), None);
    }

    /// A user turns off crypto notifications. The payload holds `crypto`
    /// and `disabled`, and leaves the user to the audit record's actor.
    #[test]
    fn preferences_payload_keeps_the_setting_and_omits_the_updater() {
        let e = NotificationPreferencesUpdated {
            category: NotificationCategory::Crypto,
            new_channel: NotificationChannel::Disabled,
            occurred_at: crate::shared::clock::now(),
        };

        let p = e.payload();

        assert_eq!(p.get("category"), Some("crypto"));
        assert_eq!(p.get("channel"), Some("disabled"));
        assert_eq!(p.get("updated_by"), None);
    }

    /// Adding a Slack destination produces a two-field payload identifying
    /// its kind without exposing the webhook URL.
    #[test]
    fn a_destination_record_names_the_kind_and_holds_no_address() {
        let e = DestinationAdded {
            organization_id: OrganizationId::new(),
            destination_id: NotificationDestinationId::new(),
            destination_label: EventLabel::of("On-call Slack"),
            kind: DestinationKind::Slack,
            occurred_at: crate::shared::clock::now(),
        };

        let p = e.payload();

        assert_eq!(p.get("kind"), Some("slack"));
        assert_eq!(p.get("url"), None);
        assert_eq!(p.fields().len(), 2);
    }

    /// Olivia, an operator, turns off branding notifications. The record
    /// holds the category and channel, and names no tenant.
    #[test]
    fn an_operator_preference_record_holds_the_choice() {
        let e = OperatorPreferencesUpdated {
            category: NotificationCategory::Branding,
            channel: NotificationChannel::Disabled,
            occurred_at: crate::shared::clock::now(),
        };

        let p = e.payload();

        assert_eq!(p.get("category"), Some("branding"));
        assert_eq!(p.get("channel"), Some("disabled"));
    }

    fn magic_link_to_ann() -> UndeliveredMail {
        UndeliveredMail {
            template: EmailTemplateType::MagicLink,
            recipient: Email::new("ann@acme.test").unwrap(),
            attempts: 5,
            reason: UntrustedText::record("mailbox full"),
        }
    }

    /// The worker gives up on the platform's sign-in link to ann@acme.test
    /// after five tries. The observation is a platform event naming the
    /// template, the address, the tries and the last answer.
    #[test]
    fn an_undelivered_mail_is_observed_with_what_the_worker_saw() {
        let event = MailUndelivered::observed(magic_link_to_ann(), MailSentFor::Platform);

        let payload = event.payload();
        assert_eq!(
            event.event_type().to_string(),
            "notifications.mail_undelivered"
        );
        assert_eq!(event.tenant_id(), None);
        assert_eq!(payload.get("recipient"), Some("ann@acme.test"));
        assert_eq!(payload.get("attempts"), Some("5"));
        assert_eq!(payload.get("reason"), Some("mailbox full"));
    }

    /// An undelivered tenant sign-in link produces an event scoped to that
    /// tenant's audit trail.
    #[test]
    fn a_tenants_undelivered_mail_is_in_its_own_trail() {
        let acme = crate::types::TenantId::new();

        let event = MailUndelivered::observed(magic_link_to_ann(), MailSentFor::Tenant(acme));

        assert_eq!(event.tenant_id(), Some(&acme));
    }
}
