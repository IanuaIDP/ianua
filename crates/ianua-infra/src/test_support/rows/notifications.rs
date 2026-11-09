//! Rows of the notifications context: notifications of a few kinds, and an
//! organization's destinations.

use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::destination::{
    DestinationEndpointRow, DestinationState, NotificationDestination, NotificationDestinationRow,
};
use ianua_domain::domains::notifications::notification::{
    AboutResource, Notification, NotificationRow, ReadState, title_label,
};
use ianua_domain::domains::notifications::reach::NotificationReach;
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::types::event_type::{CryptoEvent, IdentityEvent, NotificationsEvent};
use ianua_domain::types::{
    EventType, Label, NotificationDestinationId, NotificationId, OrganizationId, PublicHttpsUrl,
    SealedSecret, Text,
};
use uuid::Uuid;

use crate::test_support::rows::at;

/// A user registering: filed under identity, shown by the right to see
/// users.
#[must_use]
pub fn user_registered() -> EventType {
    EventType::Identity(IdentityEvent::UserRegistered)
}

/// A signing key rotating: filed under crypto, shown by the right to see
/// keys.
#[must_use]
pub fn key_rotated() -> EventType {
    EventType::Crypto(CryptoEvent::KeyRotated)
}

/// An unread notice of `event_type` at `severity`, made `seconds` after the
/// fixed moment, reaching its reader by their rights.
///
/// # Panics
///
/// Never: the title and body are valid.
#[must_use]
pub fn notification_row(
    event_type: EventType,
    severity: NotificationSeverity,
    seconds: i64,
) -> NotificationRow {
    NotificationRow {
        id: NotificationId::new(),
        event_type,
        severity,
        title: title_label(format!("{} happened", event_type.as_str())).expect("a valid title"),
        body: Some(Text::new("body", "Ann did it").expect("a valid body")),
        resource_id: AboutResource::Resource(Uuid::now_v7()),
        reach: NotificationReach::ByRights,
        read: ReadState::Unread,
        created_at: at(seconds),
    }
}

/// An unread notice of `event_type`, informational, made `seconds` after
/// the fixed moment.
///
/// # Panics
///
/// When the row breaks a rule of the notification, which is a mistake in
/// the test.
#[must_use]
pub fn notice(event_type: EventType, seconds: i64) -> Notification {
    Notification::reconstitute(notification_row(
        event_type,
        NotificationSeverity::Info,
        seconds,
    ))
    .expect("a consistent notification")
}

/// An unread notice to its reader that their own account was locked, which
/// shows to them whatever they hold.
///
/// # Panics
///
/// Never: an account lock concerns the account's safety.
#[must_use]
pub fn own_account_notice(seconds: i64) -> Notification {
    Notification::reconstitute(NotificationRow {
        reach: NotificationReach::OwnAccount,
        ..notification_row(
            EventType::Identity(IdentityEvent::UserStatusChanged),
            NotificationSeverity::Critical,
            seconds,
        )
    })
    .expect("a consistent notification")
}

/// A notice a workflow step sent the reader by name, made `seconds` after
/// the fixed moment.
///
/// # Panics
///
/// Never: the row is consistent.
#[must_use]
pub fn addressed_notice(seconds: i64) -> Notification {
    Notification::reconstitute(NotificationRow {
        reach: NotificationReach::Addressed,
        ..notification_row(
            EventType::Notifications(NotificationsEvent::NoticeSent),
            NotificationSeverity::Info,
            seconds,
        )
    })
    .expect("a consistent notification")
}

/// An active Slack destination of `organization`, for critical
/// authentication and organization alerts, added at the fixed moment.
///
/// # Panics
///
/// Never: the name and sealed address are valid.
#[must_use]
pub fn slack_destination_row(organization: OrganizationId) -> NotificationDestinationRow {
    NotificationDestinationRow {
        id: NotificationDestinationId::new(),
        organization_id: organization,
        name: Label::new("name", "On-call Slack").expect("a valid name"),
        endpoint: DestinationEndpointRow::Slack {
            hook: SealedSecret::new("v1.c2xhY2staG9vaw").expect("a sealed address"),
        },
        categories: vec![
            NotificationCategory::Authentication,
            NotificationCategory::Organization,
        ],
        minimum_severity: NotificationSeverity::Critical,
        state: DestinationState::Active,
        created_at: at(0),
        updated_at: at(0),
    }
}

/// An active webhook destination of `organization` for every identity
/// notice, added `seconds` after the fixed moment.
///
/// # Panics
///
/// Never: the name, address and sealed secret are valid.
#[must_use]
pub fn webhook_destination_row(
    organization: OrganizationId,
    seconds: i64,
) -> NotificationDestinationRow {
    NotificationDestinationRow {
        id: NotificationDestinationId::new(),
        organization_id: organization,
        name: Label::new("name", "Acme hook").expect("a valid name"),
        endpoint: DestinationEndpointRow::Webhook {
            url: PublicHttpsUrl::new("https://hooks.acme.com/alerts").expect("a public HTTPS URL"),
            signing_secret: SealedSecret::new("v1.c2lnbmluZw").expect("a sealed secret"),
        },
        categories: vec![NotificationCategory::Identity],
        minimum_severity: NotificationSeverity::Info,
        state: DestinationState::Active,
        created_at: at(seconds),
        updated_at: at(seconds),
    }
}

/// The destination `row` describes.
///
/// # Panics
///
/// When the row breaks a rule of the destination, which is a mistake in the
/// test.
#[must_use]
pub fn destination(row: NotificationDestinationRow) -> NotificationDestination {
    NotificationDestination::reconstitute(row).expect("a consistent destination")
}
