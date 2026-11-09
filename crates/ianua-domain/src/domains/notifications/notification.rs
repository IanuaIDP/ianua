//! One in-app notification, for any kind of user.

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::domains::authorization::permission::SystemPermission;
use crate::domains::notifications::category::NotificationCategory;
use crate::domains::notifications::reach::{
    NotificationReach, ToldAs, concerns_account_safety, is_addressed_notice,
};
use crate::domains::notifications::severity::NotificationSeverity;
use crate::shared::errors::DomainError;
use crate::shared::model::row_check::RowCheck;
use crate::shared::model::two_cases::two_cases;
use crate::shared::validation::ValidationError;
use crate::types::{AuditRecordId, EventType, Label, NotificationId, Text};

/// The longest a notification title may be, in characters.
///
/// It is longer than the usual label limit. A title names the scope, the
/// subject and the actor, and that sentence must fit.
pub(crate) const TITLE_MAX_CHARS: usize = 200;

/// A checked notification title.
///
/// # Errors
///
/// - [`ValidationError`] when the value is empty.
/// - [`ValidationError`] when the value is longer than `TITLE_MAX_CHARS`.
/// - [`ValidationError`] when the value contains control characters.
pub fn title_label(value: impl Into<String>) -> Result<Label, ValidationError> {
    Label::with_max_length("title", value, TITLE_MAX_CHARS)
}

/// How long a notification is kept from when it was made, read or not.
///
/// Notifications are an activity feed: what happened stays in the audit
/// trail, which keeps it as long as the tenant's compliance asks.
pub const KEPT_FOR: Duration = Duration::days(90);

/// The moment before which every notification is removed, at `now`.
#[must_use]
pub fn kept_since(now: OffsetDateTime) -> OffsetDateTime {
    now.saturating_sub(KEPT_FOR)
}

two_cases! {
    /// Whether the recipient has read a notification.
    pub enum ReadState {
        /// Read.
        Read => true,
        /// Not yet.
        Unread => false,
    }
}

/// The record a notification is about, or that it is about none.
///
/// It can be any kind of record, such as a user, a key or a route. So its
/// id is a bare UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AboutResource {
    /// It is about no one record.
    Nothing,
    /// This record.
    Resource(Uuid),
}

impl AboutResource {
    /// The record a stored column names. An empty column means
    /// [`Nothing`](Self::Nothing).
    #[must_use]
    pub fn from_stored(resource: Option<Uuid>) -> Self {
        resource.map_or(Self::Nothing, Self::Resource)
    }
}

impl From<AboutResource> for Option<Uuid> {
    fn from(about: AboutResource) -> Self {
        match about {
            AboutResource::Nothing => None,
            AboutResource::Resource(id) => Some(id),
        }
    }
}

/// One in-app notification.
///
/// The fan-out worker creates notifications when events occur. Each is
/// stored in the table for its kind of user: platform, organization, or
/// the tenant's own schema. The REST and WebSocket endpoints read them.
///
/// Only someone holding [`required_permission`](Self::required_permission)
/// may see it. That permission always comes from the event type. The one
/// exception is a notice to the person an event is about, of something
/// that changes how safe their own account is: see
/// [`NotificationReach`].
#[derive(Debug, Clone)]
pub struct Notification {
    id: NotificationId,
    event_type: EventType,
    category: NotificationCategory,
    severity: NotificationSeverity,
    title: Label,
    body: Option<Text>,
    resource_id: AboutResource,
    required_permission: SystemPermission,
    reach: NotificationReach,
    read: ReadState,
    created_at: OffsetDateTime,
}

impl NotificationId {
    /// The id of the notification one recipient gets about one recorded
    /// event: the same every time for the same record and recipient.
    ///
    /// Events are delivered at least once, so the fan-out may run twice for
    /// one record. With this id the second run finds the notification the
    /// first one kept, and the recipient is told once.
    #[must_use]
    pub fn delivered(record: &AuditRecordId, recipient: &Uuid) -> Self {
        Self::from_uuid(Uuid::new_v5(record.as_uuid(), recipient.as_bytes()))
    }
}

/// What a new notification is created from.
pub struct CreateNotificationParams {
    /// Its id: [`NotificationId::delivered`] for one told about a recorded
    /// event.
    pub id: NotificationId,
    /// The event type that caused this notification.
    ///
    /// The category, and so the permission needed to see it, comes from this.
    /// It is never given separately. Sam may see branding but not signing
    /// keys. With a separate category, a signing key event filed as branding
    /// would reach Sam.
    pub event_type: EventType,
    /// The severity level.
    pub severity: NotificationSeverity,
    /// Short summary of what happened.
    pub title: Label,
    /// Optional longer description.
    pub body: Option<Text>,
    /// The record the event is about, such as a user, a key or a route, or
    /// none.
    pub resource_id: AboutResource,
    /// Why the person it is for is told: they run what it happened to, or
    /// it happened to their own account.
    pub told_as: ToldAs,
}

/// A notification as storage holds it.
pub struct NotificationRow {
    /// Unique notification identifier.
    pub id: NotificationId,
    /// The event type.
    ///
    /// The category and the permission needed to see the notification come
    /// from it again on every read. No stored permission is trusted, so a
    /// changed row cannot show the notification to someone who may not see
    /// it.
    pub event_type: EventType,
    /// The severity level.
    pub severity: NotificationSeverity,
    /// Short summary of what happened.
    pub title: Label,
    /// Optional extended description.
    pub body: Option<Text>,
    /// The record the event is about, or none.
    pub resource_id: AboutResource,
    /// How it reaches the recipient: by their rights, or on their own
    /// account.
    pub reach: NotificationReach,
    /// Whether the recipient has read this notification.
    pub read: ReadState,
    /// When the notification was created.
    pub created_at: OffsetDateTime,
}

impl Notification {
    /// Creates a new unread notification.
    #[must_use]
    pub fn create(params: CreateNotificationParams) -> Self {
        let category = NotificationCategory::from_event_type(&params.event_type);
        Self {
            id: params.id,
            event_type: params.event_type,
            category,
            severity: params.severity,
            title: params.title,
            body: params.body,
            resource_id: params.resource_id,
            required_permission: category.required_permission(),
            reach: NotificationReach::of(&params.event_type, params.told_as),
            read: ReadState::Unread,
            created_at: crate::shared::clock::now(),
        }
    }

    /// Rebuilds a notification from storage.
    ///
    /// The category and the permission needed to see it come from the event
    /// type.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the row reaches its reader on
    ///   their own account for an event that changes nothing about how safe
    ///   an account is, or as sent to them by name for anything but a
    ///   notice. No notification like it could have been made, and it would
    ///   show to someone who may not see its category.
    pub fn reconstitute(row: NotificationRow) -> Result<Self, DomainError> {
        RowCheck::of("notification")
            .holds(
                row.reach != NotificationReach::OwnAccount
                    || concerns_account_safety(&row.event_type),
                "shown on the reader's own account for an event about no account's safety",
            )
            .holds(
                row.reach != NotificationReach::Addressed || is_addressed_notice(&row.event_type),
                "sent to the reader by name for something that is no notice",
            )
            .finish()?;
        let category = NotificationCategory::from_event_type(&row.event_type);
        Ok(Self {
            id: row.id,
            event_type: row.event_type,
            category,
            severity: row.severity,
            title: row.title,
            body: row.body,
            resource_id: row.resource_id,
            required_permission: category.required_permission(),
            reach: row.reach,
            read: row.read,
            created_at: row.created_at,
        })
    }

    /// Unique notification identifier.
    #[must_use]
    pub fn id(&self) -> NotificationId {
        self.id
    }

    /// The event type that caused this notification.
    #[must_use]
    pub fn event_type(&self) -> &EventType {
        &self.event_type
    }

    /// The notification category.
    #[must_use]
    pub fn category(&self) -> NotificationCategory {
        self.category
    }

    /// The severity level.
    #[must_use]
    pub fn severity(&self) -> NotificationSeverity {
        self.severity
    }

    /// Short summary of what happened.
    #[must_use]
    pub fn title(&self) -> &Label {
        &self.title
    }

    /// Optional extended description.
    #[must_use]
    pub fn body(&self) -> Option<&Text> {
        self.body.as_ref()
    }

    /// The record the event is about, or none.
    #[must_use]
    pub fn resource_id(&self) -> AboutResource {
        self.resource_id
    }

    /// The system permission required to see this notification.
    #[must_use]
    pub fn required_permission(&self) -> SystemPermission {
        self.required_permission
    }

    /// How it reaches the recipient: by their rights, or on their own
    /// account.
    #[must_use]
    pub fn reach(&self) -> NotificationReach {
        self.reach
    }

    /// Whether it shows to its recipient while they hold `held`, each wider
    /// permission listed with all it covers: when they hold the permission
    /// it needs, or when it is about their own account's safety.
    #[must_use]
    pub fn shows_to(&self, held: &[SystemPermission]) -> bool {
        self.reach.shows(self.required_permission, held)
    }

    /// Whether the recipient has read this notification.
    #[must_use]
    pub fn is_read(&self) -> bool {
        self.read == ReadState::Read
    }

    /// When the notification was created.
    #[must_use]
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Marks this notification as read.
    pub fn mark_read(&mut self) {
        self.read = ReadState::Read;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::event_type::IdentityEvent;

    fn test_params() -> CreateNotificationParams {
        CreateNotificationParams {
            id: NotificationId::new(),
            event_type: EventType::Identity(IdentityEvent::UserRegistered),
            severity: NotificationSeverity::Info,
            title: Label::new("title", "New user registered").unwrap(),
            body: Some(Text::new("body", "alice@acme.com joined").unwrap()),
            resource_id: AboutResource::Resource(Uuid::now_v7()),
            told_as: ToldAs::Overseer,
        }
    }

    /// Notifications are kept ninety days: a hundred days in, the cutoff
    /// is day ten.
    #[test]
    fn notifications_are_kept_ninety_days() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(100);

        let cutoff = kept_since(now);

        assert_eq!(cutoff, OffsetDateTime::UNIX_EPOCH + Duration::days(10));
    }

    /// A notification is made for a new user registering. It starts
    /// unread, files under identity and needs `idp:users:view` to be seen.
    #[test]
    fn create_produces_unread_notification() {
        let n = Notification::create(test_params());

        assert!(!n.is_read());
        assert_eq!(n.title().as_str(), "New user registered");
        assert_eq!(n.body().unwrap().as_str(), "alice@acme.com joined");
        assert_eq!(n.category(), NotificationCategory::Identity);
        assert_eq!(n.severity(), NotificationSeverity::Info);
        assert!(n.resource_id() != AboutResource::Nothing);
        assert_eq!(n.required_permission().to_string(), "idp:users:view");
    }

    /// An unread notification is marked read and then reports read.
    #[test]
    fn mark_read_changes_status() {
        let mut n = Notification::create(test_params());

        n.mark_read();

        assert!(n.is_read());
    }

    /// A notification is marked read twice, say from two devices. The
    /// second time does nothing and it stays read.
    #[test]
    fn mark_read_is_idempotent() {
        let mut n = Notification::create(test_params());

        n.mark_read();
        n.mark_read();

        assert!(n.is_read());
    }

    /// A user registration notification needs `idp:users:view`, the
    /// permission of the identity category.
    #[test]
    fn notification_derives_permission_from_category() {
        let n = Notification::create(test_params());
        assert_eq!(n.required_permission().to_string(), "idp:users:view");
    }

    /// A notification that an organization was created needs
    /// `idp:audit_log:view` to be seen.
    #[test]
    fn organization_category_needs_the_audit_log() {
        let params = CreateNotificationParams {
            id: NotificationId::new(),
            event_type: EventType::Organization(
                crate::types::event_type::OrganizationEvent::Created,
            ),
            severity: NotificationSeverity::Info,
            title: Label::new("title", "Org created").unwrap(),
            body: None,
            resource_id: AboutResource::Nothing,
            told_as: ToldAs::Overseer,
        };
        let n = Notification::create(params);
        assert_eq!(n.required_permission().to_string(), "idp:audit_log:view");
    }

    /// A key-rotation event determines the crypto category and requires
    /// crypto-view permission when its notification is created.
    #[test]
    fn a_crypto_event_needs_the_crypto_permission_whatever_else_is_said() {
        let n = Notification::create(CreateNotificationParams {
            id: NotificationId::new(),
            event_type: EventType::Crypto(crate::types::event_type::CryptoEvent::KeyRotated),
            ..test_params()
        });

        assert_eq!(n.category(), NotificationCategory::Crypto);
        assert_eq!(n.required_permission().to_string(), "idp:crypto:view");
    }

    /// A notification is created as critical. It reports critical, and the
    /// severity is not worked out again from the event.
    #[test]
    fn a_notification_keeps_its_severity() {
        let params = CreateNotificationParams {
            id: NotificationId::new(),
            severity: NotificationSeverity::Critical,
            ..test_params()
        };
        let n = Notification::create(params);

        assert_eq!(n.severity(), NotificationSeverity::Critical);
    }

    /// A notification is stored as read and read back. It keeps its id,
    /// title, severity and read state.
    #[test]
    fn reconstitute_preserves_all_fields() {
        let original = Notification::create(test_params());
        let id = original.id();

        let restored = Notification::reconstitute(NotificationRow {
            id,
            event_type: *original.event_type(),
            severity: original.severity(),
            title: Label::new("title", original.title().as_str()).unwrap(),
            body: original
                .body()
                .map(|t| Text::new("body", t.as_str()).unwrap()),
            resource_id: original.resource_id(),
            reach: original.reach(),
            read: ReadState::Read,
            created_at: original.created_at(),
        })
        .unwrap();

        assert_eq!(restored.id(), id);
        assert!(restored.is_read());
        assert_eq!(restored.title().as_str(), "New user registered");
        assert_eq!(restored.severity(), NotificationSeverity::Info);
    }

    /// Reading a stored key-rotation notification derives its crypto
    /// category and crypto-view permission from the event again.
    #[test]
    fn a_stored_notification_needs_the_permission_its_event_needs() {
        let original = Notification::create(CreateNotificationParams {
            id: NotificationId::new(),
            event_type: EventType::Crypto(crate::types::event_type::CryptoEvent::KeyRotated),
            ..test_params()
        });

        let restored = Notification::reconstitute(NotificationRow {
            id: original.id(),
            event_type: *original.event_type(),
            severity: original.severity(),
            title: original.title().clone(),
            body: None,
            resource_id: original.resource_id(),
            reach: original.reach(),
            read: ReadState::Unread,
            created_at: original.created_at(),
        })
        .unwrap();

        assert_eq!(restored.category(), NotificationCategory::Crypto);
        assert_eq!(
            restored.required_permission().to_string(),
            "idp:crypto:view"
        );
    }

    /// An admin locks Carol's account, and Carol, who may see no users, is
    /// told as its holder. The notice shows to her though she holds
    /// nothing; the same notice to an admin shows only by their rights.
    #[test]
    fn a_notice_to_the_holder_of_a_locked_account_shows_whatever_they_hold() {
        let to_carol = Notification::create(test_locked_params(ToldAs::Subject));
        let to_an_admin = Notification::create(test_locked_params(ToldAs::Overseer));

        assert!(to_carol.shows_to(&[]));
        assert!(!to_an_admin.shows_to(&[]));
        assert!(to_an_admin.shows_to(&[to_an_admin.required_permission()]));
    }

    /// A registration notice remains subject to permissions even for its
    /// subject and is hidden from a recipient holding no rights.
    #[test]
    fn a_notice_about_no_accounts_safety_shows_only_by_rights() {
        let n = Notification::create(CreateNotificationParams {
            id: NotificationId::new(),
            told_as: ToldAs::Subject,
            ..test_params()
        });

        assert_eq!(n.reach(), NotificationReach::ByRights);
        assert!(!n.shows_to(&[]));
    }

    /// A stored registration notice claiming the account-safety exception
    /// is refused as corrupt.
    #[test]
    fn a_stored_own_account_notice_about_no_accounts_safety_is_refused() {
        let original = Notification::create(test_params());

        let result = Notification::reconstitute(NotificationRow {
            id: original.id(),
            event_type: *original.event_type(),
            severity: original.severity(),
            title: original.title().clone(),
            body: None,
            resource_id: original.resource_id(),
            reach: NotificationReach::OwnAccount,
            read: ReadState::Unread,
            created_at: original.created_at(),
        });

        assert!(crate::shared::model::row_check::refused_as_corrupt(&result));
    }

    /// The parameters of a notice that an account was locked, told as
    /// `told_as`.
    fn test_locked_params(told_as: ToldAs) -> CreateNotificationParams {
        CreateNotificationParams {
            id: NotificationId::new(),
            event_type: EventType::Identity(IdentityEvent::UserStatusChanged),
            told_as,
            ..test_params()
        }
    }

    /// A notification about one record gets a fresh id and keeps that
    /// record's id. A notification about nothing points at no record, so
    /// clicking it never opens one that does not exist.
    #[test]
    fn a_notification_carries_its_own_id_and_the_resource_it_points_at() {
        let resource = Uuid::now_v7();
        let notification = Notification::create(CreateNotificationParams {
            id: NotificationId::new(),
            resource_id: AboutResource::Resource(resource),
            ..test_params()
        });

        assert!(!notification.id().as_uuid().is_nil());
        assert_eq!(
            notification.resource_id(),
            AboutResource::Resource(resource)
        );

        let unanchored = Notification::create(CreateNotificationParams {
            id: NotificationId::new(),
            resource_id: AboutResource::Nothing,
            ..test_params()
        });
        assert_eq!(
            unanchored.resource_id(),
            AboutResource::Nothing,
            "a notification about nothing in particular points nowhere"
        );
    }
}
