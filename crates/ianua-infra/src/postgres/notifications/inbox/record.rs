//! A notification as an inbox row holds it, the same in every inbox: read
//! back into the domain's notification, and written out from it.
//!
//! The category is stored beside the event type so a list can filter and
//! sort by it, but the domain works it out from the event type again on
//! every read. A row whose stored category is not the one its event files
//! under is refused, so a changed row can never show a notification to
//! someone the event's own category would hide it from.

use ianua_app::ports::notifications::Kept;
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::notification::{
    AboutResource, Notification, NotificationRow, ReadState, title_label,
};
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::{EventType, NotificationId, Text};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::foundation::stored::{Stored, StoredWord as _};

const NOTIFICATION: Stored = Stored("notification");

/// A notification as it is read. Every inbox's checked queries fill it.
pub(super) struct NotificationRecord {
    pub(super) id: Uuid,
    pub(super) event_type: String,
    pub(super) category: String,
    pub(super) severity: i16,
    pub(super) title: String,
    pub(super) body: Option<String>,
    pub(super) resource_id: Option<Uuid>,
    pub(super) reach: String,
    pub(super) read: bool,
    pub(super) created_at: OffsetDateTime,
}

impl NotificationRecord {
    /// The notification the record holds, rebuilt through the domain's
    /// checks.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::Infrastructure` when the event type or a word
    /// is unknown, the stored category is not the event's, a text no longer
    /// passes its rules, or the row breaks a rule the notification keeps.
    pub(super) fn into_notification(self) -> Result<Notification, DomainError> {
        let event_type = EventType::parse(&self.event_type)
            .ok_or_else(|| DomainError::corrupt_row(NOTIFICATION.0, "an unknown event type"))?;
        ensure_filed_under_its_event(&self.category, &event_type)?;
        let body = self
            .body
            .map(|body| NOTIFICATION.value("body", Text::new("body", body)))
            .transpose()?;
        Notification::reconstitute(NotificationRow {
            id: NotificationId::from_uuid(self.id),
            event_type,
            severity: NotificationSeverity::from_rank(self.severity)?,
            title: NOTIFICATION.value("title", title_label(self.title))?,
            body,
            resource_id: AboutResource::from_stored(self.resource_id),
            reach: NOTIFICATION.choice(&self.reach)?,
            read: ReadState::from(self.read),
            created_at: self.created_at,
        })
    }
}

/// Refuses a stored category that is not the one `event_type` files under.
fn ensure_filed_under_its_event(stored: &str, event_type: &EventType) -> Result<(), DomainError> {
    let category: NotificationCategory = NOTIFICATION.choice(stored)?;
    if category != NotificationCategory::from_event_type(event_type) {
        return Err(DomainError::corrupt_row(
            NOTIFICATION.0,
            "a category its event does not file under",
        ));
    }
    Ok(())
}

/// The notifications `records` hold, each rebuilt.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when any record is refused.
pub(super) fn rebuilt(records: Vec<NotificationRecord>) -> Result<Vec<Notification>, DomainError> {
    records
        .into_iter()
        .map(NotificationRecord::into_notification)
        .collect()
}

/// What a save that wrote `rows` rows did: the notification's id is new,
/// or a row under it was kept already and nothing was written.
/// What a save that wrote `rows` rows did: the notification's id was new,
/// or a row under it was kept already and nothing was written.
pub(super) fn kept(rows: u64) -> Kept {
    match rows {
        0 => Kept::AlreadyKept,
        _ => Kept::New,
    }
}

/// A notification's columns, as they are written. The inbox it goes to is
/// bound beside them by its store.
pub(super) struct NotificationColumns<'a> {
    pub(super) id: Uuid,
    pub(super) event_type: &'static str,
    pub(super) category: &'static str,
    pub(super) severity: i16,
    pub(super) title: &'a str,
    pub(super) body: Option<&'a str>,
    pub(super) resource_id: Option<Uuid>,
    pub(super) reach: &'static str,
    pub(super) read: bool,
    pub(super) created_at: OffsetDateTime,
}

impl<'a> NotificationColumns<'a> {
    /// The columns `notification` is written to.
    pub(super) fn of(notification: &'a Notification) -> Self {
        Self {
            id: *notification.id().as_uuid(),
            event_type: notification.event_type().as_str(),
            category: notification.category().word(),
            severity: notification.severity().rank(),
            title: notification.title().as_str(),
            body: notification.body().map(Text::as_str),
            resource_id: notification.resource_id().into(),
            reach: notification.reach().word(),
            read: notification.is_read(),
            created_at: notification.created_at(),
        }
    }
}
