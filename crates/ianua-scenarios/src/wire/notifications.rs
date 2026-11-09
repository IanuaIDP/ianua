//! A person's notification inbox, its unread count and the channel they
//! chose for each category.

use serde::{Deserialize, Serialize};

/// One notification, from `GET …/notifications`.
#[derive(Debug, Clone, Deserialize)]
pub struct Notification {
    /// Handle used to mark this inbox entry as read.
    pub id: String,
    /// The area it is about, such as `Authorization` for a role given or
    /// taken back.
    pub category: String,
    /// What it says in short.
    pub title: String,
    /// What else it says, if anything.
    #[serde(default)]
    pub body: Option<String>,
    /// Whether it was read.
    pub read: bool,
    /// The record it is about, such as the group an offer names.
    #[serde(default)]
    pub resource_id: Option<String>,
}

/// `GET …/notifications/unread-count`: the badge on the bell.
#[derive(Debug, Clone, Deserialize)]
pub struct UnreadCount {
    /// How many notifications are still unread.
    pub count: u64,
}

/// `POST …/notifications/read-all`: how many were still unread.
#[derive(Debug, Clone, Deserialize)]
pub struct MarkedRead {
    /// How many notifications this marked read.
    pub marked: u64,
}

/// One category's channel, as `GET …/notifications/preferences` answers it
/// and `PATCH` takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Preference {
    /// The area, such as `Authorization` or `Identity`.
    pub category: String,
    /// `InApp`, `InAppAndEmail` or `Disabled`.
    pub channel: String,
}

/// `PATCH …/notifications/preferences`: the categories whose channel
/// changes; the others keep theirs.
#[derive(Debug, Clone, Serialize)]
pub struct PreferencesChange {
    /// The new channel of each category named.
    pub preferences: Vec<Preference>,
}

/// One frame of a live notification stream, as the dashboard reads it:
/// `{"msg_type": "notification", "notification": {...}}`.
#[derive(Debug, Clone, Deserialize)]
pub struct LiveFrame {
    /// What kind of update it is, such as `notification`.
    pub msg_type: String,
    /// The update itself.
    pub notification: LiveNotification,
}

/// A notification as a live stream sends it the moment it is sent.
#[derive(Debug, Clone, Deserialize)]
pub struct LiveNotification {
    /// The same id the inbox lists it under.
    pub id: String,
    /// The event it reports, such as `authorization.role_assigned`.
    pub event_type: String,
    /// The area it is about, in lower case, such as `authorization`.
    pub category: String,
    /// What it says in short.
    pub title: String,
    /// Whether it was read.
    pub read: bool,
}
