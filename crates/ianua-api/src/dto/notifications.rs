//! Notification bodies: an inbox entry, counts, and the delivery
//! preferences of tenant users, members and operators. An organization's
//! destinations outside the app are in `destinations`.

pub mod destinations;

use ianua_app::listing::{PageRequest, SortOrder};
use ianua_app::ports::notifications::{NotificationSortField, ReadFilter};
use ianua_app::use_cases::notifications::{
    ListRequest, PreferenceUpdate, UpdatePreferencesRequest,
};
use ianua_domain::domains::notifications::category::NotificationCategory;
use ianua_domain::domains::notifications::channel::NotificationChannel;
use ianua_domain::domains::notifications::notification::{AboutResource, Notification};
use ianua_domain::domains::notifications::preference::{
    NotificationPreference, NotificationPreferenceSet,
};
use ianua_domain::domains::notifications::severity::NotificationSeverity;
use ianua_domain::isolation::scope::ResolvedTenant;
use ianua_domain::types::EventType;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// A single notification.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct NotificationResponse {
    /// Unique identifier.
    pub id: Uuid,
    /// The event that caused it, such as `{"Tenant":"StatusChanged"}`.
    #[schema(value_type = Object)]
    pub event_type: EventType,
    /// Its category, such as `Identity`.
    #[schema(schema_with = crate::dto::schemas::notification_category)]
    pub category: NotificationCategory,
    /// How urgent it is: `Info`, `Warning` or `Critical`.
    #[schema(schema_with = crate::dto::schemas::notification_severity)]
    pub severity: NotificationSeverity,
    /// Short summary of what happened.
    pub title: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// The resource the event refers to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<Uuid>,
    /// Whether the notification has been read.
    pub read: bool,
    /// When the notification was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<Notification> for NotificationResponse {
    fn from(n: Notification) -> Self {
        Self {
            id: *n.id().as_uuid(),
            event_type: *n.event_type(),
            category: n.category(),
            severity: n.severity(),
            title: n.title().as_str().to_owned(),
            body: n.body().map(|t| t.as_str().to_owned()),
            resource_id: match n.resource_id() {
                AboutResource::Resource(id) => Some(id),
                AboutResource::Nothing => None,
            },
            read: n.is_read(),
            created_at: n.created_at(),
        }
    }
}

/// Unread notification count.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UnreadCountResponse {
    /// Number of unread notifications.
    pub count: u64,
}

/// Result of marking all notifications as read.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MarkAllReadResponse {
    /// Number of notifications marked as read.
    pub marked: u64,
}

/// A single preference entry.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PreferenceResponse {
    /// The notification category, such as `Identity`.
    #[schema(schema_with = crate::dto::schemas::notification_category)]
    pub category: NotificationCategory,
    /// The delivery channel: `InApp`, `InAppAndEmail` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::notification_channel)]
    pub channel: NotificationChannel,
}

/// Request body for updating preferences.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct UpdatePreferencesBody {
    /// The preferences to update.
    pub preferences: Vec<PreferenceUpdateEntry>,
}

/// A single preference update entry.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct PreferenceUpdateEntry {
    /// The category to update, such as `Identity`.
    #[schema(schema_with = crate::dto::schemas::notification_category)]
    pub category: NotificationCategory,
    /// The new delivery channel: `InApp`, `InAppAndEmail` or `Disabled`.
    #[schema(schema_with = crate::dto::schemas::notification_channel)]
    pub channel: NotificationChannel,
}

/// Query parameter for filtering notifications.
#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct NotificationFilterParams {
    /// If true, only return unread notifications.
    #[serde(default)]
    pub unread_only: bool,
}

impl NotificationFilterParams {
    /// The listing asked for: these notifications, in `sort` order, the
    /// page `pagination` names.
    #[must_use]
    pub(crate) fn listing(
        &self,
        sort: SortOrder<NotificationSortField>,
        pagination: PageRequest,
    ) -> ListRequest {
        ListRequest {
            reads: self.reads(),
            sort,
            page: pagination,
        }
    }

    /// Which notifications the listing returns.
    fn reads(&self) -> ReadFilter {
        if self.unread_only {
            return ReadFilter::UnreadOnly;
        }
        ReadFilter::All
    }
}

impl PreferenceResponse {
    /// One entry per category of `set`, sorted by category name.
    #[must_use]
    pub(crate) fn all_of(set: &NotificationPreferenceSet<ResolvedTenant>) -> Vec<Self> {
        Self::listed(set.to_vec())
    }

    /// One entry per preference in `preferences`, in their order: a
    /// member's or an operator's own.
    #[must_use]
    pub(crate) fn listed(preferences: Vec<NotificationPreference>) -> Vec<Self> {
        preferences
            .into_iter()
            .map(|preference| Self {
                category: preference.category(),
                channel: preference.channel(),
            })
            .collect()
    }
}

impl UpdatePreferencesBody {
    /// The channel each listed category moves to.
    #[must_use]
    pub(crate) fn updates(self) -> Vec<PreferenceUpdate> {
        self.preferences
            .into_iter()
            .map(|entry| PreferenceUpdate {
                category: entry.category,
                channel: entry.channel,
            })
            .collect()
    }
}

impl From<UpdatePreferencesBody> for UpdatePreferencesRequest {
    fn from(body: UpdatePreferencesBody) -> Self {
        Self {
            updates: body.updates(),
        }
    }
}
