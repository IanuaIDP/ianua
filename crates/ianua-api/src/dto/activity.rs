//! Activity bodies: the contribution calendar.

use ianua_domain::domains::activity::{ActivityCalendar, ActivityCategory, ActivityDay};
use serde::Serialize;

/// A contribution calendar: how many audit events happened each day.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ActivityCalendarResponse {
    /// First day of the window (inclusive).
    pub from: String,
    /// Last day of the window (inclusive).
    pub to: String,
    /// Total events across the window.
    pub total: u64,
    /// Event count of the busiest day, 0 when the window is empty.
    pub max_count: u64,
    /// Categories that appear anywhere in the window, in canonical order.
    /// Drives the category dropdown; absent categories are not offered.
    #[schema(schema_with = crate::dto::schemas::activity_category_list)]
    pub categories: Vec<ActivityCategory>,
    /// One entry per day, oldest first; quiet days included with count 0.
    pub days: Vec<ActivityDayResponse>,
}

/// One day of the contribution calendar.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ActivityDayResponse {
    /// The UTC day, `YYYY-MM-DD`.
    pub date: String,
    /// Total events on this day, across every category.
    pub count: u64,
    /// Heatmap intensity from 0 (none) to 4 (busiest quarter), graded
    /// against the whole series.
    pub level: u8,
    /// Per-category breakdown. Re-grade against one category's window
    /// maximum to recolor the heatmap for it without a new request.
    pub by_category: Vec<CategoryCountResponse>,
}

/// One category's event count for one day.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CategoryCountResponse {
    /// The activity category.
    #[schema(schema_with = crate::dto::schemas::activity_category)]
    pub category: ActivityCategory,
    /// Events of this category on the day.
    pub count: u64,
}

impl From<ActivityCalendar> for ActivityCalendarResponse {
    fn from(calendar: ActivityCalendar) -> Self {
        Self {
            from: calendar.range().start().to_string(),
            to: calendar.range().end().to_string(),
            total: calendar.total(),
            max_count: calendar.max_count(),
            categories: calendar.categories().to_vec(),
            days: calendar
                .days()
                .iter()
                .map(ActivityDayResponse::from)
                .collect(),
        }
    }
}

impl From<&ActivityDay> for ActivityDayResponse {
    fn from(day: &ActivityDay) -> Self {
        Self {
            date: day.date().to_string(),
            count: day.count(),
            level: day.level().as_u8(),
            by_category: day
                .by_category()
                .iter()
                .map(|(category, count)| CategoryCountResponse {
                    category: *category,
                    count: *count,
                })
                .collect(),
        }
    }
}
