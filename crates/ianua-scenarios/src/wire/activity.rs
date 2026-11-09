//! The activity calendar: how many audit records each day held, by
//! category, as the dashboard's heatmap draws it.

use serde::Deserialize;

/// `GET …/activity`: a window of days, oldest first.
#[derive(Debug, Clone, Deserialize)]
pub struct ActivityCalendar {
    /// The first day, `YYYY-MM-DD`.
    pub from: String,
    /// The last day, `YYYY-MM-DD`.
    pub to: String,
    /// Records across the whole window.
    pub total: u64,
    /// The categories that happened anywhere in the window.
    pub categories: Vec<String>,
    /// One entry per day, quiet days too.
    pub days: Vec<ActivityDay>,
}

impl ActivityCalendar {
    /// The records `category` holds on `date`, `0` when it holds none or
    /// the day is outside the window.
    #[must_use]
    pub fn count_on(&self, date: &str, category: &str) -> u64 {
        self.days
            .iter()
            .filter(|day| day.date == date)
            .flat_map(|day| day.by_category.iter())
            .filter(|counted| counted.category == category)
            .map(|counted| counted.count)
            .sum()
    }
}

/// One day of the calendar.
#[derive(Debug, Clone, Deserialize)]
pub struct ActivityDay {
    /// The UTC day, `YYYY-MM-DD`.
    pub date: String,
    /// Records that day, every category together.
    pub count: u64,
    /// How dark the day is drawn, from 0 to 4.
    pub level: u8,
    /// The day's records by category.
    pub by_category: Vec<CategoryCount>,
}

/// One category's records on one day.
#[derive(Debug, Clone, Deserialize)]
pub struct CategoryCount {
    /// `Authentication`, `Access`, `Administration`, `Identity`,
    /// `Provisioning` or `Other`.
    pub category: String,
    /// How many records.
    pub count: u64,
}
