//! Activity counts per day and category, graded into calendar levels.

use std::collections::HashMap;

use time::Date;

use crate::domains::activity::category::ActivityCategory;
use crate::domains::activity::range::CalendarRange;
use crate::shared::errors::DomainError;

/// The number of events of one category on one day, as storage reports it.
///
/// Storage reports only pairs that had activity. The calendar fills the
/// missing pairs with zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DailyCategoryCount {
    /// The UTC day the events fell on.
    pub date: Date,
    /// The category the events belong to.
    pub category: ActivityCategory,
    /// How many events of that category occurred on that day.
    pub count: u64,
}

/// How busy one day was compared with the busiest day of the calendar.
///
/// Each level is one of the five shades a calendar cell can have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActivityLevel {
    /// No activity.
    None,
    /// Up to a quarter of the busiest day.
    Light,
    /// Up to half of the busiest day.
    Moderate,
    /// Up to three quarters of the busiest day.
    High,
    /// More than three quarters of the busiest day.
    Peak,
}

impl ActivityLevel {
    /// The level of `count`, in quarters of `max`, the busiest day's count.
    ///
    /// A zero count is always [`None`](Self::None). Any activity is at
    /// least [`Light`](Self::Light). A count above `max` is
    /// [`Peak`](Self::Peak).
    #[must_use]
    pub fn grade(count: u64, max: u64) -> Self {
        if count == 0 {
            return Self::None;
        }

        let max = u128::from(max.max(count));
        match (u128::from(count) * 4).div_ceil(max) {
            1 => Self::Light,
            2 => Self::Moderate,
            3 => Self::High,
            _ => Self::Peak,
        }
    }

    /// The level as a number from 0 to 4, for transports.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Light => 1,
            Self::Moderate => 2,
            Self::High => 3,
            Self::Peak => 4,
        }
    }
}

/// One cell of the calendar: a UTC day with its count, level and counts per
/// category.
///
/// The counts per category let a caller grade the same day against one
/// category alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityDay {
    date: Date,
    /// Total events on this day across every category.
    count: u64,
    /// The level against the busiest day's total.
    level: ActivityLevel,
    /// A count for every category that appears anywhere in the calendar,
    /// in display order. A category with no events on this day has `0`.
    by_category: Vec<(ActivityCategory, u64)>,
}

impl ActivityDay {
    /// The UTC day this cell represents.
    #[must_use]
    pub fn date(&self) -> Date {
        self.date
    }

    /// Total events on this day, across every category.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The level of this day against the busiest day's total.
    #[must_use]
    pub fn level(&self) -> ActivityLevel {
        self.level
    }

    /// The day's count for each of the calendar's categories, in display
    /// order, with `0` where the day had none.
    ///
    /// To shade the calendar for one category, grade these counts with
    /// [`ActivityLevel::grade`] against that category's busiest day. No new
    /// request is needed.
    #[must_use]
    pub fn by_category(&self) -> &[(ActivityCategory, u64)] {
        &self.by_category
    }
}

/// An activity calendar with one [`ActivityDay`] per day of the range,
/// oldest first.
///
/// Quiet days are included with a count of zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityCalendar {
    range: CalendarRange,
    days: Vec<ActivityDay>,
    total: u64,
    max_count: u64,
    /// Categories that appear anywhere in the range, in display order.
    categories: Vec<ActivityCategory>,
}

impl ActivityCalendar {
    /// Builds a calendar from the counts storage reported for `range`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Infrastructure`] when the same day and category
    ///   appear twice. Storage sent a corrupt result.
    /// - [`DomainError::Infrastructure`] when a count falls on a day
    ///   outside the range. Storage sent a corrupt result.
    pub fn from_daily_category_counts(
        range: CalendarRange,
        counts: &[DailyCategoryCount],
    ) -> Result<Self, DomainError> {
        let by_date = index_by_date_category(&range, counts)?;
        let categories = window_categories(&by_date);
        let max_count = by_date.values().map(day_total).max().unwrap_or(0);
        let days = range
            .days()
            .map(|date| graded_day(date, by_date.get(&date), &categories, max_count))
            .collect();
        let total = by_date.values().map(day_total).sum();

        Ok(Self {
            range,
            days,
            total,
            max_count,
            categories,
        })
    }

    /// The day range the calendar covers.
    #[must_use]
    pub fn range(&self) -> CalendarRange {
        self.range
    }

    /// Every day of the range in ascending order, quiet days included.
    #[must_use]
    pub fn days(&self) -> &[ActivityDay] {
        &self.days
    }

    /// The total number of events across the range.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The event count of the busiest day, or zero for an empty range.
    #[must_use]
    pub fn max_count(&self) -> u64 {
        self.max_count
    }

    /// Categories that appear anywhere in the range, in display order.
    ///
    /// Empty when the range had no activity.
    #[must_use]
    pub fn categories(&self) -> &[ActivityCategory] {
        &self.categories
    }
}

/// Every event a day saw, across all categories.
fn day_total(by_category: &HashMap<ActivityCategory, u64>) -> u64 {
    by_category
        .values()
        .fold(0u64, |sum, c| sum.saturating_add(*c))
}

/// One calendar cell: the day's count graded against the busiest day, and
/// its count in each of the calendar's categories, zero where it had none.
fn graded_day(
    date: Date,
    by_category: Option<&HashMap<ActivityCategory, u64>>,
    categories: &[ActivityCategory],
    max_count: u64,
) -> ActivityDay {
    let count = by_category.map(day_total).unwrap_or(0);
    let by_category = categories
        .iter()
        .map(|&category| {
            let c = by_category
                .and_then(|m| m.get(&category).copied())
                .unwrap_or(0);
            (category, c)
        })
        .collect();
    ActivityDay {
        date,
        count,
        level: ActivityLevel::grade(count, max_count),
        by_category,
    }
}

/// The counts as `day -> category -> count`.
///
/// Refuses a day outside the range and a day and category reported twice.
fn index_by_date_category(
    range: &CalendarRange,
    counts: &[DailyCategoryCount],
) -> Result<HashMap<Date, HashMap<ActivityCategory, u64>>, DomainError> {
    let mut by_date: HashMap<Date, HashMap<ActivityCategory, u64>> = HashMap::new();

    for daily in counts {
        if !range.contains(daily.date) {
            return Err(DomainError::infra_msg(format!(
                "activity count for {} falls outside the queried range",
                daily.date
            )));
        }
        let inner = by_date.entry(daily.date).or_default();
        if inner.insert(daily.category, daily.count).is_some() {
            return Err(DomainError::infra_msg(format!(
                "duplicate activity count for {}/{:?}",
                daily.date, daily.category
            )));
        }
    }

    Ok(by_date)
}

/// The categories that appear in the counts, in display order.
fn window_categories(
    by_date: &HashMap<Date, HashMap<ActivityCategory, u64>>,
) -> Vec<ActivityCategory> {
    let mut seen: Vec<ActivityCategory> =
        by_date.values().flat_map(HashMap::keys).copied().collect();
    seen.sort_unstable();
    seen.dedup();
    seen
}

#[cfg(test)]
mod tests {
    use time::Month;

    use super::*;

    fn date(day: u8) -> Date {
        Date::from_calendar_date(2026, Month::March, day).unwrap()
    }

    fn march_range(first: u8, last: u8) -> CalendarRange {
        CalendarRange::new(date(first), date(last)).unwrap()
    }

    fn count(day: u8, category: ActivityCategory, n: u64) -> DailyCategoryCount {
        DailyCategoryCount {
            date: date(day),
            category,
            count: n,
        }
    }

    /// A day with no events gets the empty shade, even when the busiest day
    /// had 100.
    #[test]
    fn grade_returns_none_for_zero_count() {
        assert_eq!(ActivityLevel::grade(0, 100), ActivityLevel::None);
    }

    /// With a busiest day of 100, counts up to 25 are light, up to 50
    /// moderate, up to 75 high and above that peak. Each boundary goes to
    /// the lower level.
    #[test]
    fn grade_splits_max_into_quarters() {
        assert_eq!(ActivityLevel::grade(1, 100), ActivityLevel::Light);
        assert_eq!(ActivityLevel::grade(25, 100), ActivityLevel::Light);
        assert_eq!(ActivityLevel::grade(26, 100), ActivityLevel::Moderate);
        assert_eq!(ActivityLevel::grade(50, 100), ActivityLevel::Moderate);
        assert_eq!(ActivityLevel::grade(51, 100), ActivityLevel::High);
        assert_eq!(ActivityLevel::grade(75, 100), ActivityLevel::High);
        assert_eq!(ActivityLevel::grade(76, 100), ActivityLevel::Peak);
        assert_eq!(ActivityLevel::grade(100, 100), ActivityLevel::Peak);
    }

    /// In a calendar where the busiest day had one event, that day is still
    /// the darkest shade.
    #[test]
    fn grade_marks_busiest_day_as_peak_even_when_max_is_one() {
        assert_eq!(ActivityLevel::grade(1, 1), ActivityLevel::Peak);
    }

    /// A count of 10 against a stated busiest day of 3 is graded peak. It
    /// does not produce a level past the top.
    #[test]
    fn grade_treats_count_above_max_as_peak() {
        assert_eq!(ActivityLevel::grade(10, 3), ActivityLevel::Peak);
    }

    /// Every count from 0 to 97 against a busiest day of 97 is graded. A
    /// busier day never gets a lighter shade, and no level goes past 4.
    #[test]
    fn grade_is_monotone_in_count() {
        let max = 97;
        let mut previous = ActivityLevel::None;
        for c in 0..=max {
            let level = ActivityLevel::grade(c, max);
            assert!(level >= previous, "level dropped at count {c}");
            assert!(level.as_u8() <= 4);
            previous = level;
        }
    }

    /// Counts at `u64::MAX` are graded without overflowing. The largest
    /// count is peak and a single event against it is light.
    #[test]
    fn grade_survives_extreme_counts_without_overflow() {
        assert_eq!(
            ActivityLevel::grade(u64::MAX, u64::MAX),
            ActivityLevel::Peak
        );
        assert_eq!(ActivityLevel::grade(1, u64::MAX), ActivityLevel::Light);
    }

    /// Storage reports logins only on 2 and 4 March. The calendar still has
    /// all four days, and 1 and 3 March list authentication with zero.
    #[test]
    fn from_counts_zero_fills_quiet_days_and_categories() {
        let calendar = ActivityCalendar::from_daily_category_counts(
            march_range(1, 4),
            &[
                count(2, ActivityCategory::Authentication, 3),
                count(4, ActivityCategory::Authentication, 1),
            ],
        )
        .unwrap();

        let totals: Vec<u64> = calendar.days().iter().map(ActivityDay::count).collect();
        assert_eq!(totals, vec![0, 3, 0, 1]);
        assert_eq!(calendar.total(), 4);
        assert_eq!(calendar.max_count(), 3);
        assert_eq!(calendar.categories(), &[ActivityCategory::Authentication]);

        for day in calendar.days() {
            assert_eq!(
                day.by_category(),
                &[(ActivityCategory::Authentication, day_total(day))]
            );
        }
    }

    /// 1 March has 8 logins and 2 March has 2 access events. Each day is
    /// graded against the total of the busiest day, so 1 March is peak and
    /// 2 March is light.
    #[test]
    fn from_counts_grades_against_busiest_total_day() {
        let calendar = ActivityCalendar::from_daily_category_counts(
            march_range(1, 3),
            &[
                count(1, ActivityCategory::Authentication, 8),
                count(2, ActivityCategory::Access, 2),
            ],
        )
        .unwrap();

        let levels: Vec<ActivityLevel> = calendar.days().iter().map(ActivityDay::level).collect();
        assert_eq!(
            levels,
            vec![
                ActivityLevel::Peak,
                ActivityLevel::Light,
                ActivityLevel::None
            ]
        );
    }

    /// Storage reports other before authentication. The calendar still
    /// lists authentication, administration, other, and each day follows
    /// that order with zeros filled in.
    #[test]
    fn from_counts_exposes_distinct_categories_in_canonical_order() {
        let calendar = ActivityCalendar::from_daily_category_counts(
            march_range(1, 2),
            &[
                count(1, ActivityCategory::Other, 1),
                count(1, ActivityCategory::Authentication, 1),
                count(2, ActivityCategory::Administration, 1),
            ],
        )
        .unwrap();

        assert_eq!(
            calendar.categories(),
            &[
                ActivityCategory::Authentication,
                ActivityCategory::Administration,
                ActivityCategory::Other,
            ]
        );

        let first = &calendar.days()[0];
        assert_eq!(first.count(), 2);
        assert_eq!(
            first.by_category(),
            &[
                (ActivityCategory::Authentication, 1),
                (ActivityCategory::Administration, 0),
                (ActivityCategory::Other, 1),
            ]
        );
    }

    /// Storage reports nothing for 1 to 3 March. The calendar has three
    /// empty days, no categories and a total of zero.
    #[test]
    fn from_counts_yields_empty_categories_for_empty_input() {
        let calendar =
            ActivityCalendar::from_daily_category_counts(march_range(1, 3), &[]).unwrap();

        assert_eq!(calendar.total(), 0);
        assert_eq!(calendar.max_count(), 0);
        assert!(calendar.categories().is_empty());
        assert!(calendar.days().iter().all(|d| d.by_category().is_empty()));
        assert!(
            calendar
                .days()
                .iter()
                .all(|day| day.level() == ActivityLevel::None)
        );
    }

    /// Storage reports a count for 4 March in a 1 to 3 March calendar. That
    /// is refused as an infrastructure error, since the query was wrong.
    #[test]
    fn from_counts_rejects_out_of_range_day() {
        let result = ActivityCalendar::from_daily_category_counts(
            march_range(1, 3),
            &[count(4, ActivityCategory::Authentication, 1)],
        );

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// Storage reports logins on 2 March twice, once 1 and once 5. That is
    /// refused as an infrastructure error. Neither number is picked.
    #[test]
    fn from_counts_rejects_duplicate_day_category_pair() {
        let result = ActivityCalendar::from_daily_category_counts(
            march_range(1, 3),
            &[
                count(2, ActivityCategory::Authentication, 1),
                count(2, ActivityCategory::Authentication, 5),
            ],
        );

        assert!(matches!(result, Err(DomainError::Infrastructure(_))));
    }

    /// A 1 to 5 March calendar with no counts still has one cell for each
    /// of the five days, oldest first.
    #[test]
    fn days_cover_range_in_ascending_order() {
        let calendar =
            ActivityCalendar::from_daily_category_counts(march_range(1, 5), &[]).unwrap();

        let dates: Vec<Date> = calendar.days().iter().map(ActivityDay::date).collect();
        assert_eq!(dates, vec![date(1), date(2), date(3), date(4), date(5)]);
    }

    fn day_total(day: &ActivityDay) -> u64 {
        day.by_category().iter().map(|(_, c)| c).sum()
    }

    /// The five levels map to 0 to 4 in order. The page shades cells from
    /// this number, so two levels sharing one would look the same.
    #[test]
    fn each_level_has_its_own_number() {
        assert_eq!(ActivityLevel::None.as_u8(), 0);
        assert_eq!(ActivityLevel::Light.as_u8(), 1);
        assert_eq!(ActivityLevel::Moderate.as_u8(), 2);
        assert_eq!(ActivityLevel::High.as_u8(), 3);
        assert_eq!(ActivityLevel::Peak.as_u8(), 4);
    }
}
