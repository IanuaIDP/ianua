//! The inclusive range of UTC calendar days an activity calendar covers.

use time::{Date, Duration, OffsetDateTime, PrimitiveDateTime, Time};

use crate::message;
use crate::shared::errors::DomainError;

/// An inclusive `[start, end]` range of UTC calendar days.
///
/// Activity is counted per UTC day, so the range holds dates, not
/// instants. It covers at most [`MAX_DAYS`](Self::MAX_DAYS) days. That
/// keeps the counting query from scanning years of audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalendarRange {
    start: Date,
    end: Date,
}

impl CalendarRange {
    /// The most days one calendar may cover. That is one leap year.
    pub const MAX_DAYS: u16 = 366;

    /// Days covered by [`trailing_year`](Self::trailing_year), the last
    /// twelve months as GitHub shows them.
    const TRAILING_YEAR_DAYS: i64 = 365;

    /// Creates a range from `start` to `end`, both inclusive.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `end` is before `start`.
    /// - [`DomainError::Validation`] when the range covers more than
    ///   [`MAX_DAYS`](Self::MAX_DAYS) days.
    pub fn new(start: Date, end: Date) -> Result<Self, DomainError> {
        if end < start {
            return Err(DomainError::invalid(message!(
                "activity-calendar-range-end-must-not-precede",
                "calendar range end must not precede start"
            )));
        }

        let range = Self { start, end };
        if range.day_count() > u32::from(Self::MAX_DAYS) {
            return Err(DomainError::invalid(message!(
                "activity-calendar-range-must-not-exceed-days",
                format!("calendar range must not exceed {} days", Self::MAX_DAYS)
            )));
        }

        Ok(range)
    }

    /// The rolling one-year window ending at `end`, inclusive.
    #[must_use]
    pub fn trailing_year(end: Date) -> Self {
        let start = end
            .checked_sub(Duration::days(Self::TRAILING_YEAR_DAYS - 1))
            .unwrap_or(Date::MIN);

        Self { start, end }
    }

    /// The first day of the range.
    #[must_use]
    pub fn start(&self) -> Date {
        self.start
    }

    /// The last day of the range.
    #[must_use]
    pub fn end(&self) -> Date {
        self.end
    }

    /// The number of days covered, counting both endpoints.
    #[must_use]
    pub fn day_count(&self) -> u32 {
        let days = self
            .end
            .to_julian_day()
            .saturating_sub(self.start.to_julian_day())
            .saturating_add(1);
        u32::try_from(days).unwrap_or(u32::MAX)
    }

    /// Whether `date` falls within the range.
    #[must_use]
    pub fn contains(&self, date: Date) -> bool {
        self.start <= date && date <= self.end
    }

    /// Iterates every day of the range in ascending order.
    pub fn days(&self) -> impl Iterator<Item = Date> + '_ {
        std::iter::successors(Some(self.start), move |day| {
            day.next_day().filter(|next| *next <= self.end)
        })
    }

    /// The UTC instants from the first midnight of the range up to, but not
    /// including, the midnight after its last day.
    ///
    /// Storage queries filter event times with it.
    #[must_use]
    pub fn utc_window(&self) -> (OffsetDateTime, OffsetDateTime) {
        let start = PrimitiveDateTime::new(self.start, Time::MIDNIGHT).assume_utc();
        let end = self
            .end
            .next_day()
            .map_or(PrimitiveDateTime::MAX.assume_utc(), |day| {
                PrimitiveDateTime::new(day, Time::MIDNIGHT).assume_utc()
            });

        (start, end)
    }
}

#[cfg(test)]
mod tests {
    use time::Month;

    use super::*;

    fn date(year: i32, month: Month, day: u8) -> Date {
        Date::from_calendar_date(year, month, day).unwrap()
    }

    /// A range from 2 March back to 1 March is refused, since the end
    /// comes before the start.
    #[test]
    fn new_rejects_reversed_range() {
        let result = CalendarRange::new(date(2026, Month::March, 2), date(2026, Month::March, 1));
        assert!(result.is_err());
    }

    /// A range that starts and ends on 1 March is allowed. It counts as one
    /// day, because both ends are included.
    #[test]
    fn new_accepts_single_day() {
        let day = date(2026, Month::March, 1);
        let range = CalendarRange::new(day, day).unwrap();
        assert_eq!(range.day_count(), 1);
    }

    /// A range from 1 January 2025 to 2 January 2026 covers 367 days. It is
    /// refused, so one query never scans more than a year of records.
    #[test]
    fn new_rejects_span_beyond_max_days() {
        let start = date(2025, Month::January, 1);
        let end = date(2026, Month::January, 2);
        assert!(CalendarRange::new(start, end).is_err());
    }

    /// The whole leap year 2024 covers exactly 366 days. It is allowed, so
    /// the limit itself is not off by one.
    #[test]
    fn new_accepts_span_at_max_days() {
        let start = date(2024, Month::January, 1);
        let end = date(2024, Month::December, 31);
        let range = CalendarRange::new(start, end).unwrap();
        assert_eq!(range.day_count(), 366);
    }

    /// The year ending on 4 July 2026 starts on 5 July 2025. It holds 365
    /// days with the given day as its last.
    #[test]
    fn trailing_year_spans_365_days() {
        let range = CalendarRange::trailing_year(date(2026, Month::July, 4));
        assert_eq!(range.day_count(), 365);
        assert_eq!(range.end(), date(2026, Month::July, 4));
        assert_eq!(range.start(), date(2025, Month::July, 5));
    }

    /// A range from 27 February to 2 March 2026 gives four days in order.
    /// The month change is crossed without skipping or repeating a day.
    #[test]
    fn days_yields_every_day_in_order() {
        let range =
            CalendarRange::new(date(2026, Month::February, 27), date(2026, Month::March, 2))
                .unwrap();

        let days: Vec<Date> = range.days().collect();

        assert_eq!(
            days,
            vec![
                date(2026, Month::February, 27),
                date(2026, Month::February, 28),
                date(2026, Month::March, 1),
                date(2026, Month::March, 2),
            ]
        );
    }

    /// For 1 to 3 March, both end days count as inside. The day before and
    /// the day after do not.
    #[test]
    fn contains_matches_endpoints_only_within_range() {
        let range =
            CalendarRange::new(date(2026, Month::March, 1), date(2026, Month::March, 3)).unwrap();

        assert!(range.contains(date(2026, Month::March, 1)));
        assert!(range.contains(date(2026, Month::March, 3)));
        assert!(!range.contains(date(2026, Month::February, 28)));
        assert!(!range.contains(date(2026, Month::March, 4)));
    }

    /// For 1 to 2 March, the instants run from midnight on 1 March to
    /// midnight on 3 March. That end is left out, so all of 2 March counts.
    #[test]
    fn utc_window_is_half_open_over_full_days() {
        let range =
            CalendarRange::new(date(2026, Month::March, 1), date(2026, Month::March, 2)).unwrap();

        let (start, end) = range.utc_window();

        assert_eq!(start.date(), date(2026, Month::March, 1));
        assert_eq!(start.time(), Time::MIDNIGHT);
        assert_eq!(end.date(), date(2026, Month::March, 3));
        assert_eq!(end.time(), Time::MIDNIGHT);
    }
}
