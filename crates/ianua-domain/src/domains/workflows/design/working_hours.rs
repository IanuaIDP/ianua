//! The hours a team works, which a wait step may wait for.
//!
//! Acme's support team works Monday to Friday, 9:00 to 17:00 in Berlin. A
//! workflow that pages them on a Saturday night waits until Monday at 9:00
//! Berlin time, and one reaching them on a Tuesday at 10:00 goes on at once.
//! Only the calendar outside the domain knows what 9:00 in Berlin is on a
//! given day, so the wait is told when the hours next begin.

use time::{Duration, Weekday};

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::distinct::first_repeat;
use crate::shared::validation::numeric::{validate_count, validate_range};
use crate::types::Timezone;

/// The minutes in a day: an hour that closes at midnight closes at this
/// minute.
pub const MINUTES_IN_A_DAY: u16 = 24 * 60;

/// The longest a wait for working hours may last: a week, and a day to
/// spare for a change of clocks. Hours on any one weekday begin within
/// that.
pub(crate) const LONGEST_WAIT_FOR_HOURS: Duration = Duration::days(8);

/// The weekday numbered `number` counting Monday as 1, or `None` past
/// Sunday's 7.
#[must_use]
pub fn weekday_numbered(number: u8) -> Option<Weekday> {
    (1..=7)
        .contains(&number)
        .then(|| Weekday::Sunday.nth_next(number))
}

/// What working hours are made of, before they are checked.
#[derive(Debug, Clone)]
pub struct WorkingHoursParams {
    /// The days worked.
    pub days: Vec<Weekday>,
    /// When work begins, in minutes after midnight.
    pub opens: u16,
    /// When work ends, in minutes after midnight, after it begins.
    pub closes: u16,
    /// Where the clock is read.
    pub timezone: Timezone,
}

/// Days of the week worked, each between two times of the same day, on
/// the clock of one place.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        into = "crate::domains::workflows::stored::WorkingHoursWire",
        try_from = "crate::domains::workflows::stored::WorkingHoursWire"
    )
)]
pub struct WorkingHours {
    days: Vec<Weekday>,
    opens: u16,
    closes: u16,
    timezone: Timezone,
}

impl WorkingHours {
    /// Working hours as `params` give them.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when no day is worked, or a day is
    ///   named twice.
    /// - [`DomainError::Validation`] when work does not begin before it
    ///   ends on the same day.
    pub fn new(params: WorkingHoursParams) -> Result<Self, DomainError> {
        validate_count("days", params.days.len(), 1..=7)?;
        if first_repeat(params.days.iter().map(|day| day.number_from_monday())).is_some() {
            return Err(DomainError::invalid(message!(
                "workflows-a-working-day-is-named-twice",
                "a working day is named twice"
            )));
        }
        validate_range("closes", params.closes, 1..=MINUTES_IN_A_DAY)?;
        validate_range("opens", params.opens, 0..=params.closes.saturating_sub(1))?;
        Ok(Self {
            days: params.days,
            opens: params.opens,
            closes: params.closes,
            timezone: params.timezone,
        })
    }

    /// The days worked.
    #[must_use]
    pub fn days(&self) -> &[Weekday] {
        &self.days
    }

    /// When work begins, in minutes after midnight.
    #[must_use]
    pub fn opens(&self) -> u16 {
        self.opens
    }

    /// When work ends, in minutes after midnight.
    #[must_use]
    pub fn closes(&self) -> u16 {
        self.closes
    }

    /// Where the clock is read.
    #[must_use]
    pub fn timezone(&self) -> &Timezone {
        &self.timezone
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn weekdays() -> Vec<Weekday> {
        vec![
            Weekday::Monday,
            Weekday::Tuesday,
            Weekday::Wednesday,
            Weekday::Thursday,
            Weekday::Friday,
        ]
    }

    fn hours(days: Vec<Weekday>, opens: u16, closes: u16) -> Result<WorkingHours, DomainError> {
        WorkingHours::new(WorkingHoursParams {
            days,
            opens,
            closes,
            timezone: Timezone::new("Europe/Berlin").unwrap(),
        })
    }

    /// Monday to Friday, 9:00 to 17:00 in Berlin, is a working week.
    #[test]
    fn a_working_week_is_kept_as_given() {
        let week = hours(weekdays(), 9 * 60, 17 * 60).unwrap();

        assert_eq!(week.days().len(), 5);
        assert_eq!((week.opens(), week.closes()), (540, 1020));
        assert_eq!(week.timezone().as_str(), "Europe/Berlin");
    }

    /// No day worked, a day named twice, hours ending before they begin
    /// and hours ending past midnight are each refused.
    #[test]
    fn hours_that_could_never_begin_are_refused() {
        let monday_twice = vec![Weekday::Monday, Weekday::Monday];

        assert!(hours(Vec::new(), 540, 1020).is_err());
        assert!(hours(monday_twice, 540, 1020).is_err());
        assert!(hours(weekdays(), 1020, 540).is_err());
        assert!(hours(weekdays(), 540, 540).is_err());
        assert!(hours(weekdays(), 540, MINUTES_IN_A_DAY + 1).is_err());
    }
}
