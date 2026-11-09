//! When working hours next begin, read on the clock of the place they name
//! from the timezone rules bundled into the binary.

use ianua_app::ports::workflows::WorkingCalendar;
use ianua_domain::domains::workflows::design::working_hours::{
    MINUTES_IN_A_DAY, WorkingHours, weekday_numbered,
};
use ianua_domain::shared::errors::DomainError;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use jiff::{Timestamp, ToSpan as _, Zoned};
use time::OffsetDateTime;

use crate::runtime::times::instant_of;

/// Working hours read from the bundled timezone database.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalWorkingCalendar;

impl WorkingCalendar for LocalWorkingCalendar {
    fn next_opening(
        &self,
        hours: &WorkingHours,
        after: OffsetDateTime,
    ) -> Result<OffsetDateTime, DomainError> {
        let rules = TimeZone::get(hours.timezone().as_str()).map_err(DomainError::infra)?;
        let now = instant_of(after)?.to_zoned(rules.clone());
        for ahead in 0..=7_i64 {
            let day = now
                .date()
                .checked_add(ahead.days())
                .map_err(DomainError::infra)?;
            let Some(shift) = shift_on(hours, day, &rules)? else {
                continue;
            };
            if let Some(begins) = shift.begins_for(&now) {
                return moment_of(begins);
            }
        }
        Err(DomainError::infra_msg(
            "working hours begin on no day within a week",
        ))
    }
}

/// One day's working hours, as two moments.
struct Shift {
    opens: Timestamp,
    closes: Timestamp,
}

impl Shift {
    /// When this shift begins for someone asking at `now`: `now` while it
    /// is on, its start when it is still to come, and nothing once over.
    fn begins_for(&self, now: &Zoned) -> Option<Timestamp> {
        let asked = now.timestamp();
        if asked >= self.closes {
            return None;
        }
        Some(asked.max(self.opens))
    }
}

/// The hours worked on `day`, or none when `day` is not worked.
fn shift_on(
    hours: &WorkingHours,
    day: Date,
    rules: &TimeZone,
) -> Result<Option<Shift>, DomainError> {
    let number = u8::try_from(day.weekday().to_monday_one_offset()).map_err(DomainError::infra)?;
    let worked = weekday_numbered(number).is_some_and(|weekday| hours.days().contains(&weekday));
    if !worked {
        return Ok(None);
    }
    Ok(Some(Shift {
        opens: minute_of(day, hours.opens(), rules)?,
        closes: minute_of(day, hours.closes(), rules)?,
    }))
}

/// The moment `minute` minutes after midnight on `day` reads on `rules`'
/// clock; the day's last minute ends at the next midnight. A time a change
/// of clocks skips or repeats reads as the clock first shows it.
fn minute_of(day: Date, minute: u16, rules: &TimeZone) -> Result<Timestamp, DomainError> {
    let (day, minute) = match minute {
        MINUTES_IN_A_DAY => (day.tomorrow().map_err(DomainError::infra)?, 0),
        other => (day, other),
    };
    let hour = i8::try_from(minute / 60).map_err(DomainError::infra)?;
    let past = i8::try_from(minute % 60).map_err(DomainError::infra)?;
    let local = day.at(hour, past, 0, 0);
    Ok(local
        .to_zoned(rules.clone())
        .map_err(DomainError::infra)?
        .timestamp())
}

/// `instant` as the `time` crate counts moments.
fn moment_of(instant: Timestamp) -> Result<OffsetDateTime, DomainError> {
    OffsetDateTime::from_unix_timestamp_nanos(instant.as_nanosecond()).map_err(DomainError::infra)
}

#[cfg(test)]
mod tests {
    use ianua_domain::domains::workflows::design::working_hours::WorkingHoursParams;
    use ianua_domain::types::Timezone;
    use time::{Date, Month, Time, Weekday};

    use super::*;

    /// Acme's support: Monday to Friday, 9:00 to 17:00 in Berlin.
    fn support() -> WorkingHours {
        WorkingHours::new(WorkingHoursParams {
            days: vec![
                Weekday::Monday,
                Weekday::Tuesday,
                Weekday::Wednesday,
                Weekday::Thursday,
                Weekday::Friday,
            ],
            opens: 9 * 60,
            closes: 17 * 60,
            timezone: Timezone::new("Europe/Berlin").unwrap(),
        })
        .unwrap()
    }

    /// `hour`:00 UTC on `day` `month` 2026.
    fn utc(month: Month, day: u8, hour: u8) -> OffsetDateTime {
        Date::from_calendar_date(2026, month, day)
            .unwrap()
            .with_time(Time::from_hms(hour, 0, 0).unwrap())
            .assume_utc()
    }

    fn opening(after: OffsetDateTime) -> OffsetDateTime {
        LocalWorkingCalendar
            .next_opening(&support(), after)
            .unwrap()
    }

    /// Tuesday 7 July 2026 at 10:00 in Berlin is 8:00 UTC: support is on,
    /// so the hours begin at once.
    #[test]
    fn during_the_hours_they_begin_at_once() {
        let tuesday_ten = utc(Month::July, 7, 8);

        assert_eq!(opening(tuesday_ten), tuesday_ten);
    }

    /// Saturday night in Berlin: support next opens on Monday at 9:00
    /// Berlin summer time, 7:00 UTC.
    #[test]
    fn over_the_weekend_they_begin_on_monday_morning() {
        let saturday_night = utc(Month::July, 11, 21);

        assert_eq!(opening(saturday_night), utc(Month::July, 13, 7));
    }

    /// Wednesday at 18:00 in Berlin, after hours: support opens on
    /// Thursday at 9:00. In winter Berlin is an hour ahead of UTC, so that
    /// is 8:00 UTC.
    #[test]
    fn after_hours_they_begin_the_next_working_morning() {
        let wednesday_evening = utc(Month::January, 14, 17);

        assert_eq!(opening(wednesday_evening), utc(Month::January, 15, 8));
    }
}
