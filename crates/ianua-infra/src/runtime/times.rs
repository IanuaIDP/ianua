//! The wall clock in a timezone, read from the timezone rules bundled into
//! the binary, so a tenant's zone means the same on every node whatever
//! the host has installed.

use ianua_app::ports::scheduling::TimeZones;
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::Timezone;
use jiff::Timestamp;
use jiff::civil::DateTime;
use jiff::tz::TimeZone;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

/// Local times read from the bundled timezone database.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalTimeZones;

impl TimeZones for LocalTimeZones {
    fn local(&self, zone: &Timezone, at: OffsetDateTime) -> Result<PrimitiveDateTime, DomainError> {
        let rules = TimeZone::get(zone.as_str()).map_err(DomainError::infra)?;
        let instant = instant_of(at)?;
        wall_clock(instant.to_zoned(rules).datetime())
    }
}

/// `at` as the timezone crate counts moments.
pub(super) fn instant_of(at: OffsetDateTime) -> Result<Timestamp, DomainError> {
    let nanos = i32::try_from(at.nanosecond()).map_err(DomainError::infra)?;
    Timestamp::new(at.unix_timestamp(), nanos).map_err(DomainError::infra)
}

/// The civil date and time `local` names, as the `time` crate spells it.
fn wall_clock(local: DateTime) -> Result<PrimitiveDateTime, DomainError> {
    let month = Month::try_from(u8::try_from(local.month()).map_err(DomainError::infra)?)
        .map_err(DomainError::infra)?;
    let day = u8::try_from(local.day()).map_err(DomainError::infra)?;
    let date = Date::from_calendar_date(i32::from(local.year()), month, day)
        .map_err(DomainError::infra)?;
    let time = Time::from_hms_nano(
        u8::try_from(local.hour()).map_err(DomainError::infra)?,
        u8::try_from(local.minute()).map_err(DomainError::infra)?,
        u8::try_from(local.second()).map_err(DomainError::infra)?,
        u32::try_from(local.subsec_nanosecond()).map_err(DomainError::infra)?,
    )
    .map_err(DomainError::infra)?;
    Ok(PrimitiveDateTime::new(date, time))
}

#[cfg(test)]
mod tests {
    use time::UtcOffset;

    use super::*;

    fn zone(name: &str) -> Timezone {
        Timezone::new(name).unwrap()
    }

    /// A wall clock reading on `day` of `month` 2026 at `hour:minute`, with
    /// `millis` past the second.
    fn reading(
        month: Month,
        day: u8,
        (hour, minute, second): (u8, u8, u8),
        millis: u16,
    ) -> PrimitiveDateTime {
        PrimitiveDateTime::new(
            Date::from_calendar_date(2026, month, day).unwrap(),
            Time::from_hms_milli(hour, minute, second, millis).unwrap(),
        )
    }

    /// The moment the reading names at `offset_hours` from UTC.
    fn moment(clock: PrimitiveDateTime, offset_hours: i8) -> OffsetDateTime {
        clock.assume_offset(UtcOffset::from_hms(offset_hours, 0, 0).unwrap())
    }

    fn local(name: &str, at: OffsetDateTime) -> PrimitiveDateTime {
        LocalTimeZones.local(&zone(name), at).unwrap()
    }

    /// Noon in UTC reads as two in the afternoon in Berlin in summer.
    #[test]
    fn a_summer_moment_reads_in_the_zones_summer_time() {
        let noon = moment(reading(Month::July, 1, (12, 0, 0), 0), 0);

        let read = local("Europe/Berlin", noon);

        assert_eq!(read, reading(Month::July, 1, (14, 0, 0), 0));
    }

    /// Berlin moves its clocks forward at one in the morning UTC on the
    /// last Sunday of March: a minute before reads 01:59, a minute after
    /// reads 03:01, and 02:30 never appears.
    #[test]
    fn the_spring_change_skips_an_hour() {
        let before = moment(reading(Month::March, 29, (0, 59, 0), 0), 0);
        let after = moment(reading(Month::March, 29, (1, 1, 0), 0), 0);

        let read_before = local("Europe/Berlin", before);
        let read_after = local("Europe/Berlin", after);

        assert_eq!(read_before, reading(Month::March, 29, (1, 59, 0), 0));
        assert_eq!(read_after, reading(Month::March, 29, (3, 1, 0), 0));
    }

    /// New York moves its clocks back at six in the morning UTC on the
    /// first Sunday of November, so two moments an hour apart both read
    /// 01:30.
    #[test]
    fn the_autumn_change_repeats_an_hour() {
        let first = moment(reading(Month::November, 1, (5, 30, 0), 0), 0);
        let second = moment(reading(Month::November, 1, (6, 30, 0), 0), 0);

        let read_first = local("America/New_York", first);
        let read_second = local("America/New_York", second);

        assert_eq!(read_first, reading(Month::November, 1, (1, 30, 0), 0));
        assert_eq!(read_second, reading(Month::November, 1, (1, 30, 0), 0));
    }

    /// A moment given with an offset of its own reads the same as that
    /// moment in UTC, with its seconds and fractions kept.
    #[test]
    fn the_offset_given_does_not_change_the_reading() {
        let at = moment(reading(Month::January, 15, (8, 0, 30), 250), 2);

        let read = local("Asia/Tokyo", at);

        assert_eq!(read, reading(Month::January, 15, (15, 0, 30), 250));
    }

    /// UTC reads a moment exactly as it is.
    #[test]
    fn utc_reads_the_moment_as_it_is() {
        let at = moment(reading(Month::June, 30, (23, 59, 59), 999), 0);

        let read = local("UTC", at);

        assert_eq!(read, reading(Month::June, 30, (23, 59, 59), 999));
    }
}
