//! A day's count of one event type as the audit tables answer it, and the
//! calendar's cells summed from many of them, one per day and category.

use std::collections::BTreeMap;

use ianua_domain::domains::activity::{ActivityCategory, DailyCategoryCount};
use ianua_domain::shared::errors::DomainError;
use ianua_domain::types::EventType;
use time::Date;

/// How many records of one event type fell on one day, as a query reads
/// it.
pub(super) struct DayCountRecord {
    pub(super) day: Date,
    pub(super) event_type: String,
    pub(super) count: i64,
}

/// The calendar's cells `records` add up to, each event filed under its
/// category, ascending by day and then by the category's stored name.
///
/// # Errors
///
/// Returns `DomainError::Infrastructure` when a record names an event type
/// this release does not know, or a count below zero.
pub(super) fn into_counts(
    records: impl IntoIterator<Item = DayCountRecord>,
) -> Result<Vec<DailyCategoryCount>, DomainError> {
    let mut cells: BTreeMap<(Date, &'static str), (ActivityCategory, u64)> = BTreeMap::new();
    for record in records {
        let event_type = EventType::parse(&record.event_type)
            .ok_or_else(|| DomainError::corrupt_row("audit record", "an unknown event type"))?;
        let category = ActivityCategory::from_event_type(&event_type);
        let count = u64::try_from(record.count).map_err(DomainError::infra)?;
        let cell = cells
            .entry((record.day, category.as_str()))
            .or_insert((category, 0));
        cell.1 = cell.1.saturating_add(count);
    }
    Ok(cells
        .into_iter()
        .map(|((date, _), (category, count))| DailyCategoryCount {
            date,
            category,
            count,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use time::Month;

    use super::*;

    fn day(of_january: u8) -> Date {
        Date::from_calendar_date(2027, Month::January, of_january).unwrap()
    }

    fn record(day: Date, event_type: &str, count: i64) -> DayCountRecord {
        DayCountRecord {
            day,
            event_type: event_type.to_owned(),
            count,
        }
    }

    /// Two sign-in types on one day sum into one authentication cell, and
    /// the cells come by day, then by the category's stored name.
    #[test]
    fn counts_sum_into_one_cell_per_day_and_category() {
        let records = [
            record(day(16), "authentication.login_failed", 1),
            record(day(15), "identity.user_registered", 2),
            record(day(15), "authentication.login_failed", 3),
            record(day(15), "authentication.login_succeeded", 4),
        ];

        let cells = into_counts(records).unwrap();

        let read: Vec<_> = cells
            .iter()
            .map(|cell| (cell.date, cell.category, cell.count))
            .collect();
        assert_eq!(
            read,
            [
                (day(15), ActivityCategory::Authentication, 7),
                (day(15), ActivityCategory::Identity, 2),
                (day(16), ActivityCategory::Authentication, 1),
            ]
        );
    }

    /// A count for an unknown event type fails as corrupt storage instead
    /// of being assigned to an activity category.
    #[test]
    fn an_unknown_event_type_is_refused() {
        let records = [record(day(15), "wizard.cast", 1)];

        assert!(matches!(
            into_counts(records),
            Err(DomainError::Infrastructure(_))
        ));
    }
}
