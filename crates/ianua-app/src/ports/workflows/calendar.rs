//! The calendar: when a team's working hours next begin, on the clock of
//! the place they name.

use ianua_domain::domains::workflows::design::working_hours::WorkingHours;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;

/// Reads working hours on their own clock.
///
/// Acme's support works Monday to Friday, 9:00 to 17:00 in Berlin. Asked on
/// a Saturday night, the calendar answers Monday at 9:00 Berlin time, as a
/// moment; asked on a Tuesday at 10:00 there, it answers that same moment.
pub trait WorkingCalendar: Send + Sync {
    /// When `hours` next begin at or after `after`: `after` itself while
    /// they are on.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Infrastructure`] when the hours' time zone
    /// cannot be read.
    fn next_opening(
        &self,
        hours: &WorkingHours,
        after: OffsetDateTime,
    ) -> Result<OffsetDateTime, DomainError>;
}
