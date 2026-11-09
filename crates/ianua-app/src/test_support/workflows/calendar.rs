//! A calendar for tests: working hours begin when the test says.

use std::sync::Arc;

use ianua_domain::domains::workflows::design::working_hours::WorkingHours;
use ianua_domain::shared::errors::DomainError;
use time::OffsetDateTime;

use crate::ports::workflows::WorkingCalendar;
use crate::test_support::Fake;

/// When a test calendar says working hours begin.
pub enum FakeCalendar {
    /// They are on now: at the moment asked about.
    OnNow,
    /// At this moment, whenever asked.
    BeginAt(OffsetDateTime),
}

impl WorkingCalendar for FakeCalendar {
    fn next_opening(
        &self,
        _hours: &WorkingHours,
        after: OffsetDateTime,
    ) -> Result<OffsetDateTime, DomainError> {
        match self {
            Self::OnNow => Ok(after),
            Self::BeginAt(at) => Ok(*at),
        }
    }
}

impl Fake for Arc<dyn WorkingCalendar> {
    fn fake() -> Self {
        Arc::new(FakeCalendar::OnNow)
    }
}
