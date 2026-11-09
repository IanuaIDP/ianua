//! Records an import set aside: where each stood and why it did not become
//! an account.

use crate::domains::identity::account::import::MAX_BATCH_RECORDS;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;

/// Where a record stood in the request that sent it, counted from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordLine(u32);

impl RecordLine {
    /// The record at `line`, counted from one.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] for line zero, or a line past
    ///   `MAX_BATCH_RECORDS`.
    pub fn new(line: u32) -> Result<Self, DomainError> {
        let most = u32::try_from(MAX_BATCH_RECORDS).unwrap_or(u32::MAX);
        validate_range("line", line, 1..=most)?;
        Ok(Self(line))
    }

    /// The line of the record at `index`, counted from zero.
    pub(crate) fn of_index(index: usize) -> Self {
        Self(u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX))
    }

    /// The line, counted from one.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Why a record did not become an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordRefusal {
    /// Another account of the tenant had the address by the time the
    /// record's chunk ran.
    AddressTaken,
    /// The record names the account as its own manager.
    OwnManager,
    /// The tenant's plan had no room for another user by the time the
    /// record's chunk ran: another import or sign-up filled it first.
    UserLimitReached,
}

impl RecordRefusal {
    /// The reason's name, stable across releases.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AddressTaken => "address_taken",
            Self::OwnManager => "own_manager",
            Self::UserLimitReached => "user_limit_reached",
        }
    }
}

/// A record that did not become an account: where it stood and why.
///
/// It says nothing the record held, so no address and no password hash is
/// kept with it or shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailedRecord {
    line: RecordLine,
    reason: RecordRefusal,
}

impl FailedRecord {
    /// The record at `line` refused for `reason`.
    #[must_use]
    pub fn new(line: RecordLine, reason: RecordRefusal) -> Self {
        Self { line, reason }
    }

    /// Where it stood in the request.
    #[must_use]
    pub fn line(&self) -> RecordLine {
        self.line
    }

    /// Why it was refused.
    #[must_use]
    pub fn reason(&self) -> RecordRefusal {
        self.reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Line zero is no line: lines count from one.
    #[test]
    fn line_zero_is_refused() {
        assert!(RecordLine::new(0).is_err());
        assert_eq!(RecordLine::new(1).unwrap().get(), 1);
    }

    /// No batch holds a ten-thousand-and-first record, so no refusal names
    /// one.
    #[test]
    fn a_line_past_the_largest_batch_is_refused() {
        assert!(RecordLine::new(10_001).is_err());
    }

    /// The admin reading an import's errors sees each reason by a name that
    /// stays the same across releases, a record past the plan's room among
    /// them.
    #[test]
    fn each_reason_keeps_its_name() {
        let names = [
            RecordRefusal::AddressTaken,
            RecordRefusal::OwnManager,
            RecordRefusal::UserLimitReached,
        ]
        .map(RecordRefusal::as_str);

        assert_eq!(
            names,
            ["address_taken", "own_manager", "user_limit_reached"]
        );
    }

    /// The first record, at index zero, stands on line one.
    #[test]
    fn the_first_record_stands_on_line_one() {
        assert_eq!(RecordLine::of_index(0).get(), 1);
    }
}
