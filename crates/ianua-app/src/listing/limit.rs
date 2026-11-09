//! How many rows one page holds.

use ianua_domain::shared::validation::ValidationError;
use ianua_domain::shared::validation::numeric::validate_range;

/// The most rows a caller may ask for on one page.
const MOST_ASKED: u32 = 100;

/// The page size when a caller does not name one.
const USUAL: u32 = 20;

/// How many rows one page holds, never zero.
///
/// A caller's limit comes through [`Limit::new`], which keeps it between 1
/// and 100. A use case that reads in bulk for itself, such as a sweep or a
/// route table, sizes its pages with [`Limit::internal`]; no caller input
/// reaches that constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit(u32);

impl Limit {
    /// The limit a caller asked for.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::OutOfRange`] for `limit` when it is below 1
    /// or above 100.
    pub fn new(limit: u32) -> Result<Self, ValidationError> {
        validate_range("limit", limit, 1..=MOST_ASKED)?;
        Ok(Self(limit))
    }

    /// A page size a use case settles on for its own reads. Zero reads as
    /// one row.
    #[must_use]
    pub const fn internal(limit: u32) -> Self {
        match limit {
            0 => Self(1),
            rows => Self(rows),
        }
    }

    /// The number of rows on a full page.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The rows a store reads for a page: one more than it answers, so the
    /// extra row tells whether another page follows.
    #[must_use]
    pub fn fetch(self) -> u64 {
        u64::from(self.0) + 1
    }

    /// The page size as a slice length.
    #[must_use]
    pub fn as_usize(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

impl Default for Limit {
    fn default() -> Self {
        Self(USUAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A caller who names no page size gets twenty rows a page.
    #[test]
    fn the_usual_page_holds_twenty_rows() {
        assert_eq!(Limit::default().get(), 20);
    }

    /// Ann asks for 50 rows a page. That is within the range, so she gets
    /// 50.
    #[test]
    fn a_limit_within_the_range_is_kept() {
        assert_eq!(Limit::new(50).map(Limit::get).ok(), Some(50));
    }

    /// Asking for 500 rows returns an out-of-range error on the limit field.
    #[test]
    fn a_limit_above_the_range_is_refused() {
        let refused = Limit::new(500).unwrap_err();

        assert_eq!(refused.field(), Some("limit"));
        assert_eq!(refused.code(), "out_of_range");
    }

    /// A page of no rows is no page, so a limit of zero is refused rather
    /// than read as the usual size.
    #[test]
    fn a_limit_of_zero_is_refused() {
        assert!(Limit::new(0).is_err());
    }

    /// A store reads one row more than the page holds, to learn whether a
    /// next page exists.
    #[test]
    fn a_store_reads_one_row_past_the_page() {
        assert_eq!(Limit::new(20).unwrap().fetch(), 21);
    }

    /// A sweep that sizes its own pages may read past what a caller may ask
    /// for, but never zero rows.
    #[test]
    fn an_internal_limit_reads_past_the_caller_range_and_never_zero() {
        assert_eq!(
            (Limit::internal(500).get(), Limit::internal(0).get()),
            (500, 1)
        );
    }
}
