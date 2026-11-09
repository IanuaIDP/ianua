use std::ops::RangeInclusive;

use crate::shared::validation::error::ValidationError;

/// Checks that a number falls inside `range`, both ends included.
///
/// Works with any unsigned integer type that converts to `u64`.
///
/// # Errors
///
/// - [`ValidationError::OutOfRange`] if the value is outside the range. It
///   carries the field, the bounds and the value.
///
/// # Examples
///
/// ```
/// # use ianua_domain::shared::validation::numeric::validate_range;
/// assert!(validate_range("retention_days", 365u32, 30..=3650).is_ok());
/// assert!(validate_range("retention_days", 0u32, 30..=3650).is_err());
/// ```
pub fn validate_range<T>(
    field: &'static str,
    value: T,
    range: RangeInclusive<T>,
) -> Result<(), ValidationError>
where
    T: Into<u64> + PartialOrd + Copy,
{
    if range.contains(&value) {
        return Ok(());
    }

    Err(ValidationError::OutOfRange {
        field,
        min: (*range.start()).into(),
        max: (*range.end()).into(),
        actual: value.into(),
    })
}

/// Checks that a list's length falls inside `range`, both ends included.
///
/// # Errors
///
/// - [`ValidationError::Count`] if `count` is outside the range.
///
/// # Examples
///
/// ```
/// # use ianua_domain::shared::validation::numeric::validate_count;
/// assert!(validate_count("hosts", 2, 1..=20).is_ok());
/// assert!(validate_count("hosts", 0, 1..=20).is_err());
/// ```
pub fn validate_count(
    field: &'static str,
    count: usize,
    range: RangeInclusive<usize>,
) -> Result<(), ValidationError> {
    if range.contains(&count) {
        return Ok(());
    }

    Err(ValidationError::Count {
        field,
        min: *range.start(),
        max: *range.end(),
        actual: count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A retention of 365 days falls inside 30 to 3650 and passes.
    #[test]
    fn accepts_value_in_range() {
        assert!(validate_range("days", 365u32, 30..=3650).is_ok());
    }

    /// 30, the lowest value of the range, passes. The lower end is included.
    #[test]
    fn accepts_at_minimum() {
        assert!(validate_range("days", 30u32, 30..=3650).is_ok());
    }

    /// 3650, the highest value of the range, passes. The upper end is
    /// included.
    #[test]
    fn accepts_at_maximum() {
        assert!(validate_range("days", 3650u32, 30..=3650).is_ok());
    }

    /// 29 days, one below the range, is refused. The error names `days`,
    /// has the code `out_of_range`, and tells the caller both bounds and the
    /// value sent.
    #[test]
    fn rejects_below_minimum() {
        let err = validate_range("days", 29u32, 30..=3650).unwrap_err();

        assert_eq!(err.field(), Some("days"));
        assert_eq!(err.code(), "out_of_range");
        assert_eq!(
            err.to_string(),
            "days must be between 30 and 3650. You provided 29."
        );
    }

    /// 3651 days, one above the range, is refused with the field `days` and
    /// the code `out_of_range`.
    #[test]
    fn rejects_above_maximum() {
        let err = validate_range("days", 3651u32, 30..=3650).unwrap_err();

        assert_eq!(err.field(), Some("days"));
        assert_eq!(err.code(), "out_of_range");
    }

    /// Zero days is refused when the range starts at 30. Zero is not read as
    /// "unset" or "no limit".
    #[test]
    fn zero_below_the_minimum_is_refused() {
        assert!(validate_range("days", 0u32, 30..=3650).is_err());
    }

    /// A `u16` port of 8080 passes the range 1 to 65535, and port 0 is
    /// refused.
    #[test]
    fn works_with_u16() {
        assert!(validate_range("port", 8080u16, 1..=65535).is_ok());
        assert!(validate_range("port", 0u16, 1..=65535).is_err());
    }

    /// A `u64` value of 100 passes the range 1 to 1000.
    #[test]
    fn works_with_u64() {
        assert!(validate_range("big", 100u64, 1..=1000).is_ok());
    }

    /// A list of one host and a list of three both pass a limit of 1 to 3.
    #[test]
    fn a_list_within_its_bounds_is_accepted() {
        assert!(validate_count("hosts", 1, 1..=3).is_ok());
        assert!(validate_count("hosts", 3, 1..=3).is_ok());
    }

    /// With a limit of 1 to 3 hosts, an empty list is refused with a count
    /// error reporting 0, and a list of four is refused too.
    #[test]
    fn an_empty_or_overfull_list_is_refused() {
        assert!(matches!(
            validate_count("hosts", 0, 1..=3),
            Err(ValidationError::Count { actual: 0, .. })
        ));
        assert!(validate_count("hosts", 4, 1..=3).is_err());
    }
}
