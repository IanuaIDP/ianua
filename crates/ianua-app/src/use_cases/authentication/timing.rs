//! How long a sign-in took, for the "average authentication time" metric
//! its success event feeds.

use std::time::Instant;

use ianua_domain::types::Fact;

/// Milliseconds since `started`, saturated to `u32`.
pub(in crate::use_cases::authentication) fn elapsed_millis(started: Instant) -> Fact<u32> {
    Fact::Known(u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Ann's sign-in took a quarter of a second. Its event says so, give or
    /// take the time the test itself takes.
    #[test]
    fn elapsed_millis_reports_the_time_that_has_passed() {
        let started = Instant::now()
            .checked_sub(Duration::from_millis(250))
            .unwrap();

        let Fact::Known(elapsed) = elapsed_millis(started) else {
            panic!("the time is always known");
        };

        assert!(elapsed >= 250, "got {elapsed}ms");
        assert!(elapsed < 60_000, "got {elapsed}ms");
    }
}
