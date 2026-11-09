//! A duration measured in whole milliseconds, used for latency and
//! authentication-time figures.

use std::fmt;

/// A non-negative duration in whole milliseconds.
///
/// Used for both p95 request latency and average authentication time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LatencyMs(u32);

impl LatencyMs {
    /// Wraps a millisecond measurement.
    #[must_use]
    pub fn new(millis: u32) -> Self {
        Self(millis)
    }

    /// The value in milliseconds.
    #[must_use]
    pub fn millis(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for LatencyMs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A latency built from 42 milliseconds reads back as 42.
    #[test]
    fn a_latency_reports_its_milliseconds() {
        assert_eq!(LatencyMs::new(42).millis(), 42);
    }

    /// A latency of 125 milliseconds prints as `125ms` on the overview.
    #[test]
    fn displays_with_unit() {
        assert_eq!(LatencyMs::new(125).to_string(), "125ms");
    }
}
