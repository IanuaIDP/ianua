//! How long a session is kept once it is over.
//!
//! An ended or expired session lets nobody in, but it is kept for a while:
//! the person sees where they were signed in, their data export lists it,
//! and a refresh token presented again after its session was replaced is
//! still recognised as reused. After [`ENDED_KEPT_FOR`] it is removed. What
//! happened stays in the audit trail, which keeps sign-ins as long as each
//! tenant's compliance asks.
//!
//! A session is over once it expired, or once it was ended and is not the
//! one a later session replaced by a refresh: a replaced session stays
//! until its line of refreshes runs out, so reuse of its token is still
//! caught while the line lives.

use time::{Duration, OffsetDateTime};

/// How long a session is kept after it expired, or after it was last used
/// once ended.
pub const ENDED_KEPT_FOR: Duration = Duration::days(90);

/// The moment before which an ended or expired session is removed, at
/// `now`.
#[must_use]
pub fn ended_kept_since(now: OffsetDateTime) -> OffsetDateTime {
    now.saturating_sub(ENDED_KEPT_FOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session that ran out ninety days ago is past its keeping, one that
    /// ran out yesterday is not.
    #[test]
    fn the_cutoff_is_ninety_days_back() {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::days(365);

        let cutoff = ended_kept_since(now);

        assert_eq!(cutoff, now - Duration::days(90));
        assert!(now - Duration::days(1) > cutoff);
    }
}
