//! Scoring a client on the shape of scanning: requests that mostly fail,
//! many distinct paths walked, or sign-ins failed again and again, even
//! while it stays under every rate limit.
//!
//! The gateway counts every finished request of a client in the tenant's
//! current recon window, refused or not, across the fleet. These are the
//! counts; what they call for is the stage's
//! [`ReconDetectionConfig::verdict`](crate::domains::proxy::stages::stage::ReconDetectionConfig::verdict).

/// What the fleet counted for one client in the current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReconSignals {
    /// Every finished request.
    pub total: u32,
    /// Requests refused with status 403 or 404.
    pub refusals: u32,
    /// Requests that failed authentication with status 401.
    pub auth_failures: u32,
    /// The distinct paths asked for.
    pub paths: u32,
}

/// What a client's window calls for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconVerdict {
    /// Nothing, or too little, tripped.
    Clean,
    /// Slow the client down.
    Tarpit,
    /// Refuse the client, and flag it for the tenants that refuse flagged
    /// addresses.
    Block,
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::domains::proxy::stages::stage::ReconDetectionConfig;
    use crate::types::Seconds;

    fn config() -> ReconDetectionConfig {
        ReconDetectionConfig {
            window_seconds: Seconds::new(3_600),
            min_requests: 4,
            error_ratio_threshold: 0.5,
            distinct_path_threshold: 50,
            auth_failure_threshold: 3,
            tarpit_signal_count: 1,
            block_signal_count: 2,
            tarpit_delay_ms: 2_000,
        }
    }

    fn signals(total: u32, refusals: u32, auth_failures: u32, paths: u32) -> ReconSignals {
        ReconSignals {
            total,
            refusals,
            auth_failures,
            paths,
        }
    }

    /// One refusal is not a ratio: below the minimum number of requests the
    /// refusal signal does not trip.
    #[test]
    fn too_few_requests_trip_no_refusal_signal() {
        assert_eq!(config().verdict(signals(1, 1, 0, 1)), ReconVerdict::Clean);
        assert_eq!(config().verdict(signals(4, 2, 0, 4)), ReconVerdict::Tarpit);
    }

    /// A client walking fifty paths is slowed; one also failing every
    /// request and three sign-ins is blocked; a quiet one is clean.
    #[test]
    fn every_signal_counts_toward_the_verdict() {
        assert_eq!(config().verdict(signals(4, 0, 0, 50)), ReconVerdict::Tarpit);
        assert_eq!(config().verdict(signals(4, 4, 3, 50)), ReconVerdict::Block);
        assert_eq!(config().verdict(signals(4, 0, 0, 4)), ReconVerdict::Clean);
    }

    fn rank(verdict: ReconVerdict) -> u8 {
        match verdict {
            ReconVerdict::Clean => 0,
            ReconVerdict::Tarpit => 1,
            ReconVerdict::Block => 2,
        }
    }

    proptest! {
        /// More failed sign-ins or more paths walked never make a client
        /// look cleaner: a scanner cannot lower its verdict by scanning
        /// more.
        #[test]
        fn more_scanning_never_lowers_the_verdict(
            total in 0_u32..200,
            refusals in 0_u32..200,
            auth in 0_u32..20,
            paths in 0_u32..100,
            more_auth in 0_u32..20,
            more_paths in 0_u32..100,
        ) {
            let before = config().verdict(signals(total, refusals.min(total), auth, paths));
            let after = config().verdict(signals(
                total,
                refusals.min(total),
                auth + more_auth,
                paths + more_paths,
            ));

            prop_assert!(rank(after) >= rank(before));
        }
    }
}
