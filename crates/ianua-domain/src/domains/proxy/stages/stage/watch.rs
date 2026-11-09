//! What the decoy and recon stages must be set up with, how long they keep
//! what they saw, and what a recon window's counts call for.
//!
//! Both watch a tenant as a whole rather than one route: a scanner probing
//! `/.env` or walking paths matches no real route, so no single pipeline
//! has been chosen when it is caught.

use crate::domains::proxy::stages::recon::{ReconSignals, ReconVerdict};
use crate::domains::proxy::stages::stage::{HoneypotConfig, ReconDetectionConfig};
use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::{validate_count, validate_range};
use crate::types::{CanonicalPath, Seconds};

/// One day, in seconds.
const DAY_SECS: u32 = 86_400;

/// A week, in seconds.
const WEEK_SECS: u32 = 7 * DAY_SECS;

/// The longest a tarpit may hold a request, in milliseconds.
const MAX_TARPIT_MS: u32 = 60_000;

/// How many recon signals there are to trip.
const RECON_SIGNALS: u8 = 3;

/// How long a client that requested a decoy path stays blocked: at least a
/// second, at most a week.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecoyLifetime(Seconds);

impl DecoyLifetime {
    /// The longest block there is, a week.
    pub const LONGEST: Self = Self(Seconds::new(WEEK_SECS));

    /// A block of `seconds`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `seconds` is zero, which would
    ///   block nobody, or longer than a week.
    pub fn new(seconds: Seconds) -> Result<Self, DomainError> {
        validate_range("block_ttl_seconds", seconds.get(), 1..=WEEK_SECS)?;
        Ok(Self(seconds))
    }

    /// How long the block lasts.
    #[must_use]
    pub fn seconds(self) -> Seconds {
        self.0
    }
}

/// How long the recon stage's scoring window is: at least a second, at most
/// a day. When it ends, the scores start again from zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReconWindow(Seconds);

impl ReconWindow {
    /// The widest window there is, a day.
    pub const WIDEST: Self = Self(Seconds::new(DAY_SECS));

    /// A window of `seconds`.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when `seconds` is zero, which would
    ///   score nothing, or longer than a day.
    pub fn new(seconds: Seconds) -> Result<Self, DomainError> {
        validate_range("window_seconds", seconds.get(), 1..=DAY_SECS)?;
        Ok(Self(seconds))
    }

    /// How long the window lasts.
    #[must_use]
    pub fn seconds(self) -> Seconds {
        self.0
    }
}

impl HoneypotConfig {
    /// Refuses a stage with no decoy, which would catch nobody, and one
    /// whose block does not read as a [`DecoyLifetime`].
    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        validate_count("paths", self.paths.len(), 1..=usize::MAX)?;
        DecoyLifetime::new(self.block_ttl_seconds)?;
        Ok(())
    }

    /// Whether `path` is one of this stage's decoys.
    ///
    /// Both sides are in canonical spelling, so `/.env/` and `/%2eenv` are
    /// caught as `/.env`.
    #[must_use]
    pub fn catches(&self, path: &CanonicalPath) -> bool {
        self.paths.contains(path)
    }

    /// How long a client that hit a decoy is blocked.
    ///
    /// A stage is checked when it is made, so its lifetime always reads. If
    /// it did not, the longest block is the answer: a scanner is held too
    /// long rather than let go at once.
    #[must_use]
    pub fn lifetime(&self) -> DecoyLifetime {
        DecoyLifetime::new(self.block_ttl_seconds).unwrap_or(DecoyLifetime::LONGEST)
    }
}

impl ReconDetectionConfig {
    /// Refuses a window that does not read as a [`ReconWindow`], a threshold
    /// that could never trip, and an escalation that does not hold.
    pub(crate) fn validate(&self) -> Result<(), DomainError> {
        ReconWindow::new(self.window_seconds)?;
        validate_range("min_requests", self.min_requests, 1..=u32::MAX)?;
        if !(self.error_ratio_threshold > 0.0 && self.error_ratio_threshold <= 1.0) {
            return Err(DomainError::invalid(message!(
                "proxy-error-ratio-threshold-must-be-a",
                "error_ratio_threshold must be a fraction above 0 and at most 1"
            )));
        }
        validate_range(
            "distinct_path_threshold",
            self.distinct_path_threshold,
            1..=u32::MAX,
        )?;
        validate_range(
            "auth_failure_threshold",
            self.auth_failure_threshold,
            1..=u32::MAX,
        )?;
        self.ensure_escalation_holds()
    }

    /// Slowing comes before blocking, and neither asks for more signals than
    /// there are.
    fn ensure_escalation_holds(&self) -> Result<(), DomainError> {
        validate_range(
            "tarpit_signal_count",
            self.tarpit_signal_count,
            1..=RECON_SIGNALS,
        )?;
        validate_range(
            "block_signal_count",
            self.block_signal_count,
            self.tarpit_signal_count..=RECON_SIGNALS,
        )?;
        validate_range("tarpit_delay_ms", self.tarpit_delay_ms, 1..=MAX_TARPIT_MS)?;
        Ok(())
    }

    /// The scoring window.
    ///
    /// A stage is checked when it is made, so its window always reads. If it
    /// did not, the widest window is the answer: it gathers the most signals.
    #[must_use]
    pub fn window(&self) -> ReconWindow {
        ReconWindow::new(self.window_seconds).unwrap_or(ReconWindow::WIDEST)
    }

    /// What `signals` call for: a block once
    /// [`block_signal_count`](Self::block_signal_count) signals tripped, a
    /// tarpit once [`tarpit_signal_count`](Self::tarpit_signal_count) did.
    #[must_use]
    pub fn verdict(&self, signals: ReconSignals) -> ReconVerdict {
        let tripped = self.tripped(signals);
        if tripped >= self.block_signal_count {
            return ReconVerdict::Block;
        }
        if tripped >= self.tarpit_signal_count {
            return ReconVerdict::Tarpit;
        }
        ReconVerdict::Clean
    }

    /// How many of the three signals tripped. The refusal ratio counts only
    /// once the window holds enough requests, so one 404 does not flag a
    /// client.
    fn tripped(&self, signals: ReconSignals) -> u8 {
        let refusal_ratio = signals.total >= self.min_requests
            && f64::from(signals.refusals) / f64::from(signals.total.max(1))
                >= f64::from(self.error_ratio_threshold);
        let walked = signals.paths >= self.distinct_path_threshold;
        let guessed = signals.auth_failures >= self.auth_failure_threshold;
        [refusal_ratio, walked, guessed]
            .into_iter()
            .map(u8::from)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn honeypot(paths: &[&str], block_ttl_seconds: u32) -> HoneypotConfig {
        HoneypotConfig {
            paths: paths
                .iter()
                .map(|path| CanonicalPath::new(*path).unwrap())
                .collect(),
            block_ttl_seconds: Seconds::new(block_ttl_seconds),
        }
    }

    /// An hour's block is kept. Zero seconds and a week and a second are
    /// refused.
    #[test]
    fn a_decoy_block_lasts_a_second_to_a_week() {
        assert_eq!(
            DecoyLifetime::new(Seconds::new(3600)).unwrap().seconds(),
            Seconds::new(3600)
        );
        assert!(DecoyLifetime::new(Seconds::new(0)).is_err());
        assert!(DecoyLifetime::new(Seconds::new(WEEK_SECS + 1)).is_err());
    }

    /// A minute's window is kept. Zero seconds and a day and a second are
    /// refused.
    #[test]
    fn a_recon_window_lasts_a_second_to_a_day() {
        assert_eq!(
            ReconWindow::new(Seconds::new(60)).unwrap().seconds(),
            Seconds::new(60)
        );
        assert!(ReconWindow::new(Seconds::new(0)).is_err());
        assert!(ReconWindow::new(Seconds::new(DAY_SECS + 1)).is_err());
    }

    /// `/.env` is a decoy of a stage listing it. `/api/users` is not.
    #[test]
    fn a_stage_catches_only_its_own_decoys() {
        let stage = honeypot(&["/.env", "/.git/config"], 3600);

        assert!(stage.catches(&CanonicalPath::new("/.env").unwrap()));
        assert!(!stage.catches(&CanonicalPath::new("/api/users").unwrap()));
    }

    /// A zero-second decoy block reads as the longest permitted lifetime,
    /// while a valid hour-long block retains its configured duration.
    #[test]
    fn a_lifetime_that_does_not_read_is_the_longest_block() {
        assert_eq!(honeypot(&["/.env"], 0).lifetime(), DecoyLifetime::LONGEST);
        assert_eq!(
            honeypot(&["/.env"], 3600).lifetime().seconds(),
            Seconds::new(3600)
        );
    }

    /// A zero-second recon window reads as the widest permitted window,
    /// while a valid minute-long window retains its duration.
    #[test]
    fn a_window_that_does_not_read_is_the_widest() {
        let recon = |window_seconds| ReconDetectionConfig {
            window_seconds: Seconds::new(window_seconds),
            min_requests: 10,
            error_ratio_threshold: 0.5,
            distinct_path_threshold: 50,
            auth_failure_threshold: 10,
            tarpit_signal_count: 1,
            block_signal_count: 3,
            tarpit_delay_ms: 2000,
        };

        assert_eq!(recon(0).window(), ReconWindow::WIDEST);
        assert_eq!(recon(60).window().seconds(), Seconds::new(60));
    }
}
