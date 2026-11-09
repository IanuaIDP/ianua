//! How a service's backends are probed, and what the proxy does when most of
//! them fail.

use crate::message;
use crate::shared::errors::DomainError;
use crate::shared::validation::numeric::validate_range;
use crate::types::{Seconds, UrlPath};

/// Whether a service's backends are probed at all.
///
/// `Disabled` does not mean "unknown health". It means every backend always
/// counts as healthy. Health decides availability, not who is let in. So an
/// unprobed backend still gets traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HealthCheckPolicy {
    /// Never probed. Every backend is always eligible for traffic.
    Disabled,
    /// Probed on a schedule.
    Active(ActiveHealthCheck),
}

impl Default for HealthCheckPolicy {
    /// Probes `/healthz` every 10 seconds.
    fn default() -> Self {
        Self::Active(ActiveHealthCheck::default())
    }
}

impl HealthCheckPolicy {
    /// The probe settings, or `None` when checking is off.
    #[must_use]
    pub fn active(&self) -> Option<&ActiveHealthCheck> {
        match self {
            Self::Active(check) => Some(check),
            Self::Disabled => None,
        }
    }
}

/// Probe settings for a service whose backends are health checked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "ActiveHealthCheckWire"))]
pub struct ActiveHealthCheck {
    path: UrlPath,
    interval_secs: Seconds,
    timeout_secs: Seconds,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
    panic_threshold_percent: u32,
}

/// Probe settings as they arrive, before [`ActiveHealthCheck::new`] has
/// checked them.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct ActiveHealthCheckWire {
    path: UrlPath,
    interval_secs: Seconds,
    timeout_secs: Seconds,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
    panic_threshold_percent: u32,
}

#[cfg(feature = "serde")]
impl TryFrom<ActiveHealthCheckWire> for ActiveHealthCheck {
    type Error = DomainError;

    /// Settings read from a stored service or an API body pass the same
    /// checks as ones built in code. So a stored probe can never outlive its
    /// own interval.
    fn try_from(wire: ActiveHealthCheckWire) -> Result<Self, Self::Error> {
        Self::new(ActiveHealthCheckParams {
            path: wire.path,
            interval_secs: wire.interval_secs,
            timeout_secs: wire.timeout_secs,
            healthy_threshold: wire.healthy_threshold,
            unhealthy_threshold: wire.unhealthy_threshold,
            panic_threshold_percent: wire.panic_threshold_percent,
        })
    }
}

/// Seconds between probes, unless the service says otherwise.
const DEFAULT_INTERVAL_SECS: u32 = 10;
/// Seconds a single probe may take, unless the service says otherwise.
const DEFAULT_TIMEOUT_SECS: u32 = 5;
/// Consecutive successes before a backend is eligible again.
const DEFAULT_HEALTHY_THRESHOLD: u32 = 2;
/// Consecutive failures before a backend is taken out.
const DEFAULT_UNHEALTHY_THRESHOLD: u32 = 3;
/// Below this share of healthy backends, health is ignored entirely.
///
/// Envoy calls this panic mode and uses the same default. Once most of a pool
/// looks dead, the probe is more likely wrong than the backends. Refusing all
/// traffic is worse than sending it to a backend that might still serve.
const DEFAULT_PANIC_THRESHOLD_PERCENT: u32 = 50;

impl Default for ActiveHealthCheck {
    /// Probes `/healthz` every 10 seconds with a 5 second timeout.
    fn default() -> Self {
        Self {
            path: UrlPath::health_probe(),
            interval_secs: Seconds::new(DEFAULT_INTERVAL_SECS),
            timeout_secs: Seconds::new(DEFAULT_TIMEOUT_SECS),
            healthy_threshold: DEFAULT_HEALTHY_THRESHOLD,
            unhealthy_threshold: DEFAULT_UNHEALTHY_THRESHOLD,
            panic_threshold_percent: DEFAULT_PANIC_THRESHOLD_PERCENT,
        }
    }
}

/// What a caller supplies to configure probing.
pub struct ActiveHealthCheckParams {
    /// Path to request on each backend.
    pub path: UrlPath,
    /// Seconds between probes.
    pub interval_secs: Seconds,
    /// Seconds a single probe may take.
    pub timeout_secs: Seconds,
    /// Consecutive successes before a backend is eligible again.
    pub healthy_threshold: u32,
    /// Consecutive failures before a backend is taken out.
    pub unhealthy_threshold: u32,
    /// Below this share of healthy backends, health is ignored entirely.
    /// Zero turns panic mode off.
    pub panic_threshold_percent: u32,
}

impl ActiveHealthCheck {
    /// A checked probe configuration.
    ///
    /// # Errors
    ///
    /// - [`DomainError::Validation`] when a value is outside its range. The
    ///   interval is 5 to 3600 seconds, the timeout 1 to 300, each threshold
    ///   1 to 10, and the panic share 0 to 100.
    /// - [`DomainError::Validation`] when `timeout_secs` is not shorter than
    ///   `interval_secs`. A probe that outlives its interval overlaps the next
    ///   one, and probes pile up.
    pub fn new(params: ActiveHealthCheckParams) -> Result<Self, DomainError> {
        validate_range("interval_secs", params.interval_secs.get(), 5..=3600)?;
        validate_range("timeout_secs", params.timeout_secs.get(), 1..=300)?;
        validate_range("healthy_threshold", params.healthy_threshold, 1..=10)?;
        validate_range("unhealthy_threshold", params.unhealthy_threshold, 1..=10)?;
        validate_range(
            "panic_threshold_percent",
            params.panic_threshold_percent,
            0..=100,
        )?;

        if params.timeout_secs >= params.interval_secs {
            return Err(DomainError::invalid(message!(
                "routing-timeout-secs-must-be-shorter-than",
                "timeout_secs must be shorter than interval_secs"
            )));
        }

        Ok(Self {
            path: params.path,
            interval_secs: params.interval_secs,
            timeout_secs: params.timeout_secs,
            healthy_threshold: params.healthy_threshold,
            unhealthy_threshold: params.unhealthy_threshold,
            panic_threshold_percent: params.panic_threshold_percent,
        })
    }

    /// Path requested on each backend.
    #[must_use]
    pub fn path(&self) -> &UrlPath {
        &self.path
    }

    /// Seconds between probes.
    #[must_use]
    pub fn interval_secs(&self) -> Seconds {
        self.interval_secs
    }

    /// Seconds a single probe may take.
    #[must_use]
    pub fn timeout_secs(&self) -> Seconds {
        self.timeout_secs
    }

    /// Consecutive successes before a backend is eligible again.
    #[must_use]
    pub fn healthy_threshold(&self) -> u32 {
        self.healthy_threshold
    }

    /// Consecutive failures before a backend is taken out.
    #[must_use]
    pub fn unhealthy_threshold(&self) -> u32 {
        self.unhealthy_threshold
    }

    /// Below this share of healthy backends, health is ignored entirely.
    #[must_use]
    pub fn panic_threshold_percent(&self) -> u32 {
        self.panic_threshold_percent
    }

    /// Whether a pool with `healthy` of `total` backends still up should
    /// ignore health and balance across all of them.
    ///
    /// This keeps a wrong probe from taking a service down. Take a service
    /// with one backend that fails its check. Without panic mode, the pool has
    /// nothing to pick, and every request gets a 503 on an unproven signal.
    #[must_use]
    pub fn in_panic(&self, healthy: usize, total: usize) -> bool {
        if self.panic_threshold_percent == 0 || total == 0 || healthy == total {
            return false;
        }
        let threshold = usize::try_from(self.panic_threshold_percent).unwrap_or(usize::MAX);
        healthy
            .saturating_mul(100)
            .checked_div(total)
            .is_some_and(|healthy_percent| healthy_percent < threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ActiveHealthCheckParams {
        ActiveHealthCheckParams {
            path: UrlPath::new("/healthz").unwrap(),
            interval_secs: Seconds::new(10),
            timeout_secs: Seconds::new(5),
            healthy_threshold: 2,
            unhealthy_threshold: 3,
            panic_threshold_percent: 50,
        }
    }

    /// The default probe asks `/healthz` every 10 seconds with a 5 second
    /// timeout. It needs 2 successes and 3 failures, and panics below 50%.
    #[test]
    fn the_default_is_what_every_backend_was_probed_with_before() {
        let check = ActiveHealthCheck::default();

        assert_eq!(check.path().as_str(), "/healthz");
        assert_eq!(check.interval_secs(), Seconds::new(10));
        assert_eq!(check.timeout_secs(), Seconds::new(5));
        assert_eq!(check.healthy_threshold(), 2);
        assert_eq!(check.unhealthy_threshold(), 3);
        assert_eq!(check.panic_threshold_percent(), 50);
    }

    /// An operator sets the panic threshold to 70%. The probe reports 70, so
    /// the setting shows back as made and never as zero, which means off.
    #[test]
    fn a_probe_reports_the_panic_threshold_it_was_configured_with() {
        let mut p = params();
        p.panic_threshold_percent = 70;

        let check = ActiveHealthCheck::new(p).unwrap();

        assert_eq!(check.panic_threshold_percent(), 70);
    }

    /// An operator sets a 10 second timeout on a 10 second interval. It is
    /// refused, since the probe could overlap the next one.
    #[test]
    fn a_timeout_at_least_as_long_as_the_interval_is_refused() {
        let mut p = params();
        p.timeout_secs = Seconds::new(10);

        assert!(matches!(
            ActiveHealthCheck::new(p),
            Err(DomainError::Validation(_))
        ));
    }

    /// An operator asks for a probe every second. It is refused, since the
    /// interval must be at least 5 seconds.
    #[test]
    fn an_interval_below_the_floor_is_refused() {
        let mut p = params();
        p.interval_secs = Seconds::new(1);
        p.timeout_secs = Seconds::new(1);

        assert!(ActiveHealthCheck::new(p).is_err());
    }

    /// A pool has one backend, and it fails its check. The pool is in panic,
    /// so the backend still gets traffic instead of every request failing.
    #[test]
    fn a_single_failing_backend_puts_the_pool_in_panic() {
        let check = ActiveHealthCheck::new(params()).unwrap();

        assert!(check.in_panic(0, 1));
    }

    /// A pool of one healthy backend, or four, is not in panic.
    #[test]
    fn a_fully_healthy_pool_is_never_in_panic() {
        let check = ActiveHealthCheck::new(params()).unwrap();

        assert!(!check.in_panic(1, 1));
        assert!(!check.in_panic(4, 4));
    }

    /// With a 50% threshold, two of four healthy is not panic. One of four
    /// healthy is.
    #[test]
    fn panic_engages_only_below_the_threshold() {
        let check = ActiveHealthCheck::new(params()).unwrap();

        assert!(!check.in_panic(2, 4), "50% healthy is not below 50%");
        assert!(check.in_panic(1, 4), "25% healthy is below 50%");
    }

    /// An operator sets the threshold to zero. With none of four healthy, the
    /// pool is not in panic, so a dead pool refuses traffic.
    #[test]
    fn a_zero_threshold_turns_panic_off() {
        let mut p = params();
        p.panic_threshold_percent = 0;
        let check = ActiveHealthCheck::new(p).unwrap();

        assert!(!check.in_panic(0, 4));
    }

    /// Disabled health checks carry no probe settings, so nothing is probed
    /// or taken out. The default carries settings.
    #[test]
    fn disabled_carries_no_probe_settings() {
        assert!(HealthCheckPolicy::Disabled.active().is_none());
        assert!(HealthCheckPolicy::default().active().is_some());
    }

    /// Stored settings have a 30 second timeout on a 10 second interval.
    /// Reading them is refused.
    #[cfg(feature = "serde")]
    #[test]
    fn a_probe_outliving_its_interval_is_refused_on_deserialize() {
        let mut json = serde_json::to_value(ActiveHealthCheck::default()).unwrap();
        json["timeout_secs"] = serde_json::json!(30);

        assert!(serde_json::from_value::<ActiveHealthCheck>(json).is_err());
    }

    /// Active probe settings are written to JSON and read back. They come
    /// back equal.
    #[cfg(feature = "serde")]
    #[test]
    fn valid_probe_settings_round_trip_through_json() {
        let policy = HealthCheckPolicy::Active(ActiveHealthCheck::new(params()).unwrap());

        let json = serde_json::to_string(&policy).unwrap();

        assert_eq!(
            serde_json::from_str::<HealthCheckPolicy>(&json).unwrap(),
            policy
        );
    }
}
