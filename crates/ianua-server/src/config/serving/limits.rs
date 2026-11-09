//! How often one address or person may call, and the caps on what one
//! request or event may carry.

use std::num::NonZeroU32;
use std::time::Duration;

use ianua_api::state::http::{RateLimits, RateWindow};
use ianua_boot::env::{Env, Read};

/// The rate limits and caps.
#[derive(Debug, Clone, Copy)]
pub struct LimitsConfig {
    /// The per-address and per-person rate limits: `RATE_LIMIT_*`.
    pub rate: RateLimits,
    /// `NOTIFICATION_MAX_FANOUT` (500): people one event may notify.
    pub notification_max_fanout: u64,
    /// `SCIM_GROUP_MEMBER_CAP` (1000): members one SCIM group write may
    /// name.
    pub scim_group_member_cap: u32,
    /// `AUDIT_EXPORTS_PENDING_PER_LOG` (3): exports one audit log may have
    /// waiting for the worker.
    pub audit_exports_pending_per_log: NonZeroU32,
    /// `SIGN_IN_FAILURE_THRESHOLD` (200): failed sign-ins, across every
    /// organization sign-in that names no organization, that put those
    /// sign-ins under high pressure.
    pub unnamed_org_failure_threshold: u32,
    /// `SIGN_IN_FAILURE_WINDOW_SECONDS` (300): the sliding window failed
    /// password sign-ins are counted over, per tenant and per organization.
    pub sign_in_failure_window: Duration,
    /// `WEBHOOK_SENDS_PER_WINDOW` (10) and `WEBHOOK_SEND_WINDOW_SECONDS`
    /// (60): resends and tests one webhook takes, on a node.
    pub webhook_sends: RateWindow,
    /// `SIGNAL_VERIFICATIONS_PER_WINDOW` (5) and
    /// `SIGNAL_VERIFICATION_WINDOW_SECONDS` (60): verification events one
    /// signal stream's receiver may ask for, on a node.
    pub signal_verifications: RateWindow,
    /// `WASM_MODULE_MAX_BYTES` (1048576): the largest proxy stage module a
    /// tenant may upload.
    pub wasm_module_max_bytes: usize,
}

impl LimitsConfig {
    /// The limits `vars` holds.
    ///
    /// # Errors
    ///
    /// A number that does not read or lies outside its range.
    pub fn read(vars: &Env) -> Read<Self> {
        let pending = vars.number_in("AUDIT_EXPORTS_PENDING_PER_LOG", 3, 1..=100)?;
        let minute = Duration::from_secs(60);
        Ok(Self {
            rate: rate(vars)?,
            notification_max_fanout: vars.number_in("NOTIFICATION_MAX_FANOUT", 500, 1..=100_000)?,
            scim_group_member_cap: vars.number_in("SCIM_GROUP_MEMBER_CAP", 1000, 1..=100_000)?,
            audit_exports_pending_per_log: NonZeroU32::new(pending).unwrap_or(NonZeroU32::MIN),
            unnamed_org_failure_threshold: vars.number_in(
                "SIGN_IN_FAILURE_THRESHOLD",
                200,
                10..=1_000_000,
            )?,
            sign_in_failure_window: vars
                .seconds("SIGN_IN_FAILURE_WINDOW_SECONDS", Duration::from_secs(300))?,
            webhook_sends: RateWindow {
                max: vars.number_in("WEBHOOK_SENDS_PER_WINDOW", 10, 1..=10_000)?,
                window: vars.seconds("WEBHOOK_SEND_WINDOW_SECONDS", minute)?,
            },
            signal_verifications: RateWindow {
                max: vars.number_in("SIGNAL_VERIFICATIONS_PER_WINDOW", 5, 1..=10_000)?,
                window: vars.seconds("SIGNAL_VERIFICATION_WINDOW_SECONDS", minute)?,
            },
            wasm_module_max_bytes: vars.number_in(
                "WASM_MODULE_MAX_BYTES",
                1024 * 1024,
                1..=64 * 1024 * 1024,
            )?,
        })
    }
}

/// The per-address and per-person rate limits.
fn rate(vars: &Env) -> Read<RateLimits> {
    let five_minutes = Duration::from_secs(300);
    Ok(RateLimits {
        login_per_minute: vars.number_in("RATE_LIMIT_LOGIN_PER_MINUTE", 20, 1..=100_000)?,
        agent_relay_per_minute: vars.number_in(
            "RATE_LIMIT_AGENT_RELAY_PER_MINUTE",
            600,
            1..=1_000_000,
        )?,
        scim_per_minute: vars.number_in("RATE_LIMIT_SCIM_PER_MINUTE", 600, 1..=1_000_000)?,
        sso: RateWindow {
            max: vars.number_in("RATE_LIMIT_SSO_PER_WINDOW", 60, 1..=100_000)?,
            window: vars.seconds("RATE_LIMIT_SSO_WINDOW_SECONDS", five_minutes)?,
        },
        sensitive: RateWindow {
            max: vars.number_in("RATE_LIMIT_SENSITIVE_PER_WINDOW", 10, 1..=100_000)?,
            window: vars.seconds("RATE_LIMIT_SENSITIVE_WINDOW_SECONDS", five_minutes)?,
        },
        user: RateWindow {
            max: vars.number_in("RATE_LIMIT_USER_PER_WINDOW", 10, 1..=100_000)?,
            window: vars.seconds("RATE_LIMIT_USER_WINDOW_SECONDS", five_minutes)?,
        },
        max_tracked_ips: vars.number_in("RATE_LIMIT_MAX_TRACKED_IPS", 100_000, 1..=100_000_000)?,
        api_default_per_minute: vars.number_in(
            "RATE_LIMIT_DEFAULT_PER_MINUTE",
            200,
            1..=1_000_000,
        )?,
        limit_cache_ttl: vars.seconds("RATE_LIMIT_CACHE_SECONDS", Duration::from_secs(60))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With nothing set, the documented limits hold.
    #[test]
    fn with_nothing_set_the_documented_limits_hold() {
        let config = LimitsConfig::read(&Env::of([])).unwrap();

        assert_eq!(config.rate.login_per_minute, 20);
        assert_eq!(config.rate.sso.window, Duration::from_secs(300));
        assert_eq!(config.scim_group_member_cap, 1000);
        assert_eq!(config.audit_exports_pending_per_log.get(), 3);
    }

    /// Configuration refuses a sign-in rate limit of zero.
    #[test]
    fn a_limit_of_zero_is_refused() {
        assert!(LimitsConfig::read(&Env::of([("RATE_LIMIT_LOGIN_PER_MINUTE", "0")])).is_err());
    }

    /// Configuration refuses a sign-in failure threshold below the
    /// domain's minimum.
    #[test]
    fn a_failure_threshold_below_the_floor_is_refused() {
        assert!(LimitsConfig::read(&Env::of([("SIGN_IN_FAILURE_THRESHOLD", "3")])).is_err());
    }
}
