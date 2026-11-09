//! How often the gateway reads its configuration again in full, beside the
//! changes it follows on the bus, and how often its stream ports are
//! matched to what it read.
//!
//! The follower applies each change as it is heard and reloads everything
//! when it misses a stretch or loses the feed. The timer catches what
//! neither saw, so it bounds how long a change can go unserved.

use std::time::Duration;

use ianua_boot::env::{Env, Read};

/// How often the configuration is read again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReloadConfig {
    /// `GATEWAY_RELOAD_SECONDS` (300): every tenant, route, certificate and
    /// sign-in host read again, whatever the bus said.
    pub everything: Duration,
    /// `GATEWAY_STREAM_RECONCILE_SECONDS` (30): the bound TCP and UDP
    /// stream ports matched to the stream routes read.
    pub stream_ports: Duration,
}

impl ReloadConfig {
    /// The reload settings `vars` holds.
    ///
    /// # Errors
    ///
    /// A time out of its range.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        Ok(Self {
            everything: vars.seconds_in(
                "GATEWAY_RELOAD_SECONDS",
                Duration::from_secs(300),
                10..=86_400,
            )?,
            stream_ports: vars.seconds_in(
                "GATEWAY_STREAM_RECONCILE_SECONDS",
                Duration::from_secs(30),
                1..=3600,
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_boot::env::ConfigError;

    use super::*;

    /// With nothing set, everything is read again every five minutes and
    /// stream ports matched every 30 seconds.
    #[test]
    fn with_nothing_set_the_documented_times_hold() {
        let config = ReloadConfig::read(&Env::of([])).unwrap();

        assert_eq!(config.everything, Duration::from_secs(300));
        assert_eq!(config.stream_ports, Duration::from_secs(30));
    }

    /// A one-second full reload interval is rejected with the reload setting named.
    #[test]
    fn a_full_reload_more_often_than_ten_seconds_is_refused() {
        let read = ReloadConfig::read(&Env::of([("GATEWAY_RELOAD_SECONDS", "1")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_RELOAD_SECONDS")
        );
    }

    /// A week between full reloads exceeds the daily ceiling and is rejected.
    #[test]
    fn a_full_reload_rarer_than_daily_is_refused() {
        let read = ReloadConfig::read(&Env::of([("GATEWAY_RELOAD_SECONDS", "604800")]));

        assert!(read.is_err());
    }
}
