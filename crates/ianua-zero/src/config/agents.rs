//! Agents and people: how often the access of whoever opened a connection is
//! asked again while it stays open, and how long that may take. An agent is
//! asked about its delegation and standing; a person about their account,
//! session and the route they opened it on.
//!
//! An agent's approvals are asked of the API over the internal channel app
//! sign-in uses, so they take its address and timeout; how long a person
//! has to decide, and how many requests may wait, are the API's settings.

use std::time::Duration;

use ianua_boot::env::{ConfigError, Env, Read};

/// Bounds how often open connections recheck their caller's access and how long checks may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AgentsConfig {
    /// `GATEWAY_TUNNEL_RECHECK_SECONDS` (30): how often the access of the
    /// agent or person who opened a WebSocket or stream is asked again
    /// while it is open.
    pub recheck: Duration,
    /// `GATEWAY_TUNNEL_RECHECK_TIMEOUT_SECONDS` (5): how long that may take
    /// before the connection is closed for it.
    pub recheck_timeout: Duration,
}

impl AgentsConfig {
    /// The agent settings `vars` holds.
    ///
    /// # Errors
    ///
    /// A time out of its range, or a check allowed as long as the time
    /// between two.
    pub(crate) fn read(vars: &Env) -> Read<Self> {
        let config = Self {
            recheck: vars.seconds_in(
                "GATEWAY_TUNNEL_RECHECK_SECONDS",
                Duration::from_secs(30),
                1..=3600,
            )?,
            recheck_timeout: vars.seconds_in(
                "GATEWAY_TUNNEL_RECHECK_TIMEOUT_SECONDS",
                Duration::from_secs(5),
                1..=60,
            )?,
        };
        if config.recheck_timeout >= config.recheck {
            return Err(ConfigError::contradicts(
                "GATEWAY_TUNNEL_RECHECK_TIMEOUT_SECONDS",
                "is not shorter than GATEWAY_TUNNEL_RECHECK_SECONDS, so one check would still run when the next is due",
            ));
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With nothing set, authority is asked again every 30 seconds, each
    /// time for at most 5.
    #[test]
    fn with_nothing_set_the_documented_times_hold() {
        let config = AgentsConfig::read(&Env::of([])).unwrap();

        assert_eq!(config.recheck, Duration::from_secs(30));
        assert_eq!(config.recheck_timeout, Duration::from_secs(5));
    }

    /// A zero authority recheck interval is rejected with the interval setting named.
    #[test]
    fn a_recheck_interval_of_nothing_is_refused() {
        let read = AgentsConfig::read(&Env::of([("GATEWAY_TUNNEL_RECHECK_SECONDS", "0")]));

        assert!(
            matches!(read, Err(ConfigError::Invalid { name, .. }) if name == "GATEWAY_TUNNEL_RECHECK_SECONDS")
        );
    }

    /// A check timeout equal to the recheck interval is rejected as contradictory.
    #[test]
    fn a_check_as_long_as_its_interval_is_refused() {
        let vars = Env::of([
            ("GATEWAY_TUNNEL_RECHECK_SECONDS", "5"),
            ("GATEWAY_TUNNEL_RECHECK_TIMEOUT_SECONDS", "5"),
        ]);

        let read = AgentsConfig::read(&vars);

        assert!(
            matches!(read, Err(ConfigError::Contradicts { name, .. }) if name == "GATEWAY_TUNNEL_RECHECK_TIMEOUT_SECONDS")
        );
    }
}
