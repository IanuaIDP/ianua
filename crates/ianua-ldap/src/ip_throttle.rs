//! Per-source-IP bind throttling.
//!
//! Applies before a bind DN resolves to any tenant, so guessing at
//! organization or tenant slugs is throttled too — the app-layer
//! `BindThrottle` port only sees attempts once a tenant is known.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

/// Upper bound on tracked source IPs, as a backstop against memory growth
/// from a spoofed-source flood.
const MAX_TRACKED_IPS: usize = 100_000;

struct Window {
    count: u32,
    started_at: Instant,
}

/// Bounded, in-process per-IP sliding-window bind throttle.
pub(crate) struct IpBindThrottle {
    windows: Mutex<HashMap<IpAddr, Window>>,
    per_minute: u32,
}

impl IpBindThrottle {
    /// Creates an empty throttle allowing each source IP `per_minute` bind
    /// attempts a minute.
    #[must_use]
    pub(crate) fn new(per_minute: u32) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            per_minute,
        }
    }

    /// Records an attempt from `ip` and reports whether it is over the
    /// per-minute limit.
    #[must_use]
    pub(crate) fn check_and_record(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);

        prune(&mut windows, now);

        let window = windows.entry(ip).or_insert(Window {
            count: 0,
            started_at: now,
        });

        if now.duration_since(window.started_at) >= WINDOW {
            window.count = 0;
            window.started_at = now;
        }

        window.count += 1;
        window.count <= self.per_minute
    }
}

/// Evicts expired windows, then the oldest, to keep the map under its cap.
fn prune(windows: &mut HashMap<IpAddr, Window>, now: Instant) {
    if windows.len() < MAX_TRACKED_IPS {
        return;
    }

    windows.retain(|_, w| now.duration_since(w.started_at) < WINDOW);
    if windows.len() < MAX_TRACKED_IPS {
        return;
    }

    let mut by_age: Vec<(IpAddr, Instant)> =
        windows.iter().map(|(ip, w)| (*ip, w.started_at)).collect();
    by_age.sort_by_key(|(_, started)| *started);

    for (ip, _) in by_age.into_iter().take(windows.len() - MAX_TRACKED_IPS + 1) {
        windows.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_ATTEMPTS_PER_IP_PER_MINUTE: u32 = 30;

    #[test]
    fn allows_attempts_under_the_limit() {
        let throttle = IpBindThrottle::new(MAX_ATTEMPTS_PER_IP_PER_MINUTE);
        let ip = IpAddr::from([127, 0, 0, 1]);

        for _ in 0..MAX_ATTEMPTS_PER_IP_PER_MINUTE {
            assert!(throttle.check_and_record(ip));
        }
    }

    #[test]
    fn refuses_once_the_allowance_is_spent() {
        let throttle = IpBindThrottle::new(MAX_ATTEMPTS_PER_IP_PER_MINUTE);
        let ip = IpAddr::from([127, 0, 0, 1]);

        for _ in 0..MAX_ATTEMPTS_PER_IP_PER_MINUTE {
            let _ = throttle.check_and_record(ip);
        }

        assert!(!throttle.check_and_record(ip));
    }

    #[test]
    fn one_ips_flood_does_not_spend_anothers_allowance() {
        let throttle = IpBindThrottle::new(MAX_ATTEMPTS_PER_IP_PER_MINUTE);
        let noisy = IpAddr::from([127, 0, 0, 1]);
        let quiet = IpAddr::from([127, 0, 0, 2]);

        for _ in 0..MAX_ATTEMPTS_PER_IP_PER_MINUTE {
            let _ = throttle.check_and_record(noisy);
        }
        assert!(!throttle.check_and_record(noisy));

        assert!(throttle.check_and_record(quiet), "limits are per source IP");
    }
}
