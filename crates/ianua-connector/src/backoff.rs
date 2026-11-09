//! How long to wait before trying again: twice as long each time, up to a
//! cap, each wait drawn at random from its upper half, so many connectors
//! that lost the gateway at once do not all come back at the same moment.

use std::time::Duration;

use rand::Rng as _;

/// The first wait.
const FIRST: Duration = Duration::from_secs(1);

/// The waits between tries.
#[derive(Debug, Clone)]
pub struct Backoff {
    first: Duration,
    next: Duration,
    cap: Duration,
}

impl Backoff {
    /// Waits starting at one second and growing to `cap`.
    #[must_use]
    pub fn new(cap: Duration) -> Self {
        Self::starting_at(FIRST, cap)
    }

    /// Waits starting at `first` and growing to `cap`.
    #[must_use]
    pub fn starting_at(first: Duration, cap: Duration) -> Self {
        let first = first.min(cap);
        Self {
            first,
            next: first,
            cap,
        }
    }

    /// The wait before the next try, between half and all of the current
    /// step, which then doubles up to the cap.
    pub fn wait(&mut self) -> Duration {
        let step = self.next;
        self.next = self.next.saturating_mul(2).min(self.cap);
        let half = step / 2;
        let spread = u64::try_from((step - half).as_millis()).unwrap_or(u64::MAX);
        half + Duration::from_millis(rand::thread_rng().gen_range(0..=spread))
    }

    /// Starts again from the first wait, after a try that worked.
    pub fn reset(&mut self) {
        self.next = self.first;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The waits grow and stop growing at the cap, never past it.
    #[test]
    fn waits_grow_to_the_cap_and_no_further() {
        let mut backoff = Backoff::new(Duration::from_secs(8));

        let waits: Vec<Duration> = (0..8).map(|_| backoff.wait()).collect();

        assert!(waits.iter().all(|wait| *wait <= Duration::from_secs(8)));
        assert!(waits[0] <= Duration::from_secs(1));
        assert!(waits[7] >= Duration::from_secs(4));
    }

    /// After a try that worked, the next wait is short again.
    #[test]
    fn a_reset_starts_from_the_first_wait() {
        let mut backoff = Backoff::new(Duration::from_secs(60));
        for _ in 0..5 {
            backoff.wait();
        }

        backoff.reset();

        assert!(backoff.wait() <= Duration::from_secs(1));
    }
}
