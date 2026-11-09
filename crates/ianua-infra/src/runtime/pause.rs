//! The wait a password sign-in is held to while its account is guessed at
//! from many networks: the process's own clock.

use async_trait::async_trait;
use ianua_app::ports::runtime::Pause;

/// A pause on this process's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalPause;

#[async_trait]
impl Pause for LocalPause {
    async fn hold(&self, wait: time::Duration) {
        let wait = std::time::Duration::try_from(wait).unwrap_or_default();
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pause ends only once its wait has passed.
    #[tokio::test]
    async fn a_pause_ends_once_its_wait_passed() {
        let started = std::time::Instant::now();

        LocalPause.hold(time::Duration::milliseconds(30)).await;

        assert!(started.elapsed() >= std::time::Duration::from_millis(30));
    }

    /// A wait of less than nothing ends at once.
    #[tokio::test]
    async fn a_negative_wait_ends_at_once() {
        let started = std::time::Instant::now();

        LocalPause.hold(time::Duration::seconds(-5)).await;

        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
