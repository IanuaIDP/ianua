//! The timer a job is bounded by: the process's own clock.

use async_trait::async_trait;
use ianua_app::ports::scheduling::JobTimer;

/// A timer on this process's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalJobTimer;

#[async_trait]
impl JobTimer for LocalJobTimer {
    async fn wait(&self, after: time::Duration) {
        let wait = std::time::Duration::try_from(after).unwrap_or_default();
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wait ends only once its time has passed.
    #[tokio::test]
    async fn a_wait_ends_once_its_time_passed() {
        let started = std::time::Instant::now();

        LocalJobTimer.wait(time::Duration::milliseconds(30)).await;

        assert!(started.elapsed() >= std::time::Duration::from_millis(30));
    }

    /// A wait already over, its time negative, ends at once.
    #[tokio::test]
    async fn a_negative_wait_ends_at_once() {
        let started = std::time::Instant::now();

        LocalJobTimer.wait(time::Duration::seconds(-5)).await;

        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
