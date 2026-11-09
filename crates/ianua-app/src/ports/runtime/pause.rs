//! Waiting on this process's clock.

use async_trait::async_trait;

/// Dyn-safe port that waits a short time on this process's clock: a
/// password sign-in held back while its account is guessed at, or a change
/// waiting for its company rules to decide.
///
/// Every wait is short and capped by its caller, so a waiting request never
/// holds a connection for long.
#[async_trait]
pub trait Pause: Send + Sync {
    /// Returns once `wait` has passed. A wait of nothing or less returns at
    /// once.
    async fn hold(&self, wait: time::Duration);
}
