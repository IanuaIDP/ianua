//! Whether the shared cache answers, for the process's readiness check.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::runtime::{Readiness, ReadinessProbe, UnreadyReason};

use crate::cache::state::{CacheError, SharedState};

/// The longest the cache is waited on before it counts as not ready.
const WAIT: Duration = Duration::from_secs(2);

/// Asks the shared cache whether it answers.
pub struct CacheReadinessProbe {
    state: Arc<dyn SharedState>,
}

impl CacheReadinessProbe {
    /// A probe of `state`.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ReadinessProbe for CacheReadinessProbe {
    async fn check(&self) -> Readiness {
        match tokio::time::timeout(WAIT, self.state.ping()).await {
            Ok(Ok(())) => Readiness::Ready,
            Ok(Err(error)) => Readiness::NotReady(UnreadyReason::new(reason(&error))),
            Err(_) => Readiness::NotReady(UnreadyReason::new("the cache did not answer in time")),
        }
    }
}

/// What went wrong, without the server's address.
fn reason(error: &CacheError) -> &'static str {
    match error {
        CacheError::TimedOut => "the cache did not answer in time",
        CacheError::Unreachable(_) => "the cache cannot be reached",
        CacheError::Unexpected => "the cache answered something unexpected",
        CacheError::Full => "the cache is full",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::state::MemoryState;

    /// A cache in this process answers, so it is ready.
    #[tokio::test]
    async fn a_cache_in_the_process_is_ready() {
        let probe = CacheReadinessProbe::new(Arc::new(MemoryState::new(16)));

        assert_eq!(probe.check().await, Readiness::Ready);
    }
}
