//! The count of failed password sign-ins per tenant and per organization,
//! over a sliding window, and the pressure each was last seen under.
//!
//! The window slides by weighing two fixed ones: the current window's count
//! in full and the one before by how much of it still falls inside, so a
//! flood straddling a window's edge counts as one. Both live on the state
//! every node shares, and so does the pressure, swapped in one step so two
//! nodes seeing the same change record it once.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ianua_app::ports::authentication::{FailureScope, SignInFailureBudget};
use ianua_domain::domains::authentication::risk_engine::pressure::{FailureCount, Pressure};
use ianua_domain::shared::clock;
use ianua_domain::shared::errors::DomainError;

use crate::cache::state::{CacheError, SharedState, key};

/// The words a pressure is kept as.
const NORMAL: &str = "normal";
const HIGH: &str = "high";

/// The fixed window containing a failure count and the elapsed seconds in it.
struct WindowPosition {
    number: u64,
    elapsed: u64,
}

/// The count of failed sign-ins, on shared state.
pub struct CacheSignInFailureBudget {
    state: Arc<dyn SharedState>,
    window: Duration,
}

impl CacheSignInFailureBudget {
    /// A count over `window`, on `state`. A window shorter than a second
    /// counts over one second.
    #[must_use]
    pub fn new(state: Arc<dyn SharedState>, window: Duration) -> Self {
        Self {
            state,
            window: window.max(Duration::from_secs(1)),
        }
    }

    fn seconds(&self) -> u64 {
        self.window.as_secs().max(1)
    }

    /// The fixed window holding now, and how far into it now is, in
    /// seconds.
    fn position(&self) -> WindowPosition {
        let now = u64::try_from(clock::now().unix_timestamp()).unwrap_or_default();
        let seconds = self.seconds();
        WindowPosition {
            number: now.checked_div(seconds).unwrap_or_default(),
            elapsed: now.checked_rem(seconds).unwrap_or_default(),
        }
    }

    /// The count of `scope`'s failures, given the current window's count.
    async fn weighed(
        &self,
        scope: &FailureScope,
        position: &WindowPosition,
        current: u64,
    ) -> Result<FailureCount, CacheError> {
        let before = self
            .state
            .read(&bucket(scope, position.number.saturating_sub(1)))
            .await?
            .unwrap_or_default();
        let seconds = self.seconds();
        let left = seconds.saturating_sub(position.elapsed);
        let weighed = before
            .saturating_mul(left)
            .checked_div(seconds)
            .unwrap_or_default();
        Ok(FailureCount::from(current.saturating_add(weighed)))
    }
}

/// The scope's name in a key.
fn scope_name(scope: &FailureScope) -> String {
    match scope {
        FailureScope::Tenant(id) => format!("tenant:{id}"),
        FailureScope::Organization(id) => format!("organization:{id}"),
        FailureScope::UnnamedOrganizations => "unnamed-organizations".to_owned(),
    }
}

/// The key `scope`'s failures in the fixed window `window` are counted
/// under.
fn bucket(scope: &FailureScope, window: u64) -> String {
    key(&["sign-in-failures", &scope_name(scope), &window.to_string()])
}

#[async_trait]
impl SignInFailureBudget for CacheSignInFailureBudget {
    async fn failures(&self, scope: &FailureScope) -> Result<FailureCount, DomainError> {
        let position = self.position();
        let current = self
            .state
            .read(&bucket(scope, position.number))
            .await?
            .unwrap_or_default();
        Ok(self.weighed(scope, &position, current).await?)
    }

    async fn record_failure(&self, scope: &FailureScope) -> Result<FailureCount, DomainError> {
        let position = self.position();
        let keep = self.window.saturating_mul(2);
        let current = self
            .state
            .count(&bucket(scope, position.number), 1, keep)
            .await?;
        Ok(self.weighed(scope, &position, current).await?)
    }

    async fn swap_pressure(
        &self,
        scope: &FailureScope,
        now: Pressure,
    ) -> Result<Pressure, DomainError> {
        let word = match now {
            Pressure::Normal => NORMAL,
            Pressure::High => HIGH,
        };
        let kept = key(&["sign-in-pressure", &scope_name(scope)]);
        let before = self
            .state
            .swap(&kept, word, self.window.saturating_mul(4))
            .await?;
        Ok(match before.as_deref() {
            Some(HIGH) => Pressure::High,
            Some(_) | None => Pressure::Normal,
        })
    }
}

#[cfg(test)]
mod tests {
    use ianua_domain::types::TenantId;

    use super::*;
    use crate::cache::MemoryState;

    fn budget() -> CacheSignInFailureBudget {
        CacheSignInFailureBudget::new(Arc::new(MemoryState::new(1_000)), Duration::from_secs(600))
    }

    /// Failures are counted per scope, and the count reads back.
    #[tokio::test]
    async fn failures_are_counted_per_scope() {
        let budget = budget();
        let acme = FailureScope::Tenant(TenantId::new());
        let other = FailureScope::UnnamedOrganizations;

        budget.record_failure(&acme).await.unwrap();
        let second = budget.record_failure(&acme).await.unwrap();

        assert_eq!(second.get(), 2);
        assert_eq!(budget.failures(&acme).await.unwrap().get(), 2);
        assert_eq!(budget.failures(&other).await.unwrap().get(), 0);
    }

    /// A pressure never kept reads as normal; a swap answers the one before.
    #[tokio::test]
    async fn a_pressure_swap_answers_the_one_before() {
        let budget = budget();
        let acme = FailureScope::Tenant(TenantId::new());

        let first = budget.swap_pressure(&acme, Pressure::High).await.unwrap();
        let second = budget.swap_pressure(&acme, Pressure::Normal).await.unwrap();

        assert_eq!(first, Pressure::Normal);
        assert_eq!(second, Pressure::High);
    }
}
