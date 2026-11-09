//! Claim due sweeps: which sweeps this worker runs now. Every worker asks
//! on each tick; for each sweep the round the moment falls in is claimed,
//! and only the one worker that wins a round runs it.

use std::sync::Arc;

use ianua_domain::domains::scheduling::sweep::{SweepName, SweepRound};
use time::OffsetDateTime;

use crate::auditor::RequestAuditor;
use crate::error::{AppError, OrInternal};
use crate::ports::scheduling::SweepClaims;
use crate::use_case::Command;
use crate::use_cases::scheduling::sweeps::Sweep;

/// The ports [`ClaimDueUseCase`] needs.
#[derive(ianua_macros::Fakes)]
pub struct ClaimDuePorts {
    /// Hands each round of each sweep to one worker.
    pub claims: Arc<dyn SweepClaims>,
}

/// Claims the rounds of the sweeps that are due for this worker.
///
/// It runs on the worker's tick: no one calls it, so it takes no caller.
pub struct ClaimDueUseCase {
    ports: ClaimDuePorts,
    sweeps: Vec<Sweep>,
}

impl ClaimDueUseCase {
    /// Claims for `sweeps` through `ports`.
    #[must_use]
    pub fn new(ports: ClaimDuePorts, sweeps: Vec<Sweep>) -> Self {
        Self { ports, sweeps }
    }
}

impl Command for ClaimDueUseCase {
    type Caller = ();
    type Input = OffsetDateTime;
    type Output = Result<Vec<SweepName>, AppError>;

    /// The sweeps whose round `now` falls in this worker claimed, for it to
    /// run. A round another worker claimed is left to it, so each round of
    /// each sweep runs once however many workers tick. Records nothing:
    /// claiming is coordination between workers, and each sweep records
    /// what it changes itself.
    ///
    /// # Errors
    ///
    /// - `AppError::Internal` when a claim cannot be made. The sweeps
    ///   claimed before it are lost for this round, and run the next.
    async fn execute(
        &self,
        (): &(),
        _auditor: &RequestAuditor,
        now: OffsetDateTime,
    ) -> Result<Vec<SweepName>, AppError> {
        let mut claimed = Vec::new();
        for sweep in &self.sweeps {
            let round = SweepRound::at(now, sweep.period());
            if self
                .ports
                .claims
                .claim(sweep.name(), round)
                .await
                .or_internal()?
            {
                claimed.push(sweep.name().clone());
            }
        }
        Ok(claimed)
    }
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;
    use crate::test_support::scheduling::FakeSweepClaims;
    use crate::test_support::{FakeEventDispatcher, block_on, test_auditor};
    use crate::use_cases::scheduling::sweeps::sweeps;

    fn claim(uc: &ClaimDueUseCase, now: OffsetDateTime) -> Vec<SweepName> {
        block_on(uc.execute(
            &(),
            &test_auditor(Arc::new(FakeEventDispatcher::new())),
            now,
        ))
        .unwrap()
    }

    /// Two workers share one claim store. At noon the first claims every
    /// sweep's round, and the second, ticking a moment later, runs none of
    /// them again.
    #[test]
    fn each_round_goes_to_one_worker() {
        let claims = Arc::new(FakeSweepClaims::default());
        let first = ClaimDueUseCase::new(
            ClaimDuePorts {
                claims: claims.clone(),
            },
            sweeps().unwrap(),
        );
        let second = ClaimDueUseCase::new(ClaimDuePorts { claims }, sweeps().unwrap());
        let noon = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();

        let by_first = claim(&first, noon);
        let by_second = claim(&second, noon + Duration::SECOND);

        assert_eq!(by_first.len(), sweeps().unwrap().len());
        assert!(by_second.is_empty());
    }

    /// A minute later the minute sweeps are due again, but the daily purge
    /// is not.
    #[test]
    fn the_next_round_comes_with_the_next_period() {
        let uc = ClaimDueUseCase::new(ClaimDuePorts::fakes(), sweeps().unwrap());
        let noon = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        claim(&uc, noon);

        let later: Vec<String> = claim(&uc, noon + Duration::MINUTE)
            .iter()
            .map(ToString::to_string)
            .collect();

        assert!(
            later
                .iter()
                .any(|name| name == "authorization.expire_holdings")
        );
        assert!(
            !later
                .iter()
                .any(|name| name == "audit.purge_expired_records")
        );
    }
}
